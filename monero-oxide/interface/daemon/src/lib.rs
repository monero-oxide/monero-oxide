#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{fmt::Debug, future::Future};

extern crate alloc;
use alloc::{
  format, vec,
  vec::Vec,
  string::{String, ToString},
};

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use monero_oxide::transaction::{Input, Output, NotPruned, Pruned, Transaction};
use monero_address::Address;

use monero_interface::*;

mod blocks;
mod bin_rpc;

// https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
//   /src/cryptonote_config.h#L134
// https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
//   /src/rpc/core_rpc_server.cpp#L427
// https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd57
//   /contrib/epee/include/net/http_protocol_handler.inl#L283
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/*
  Monero has two distinct limits on responses. The first is the maximum size for the queue of
  messages to send, which is 100 MiB.

  https://github.com/monero-project/monero/blob/b591866fcfed400bc89631686655aa769ec5f2dd
    /contrib/epee/include/net/abstract_tcp_server2.h#L68

  The second is the maximum size for the amount of in-flight bytes when a new response is queued,
  which is 25 MiB.

  https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570/
    src/cryptonote_config.h#L133
  https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
    /src/rpc/core_rpc_server.cpp#L3922-L3925

  We only apply the former bound per the following comment:

  https://github.com/monero-project/monero/blob/8e9ab9677f90492bca3c7555a246f2a8677bd570
    /contrib/epee/include/net/abstract_tcp_server2.inl#L793-L797

  and our documented bound that the transport completely read a response _before_ reusing it for
  the next request.
*/
const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024;

// These are our own constants used for determining our own bounds on response sizes
const HTTP_OVERHEAD_ESTIMATE: usize = u16::MAX as usize;
const REQUEST_SIZE_TARGET: usize = MAX_REQUEST_SIZE - HTTP_OVERHEAD_ESTIMATE - 2048;
const JSON_BYTE_OVERHEAD_FACTOR_ESTIMATE: usize = 8;
// Every response should have _some_ amount of bytes, for which this is an estimate
const MIN_RESPONSE_SIZE_IN_BYTES_ESTIMATE: usize = 1024;

/*
  Monero doesn't have a size limit on miner transactions and accordingly doesn't have a size limit
  on transactions, yet we would like _a_ bound (even if absurd) to limit a malicious remote node
  from sending a gigantic HTTP response and wasting our bandwidth.

  We use the bounds intended with the FCMP++ hard fork _now_ (as they should be absurd, exceeding
  the entire default block size) to determine a bound (despite the fact these bounds aren't in
  force yet).

  https://github.com/seraphis-migration/monero/pull/104
*/
const MINER_TRANSACTION_OUTPUT_BOUND: usize = 10_000;
// 2048 is used an approximation for the bounded size of the prefix for a miner transaction
const MINER_TRANSACTION_SIZE_BOUND: usize =
  2048 + (MINER_TRANSACTION_OUTPUT_BOUND * Output::SIZE_UPPER_BOUND.0);
const TRANSACTION_SIZE_BOUND: usize = monero_oxide::primitives::const_max!(
  MINER_TRANSACTION_SIZE_BOUND,
  Transaction::<NotPruned>::NON_MINER_SIZE_UPPER_BOUND.0
);

fn rpc_hex(value: &str) -> Result<Vec<u8>, InterfaceError> {
  hex::decode(value)
    .map_err(|_| InterfaceError::InvalidInterface("expected hex wasn't hex".to_string()))
}

fn hash_hex(hash: &str) -> Result<[u8; 32], InterfaceError> {
  rpc_hex(hash)?
    .try_into()
    .map_err(|_| InterfaceError::InvalidInterface("hash wasn't 32-bytes".to_string()))
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
  result: T,
  id: Option<usize>,
}

#[rustfmt::skip]
/// An HTTP transport usable with a Monero daemon.
///
/// This is abstract such that users can use an HTTP library (which being their choice), a
/// Tor/i2p-based transport, or even a memory buffer an external service somehow routes.
///
/// While no implementors are directly provided, [monero-simple-request-rpc](
///   https://github.com/monero-oxide/monero-oxide/tree/main/monero-oxide/interface/daemon/simple-request
/// ) is recommended.
pub trait HttpTransport: Sync + Clone {
  /// Perform a POST request to the specified route with the specified body.
  ///
  /// The response must be read in full BEFORE the underlying connection is reused for another
  /// request. This is due to `monerod` terminating connections which have additional responses
  /// sent while more than 25 MB from prior responses has yet to be read.
  ///
  /// The implementor is left to handle anything such as authentication.
  fn post(
    &self,
    route: &str,
    body: Vec<u8>,
    response_size_limit: Option<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>>;
}

/// A connection to a Monero daemon.
///
/// This interface, if unable to fulfill a request (such as when requesting a non-existent block),
/// may represent that as the interface being invalid (on the assumption requests made should be
/// fulfilled). Please be mindful accordingly.
#[derive(Clone)]
pub struct MoneroDaemon<T: HttpTransport> {
  transport: T,
  response_size_limits: bool,
  supports_json_rpc_batch_requests: bool,
}

impl<T: HttpTransport> MoneroDaemon<T> {
  /// Construct a new connection to a Monero daemon.
  pub async fn new(transport: T) -> Result<Self, InterfaceError> {
    /*
      TODO: We don't currently fetch the RPC version here. If we did, we would be able to know
      which RPC routes are available and optimize accordingly. It'd also provide some level of
      validation over the functionality expected to be offered.
    */

    let mut result =
      Self { transport, response_size_limits: true, supports_json_rpc_batch_requests: true };

    // https://github.com/monero-project/monero/issues/10118
    {
      const BATCH_REQUEST: &str = r#"[
       { "jsonrpc": "2.0", "method": "on_get_block_hash", "params": [0], "id": 0 },
       { "jsonrpc": "2.0", "method": "on_get_block_hash", "params": [1], "id": 1 }
      ]"#;
      let response: serde_json::Value =
        result.rpc_call_internal("json_rpc", Some(BATCH_REQUEST.to_string()), 0).await?;
      if let Some(error) = response.get("error") {
        /*
          If the server failed to parse our valid JSON, we assume it's because it's expecting an
          object (while we sent an array, as allowed under the JSON-RPC 2.0 specification).

          https://www.jsonrpc.org/specification#batch
        */
        if error.get("code") == Some(&serde_json::Value::from(-32700i32)) {
          result.supports_json_rpc_batch_requests = false;
        } else {
          Err(InterfaceError::InvalidInterface(format!(
            "interface returned error when attempting a batch request, code {:?}",
            error.get("code").map(|code| code.as_number())
          )))?;
        }
      }
    }

    Ok(result)
  }

  /// Whether to enable or disable response size limits.
  ///
  /// The default is to enable size limits on the response, preventing a malicious daemon from
  /// transmitting a 1 GB response to a request for a single transaction. However, as Monero has
  /// unbounded block sizes, miner transaction sizes, a completely correct transport cannot bound
  /// any responses. This allows disable size limits on responses (not recommended) to ensure
  /// correctness.
  pub fn response_size_limits(&mut self, enabled: bool) {
    self.response_size_limits = enabled;
  }
}

impl<T: Debug + HttpTransport> core::fmt::Debug for MoneroDaemon<T> {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("MoneroDaemon")
      .field("transport", &self.transport)
      .field("response_size_limits", &self.response_size_limits)
      .field("supports_json_rpc_batch_requests", &self.supports_json_rpc_batch_requests)
      .finish()
  }
}

impl<T: HttpTransport> MoneroDaemon<T> {
  async fn rpc_call_core(
    &self,
    route: &str,
    params: Option<String>,
    response_size_limit: usize,
  ) -> Result<String, InterfaceError> {
    let response_size_limit = {
      let response_size_limit = response_size_limit.max(MIN_RESPONSE_SIZE_IN_BYTES_ESTIMATE);
      let json_response_size_limt =
        JSON_BYTE_OVERHEAD_FACTOR_ESTIMATE.saturating_mul(response_size_limit);
      let full_response_size_limit = HTTP_OVERHEAD_ESTIMATE.saturating_add(json_response_size_limt);
      full_response_size_limit.min(MAX_RESPONSE_SIZE)
    };

    let mut res = self
      .transport
      .post(
        route,
        if let Some(params) = params { params.into_bytes() } else { vec![] },
        self.response_size_limits.then_some(response_size_limit),
      )
      .await?;

    /*
      If the transport erroneously returned more bytes, truncate it before we expand it into an
      object. This may invalidate it, but it limits the impact of a DoS the transport was supposed
      to prevent.
    */
    res.truncate(response_size_limit);

    std_shims::string::String::from_utf8(res)
      .map_err(|_| InterfaceError::InvalidInterface("response wasn't utf-8".to_string()))
  }

  async fn rpc_call_internal<Response: DeserializeOwned>(
    &self,
    route: &str,
    params: Option<String>,
    response_size_limit: usize,
  ) -> Result<Response, InterfaceError> {
    let res = self.rpc_call_core(route, params, response_size_limit).await?;
    serde_json::from_str(&res).map_err(|_| {
      InterfaceError::InvalidInterface("response wasn't the expected json".to_string())
    })
  }

  /// Perform a RPC call to the specified route with the provided parameters.
  ///
  /// This is NOT a JSON-RPC call. They use a route of "json_rpc" and are available via
  /// `json_rpc_call`.
  ///
  /// The `response_size_limit` is expected to be in terms of the amount of bytes of data
  /// communicated with the response. A scaling factor for the overhead of JSON, and a flat amount
  /// for the overhead of HTTP, will be automatically applied.
  ///
  /// This method is NOT guaranteed by SemVer and may be removed in a future release. No guarantees
  /// on the safety nor correctness of bespoke calls made with this function are guaranteed.
  #[doc(hidden)]
  pub async fn rpc_call(
    &self,
    route: &str,
    params: Option<String>,
    response_size_limit: usize,
  ) -> Result<String, InterfaceError> {
    Ok(
      self
        .rpc_call_internal::<serde_json::Value>(route, params, response_size_limit)
        .await?
        .to_string(),
    )
  }

  async fn json_rpc_call_internal<Response: DeserializeOwned>(
    &self,
    method: &str,
    params: Option<String>,
    response_size_limit: usize,
  ) -> Result<Response, InterfaceError> {
    let req = if let Some(params) = params {
      format!(r#"{{ "jsonrpc": "2.0", "method": "{method}", "params": {params}, "id": 0 }}"#)
    } else {
      format!(r#"{{ "jsonrpc": "2.0", "method": "{method}", "params": [], "id": 0 }}"#)
    };

    Ok(
      self
        .rpc_call_internal::<JsonRpcResponse<Response>>("json_rpc", Some(req), response_size_limit)
        .await?
        .result,
    )
  }

  /// Perform a JSON-RPC call with the specified method with the provided parameters.
  ///
  /// The `response_size_limit` is expected to be in terms of the amount of bytes of data
  /// communicated with the response. A scaling factor for the overhead of JSON, and a flat amount
  /// for the overhead of HTTP, will be automatically applied.
  ///
  /// This method is NOT guaranteed by SemVer and may be removed in a future release. No guarantees
  /// on the safety nor correctness of bespoke calls made with this function are guaranteed.
  #[doc(hidden)]
  pub async fn json_rpc_call(
    &self,
    method: &str,
    params: Option<String>,
    response_size_limit: usize,
  ) -> Result<String, InterfaceError> {
    // Untyped response
    let result: Value = self.json_rpc_call_internal(method, params, response_size_limit).await?;
    // Return the response as a string
    Ok(result.to_string())
  }

  /// Generate blocks, with the specified address receiving the block reward.
  ///
  /// Returns the hashes of the generated blocks and the last block's alleged number.
  ///
  /// This is intended for testing purposes and does not validate the result in any way.
  pub async fn generate_blocks<const ADDR_BYTES: u128>(
    &self,
    address: &Address<ADDR_BYTES>,
    block_count: usize,
  ) -> Result<(Vec<[u8; 32]>, usize), InterfaceError> {
    #[derive(Deserialize)]
    struct BlocksResponse {
      blocks: Vec<String>,
      height: usize,
    }

    let res = self
      .json_rpc_call_internal::<BlocksResponse>(
        "generateblocks",
        Some(format!(r#"{{ "wallet_address": "{address}", "amount_of_blocks": {block_count} }}"#)),
        block_count.saturating_mul(32),
      )
      .await?;

    let mut blocks = Vec::with_capacity(res.blocks.len());
    for block in res.blocks {
      blocks.push(hash_hex(&block)?);
    }
    Ok((blocks, res.height))
  }
}

impl<T: HttpTransport> ProvidesBlockchainMeta for MoneroDaemon<T> {
  fn latest_block_number(&self) -> impl Send + Future<Output = Result<usize, InterfaceError>> {
    async move {
      #[derive(Deserialize)]
      struct HeightResponse {
        height: usize,
      }
      let res = self.rpc_call_internal::<HeightResponse>("get_height", None, 0).await?.height;
      res.checked_sub(1).ok_or_else(|| {
        InterfaceError::InvalidInterface(
          "node claimed the blockchain didn't even have the genesis block".to_string(),
        )
      })
    }
  }
}

mod provides_transaction {
  use super::*;

  /*
    Monero errors if more than 100 is requested unless using a non-restricted RPC.

    https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
      /src/rpc/core_rpc_server.cpp#L75
  */
  const EXPLICIT_TRANSACTIONS_PER_REQUEST_LIMIT: usize = 100;
  const IMPLICIT_TRANSACTIONS_PER_REQUEST_LIMIT: usize =
    REQUEST_SIZE_TARGET / (JSON_BYTE_OVERHEAD_FACTOR_ESTIMATE.saturating_mul(32));
  const TRANSACTIONS_PER_REQUEST_LIMIT: usize = monero_oxide::primitives::const_min!(
    EXPLICIT_TRANSACTIONS_PER_REQUEST_LIMIT,
    IMPLICIT_TRANSACTIONS_PER_REQUEST_LIMIT
  );

  // And of course, the response limit also applies here
  const TRANSACTIONS_PER_RESPONSE_LIMIT: usize =
    (MAX_RESPONSE_SIZE - HTTP_OVERHEAD_ESTIMATE).div_ceil(TRANSACTION_SIZE_BOUND);

  const TRANSACTIONS_LIMIT: usize = monero_oxide::primitives::const_min!(
    TRANSACTIONS_PER_REQUEST_LIMIT,
    TRANSACTIONS_PER_RESPONSE_LIMIT
  );

  #[derive(Deserialize)]
  struct TransactionResponse {
    tx_hash: String,
    as_hex: String,
    pruned_as_hex: String,
    prunable_hash: String,
  }
  #[derive(Deserialize)]
  struct TransactionsResponse {
    #[serde(default)]
    missed_tx: Vec<String>,
    txs: Vec<TransactionResponse>,
  }

  #[rustfmt::skip]
  impl<T: HttpTransport> ProvidesUnvalidatedTransactions for MoneroDaemon<T> {
    fn transactions(
      &self,
      hashes: &[[u8; 32]],
    ) -> impl Send + Future<Output = Result<Vec<Transaction>, TransactionsError>> {
      async move {
        let mut hashes_hex = hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let mut all_txs = Vec::with_capacity(hashes.len());
        while !hashes_hex.is_empty() {
          let this_count = TRANSACTIONS_LIMIT.min(hashes_hex.len());

          let txs = "\"".to_string() + &hashes_hex.drain(.. this_count).collect::<Vec<_>>().join("\",\"") + "\"";
          let txs: TransactionsResponse = self
            .rpc_call_internal(
              "get_transactions",
              Some(format!(r#"{{ "txs_hashes": [{txs}] }}"#)),
              this_count.saturating_mul(TRANSACTION_SIZE_BOUND),
            )
            .await?;

          if !txs.missed_tx.is_empty() {
            Err(TransactionsError::TransactionNotFound)?;
          }
          if txs.txs.len() != this_count {
            Err(InterfaceError::InvalidInterface(
              "not missing any transactions yet didn't return all transactions".to_string(),
            ))?;
          }

          all_txs.extend(txs.txs);
        }

        all_txs
          .iter()
          .map(|res| {
            // https://github.com/monero-project/monero/issues/8311
            let buf =
              rpc_hex(if !res.as_hex.is_empty() { &res.as_hex } else { &res.pruned_as_hex })?;
            let mut buf = buf.as_slice();
            let tx = Transaction::read(&mut buf).map_err(|_| {
              InterfaceError::InvalidInterface(format!(
                "node yielded transaction allegedly with hash {:?} which was invalid",
                rpc_hex(&res.tx_hash).ok().map(hex::encode),
              ))
            })?;
            if !buf.is_empty() {
              Err(InterfaceError::InvalidInterface("transaction had extra bytes after it".to_string()))?;
            }

            // We check this to ensure we didn't read a pruned transaction when we meant to read an
            // actual transaction. That shouldn't be possible, as they have different
            // serializations, yet it helps to ensure that if we applied the above exception (using
            //  the pruned data), it was for the right reason
            if res.as_hex.is_empty() {
              match tx.prefix().inputs.first() {
                Some(Input::Gen { .. }) => (),
                _ => Err(TransactionsError::PrunedTransaction)?,
              }
            }

            Ok(tx)
          })
          .collect()
      }
    }

    fn pruned_transactions(
      &self,
      hashes: &[[u8; 32]],
    ) -> impl Send + Future<Output = Result<Vec<PrunedTransactionWithPrunableHash>, TransactionsError>>
    {
      async move {
        let mut hashes_hex = hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let mut all_txs = Vec::with_capacity(hashes.len());
        while !hashes_hex.is_empty() {
          let this_count = TRANSACTIONS_LIMIT.min(hashes_hex.len());

          let txs = "\"".to_string() + &hashes_hex.drain(.. this_count).collect::<Vec<_>>().join("\",\"") + "\"";
          let txs: TransactionsResponse = self
            .rpc_call_internal(
              "get_transactions",
              Some(format!(r#"{{ "txs_hashes": [{txs}], "prune": true }}"#)),
              this_count.saturating_mul(TRANSACTION_SIZE_BOUND),
            )
            .await?;

          if !txs.missed_tx.is_empty() {
            Err(TransactionsError::TransactionNotFound)?;
          }
          if txs.txs.len() != this_count {
            Err(InterfaceError::InvalidInterface(
              "not missing any transactions yet didn't return all pruned transactions".to_string(),
            ))?;
          }

          all_txs.extend(txs.txs);
        }

        all_txs
          .iter()
          .map(|res| {
            let buf = rpc_hex(&res.pruned_as_hex)?;
            let mut buf = buf.as_slice();
            let tx = Transaction::<Pruned>::read(&mut buf).map_err(|_| {
              InterfaceError::InvalidInterface(
                format!("node yielded transaction allegedly with hash {:?} which was invalid",
                rpc_hex(&res.tx_hash).ok().map(hex::encode),
            ))
            })?;
            if !buf.is_empty() {
              Err(InterfaceError::InvalidInterface(
                "pruned transaction had extra bytes after it".to_string(),
              ))?;
            }
            let prunable_hash = (!matches!(tx, Transaction::V1 { .. }))
              .then(|| hash_hex(&res.prunable_hash))
              .transpose()?;
            Ok(
              PrunedTransactionWithPrunableHash::new(tx, prunable_hash)
                .expect(
                  "couldn't create `PrunedTransactionWithPrunableHash` despite providing prunable hash if version != 1"
                )
            )
          })
          .collect()
      }
    }
  }
}

impl<T: HttpTransport> PublishTransaction for MoneroDaemon<T> {
  fn publish_transaction(
    &self,
    tx: &Transaction,
  ) -> impl Send + Future<Output = Result<(), PublishTransactionError>> {
    async move {
      #[allow(dead_code)]
      #[derive(Deserialize)]
      struct SendRawResponse {
        status: String,
        double_spend: bool,
        fee_too_low: bool,
        invalid_input: bool,
        invalid_output: bool,
        low_mixin: bool,
        not_relayed: bool,
        overspend: bool,
        too_big: bool,
        too_few_outputs: bool,
        reason: String,
      }

      let res: SendRawResponse = self
        .rpc_call_internal(
          "send_raw_transaction",
          Some(format!(
            r#"{{ "tx_as_hex": "{}", "do_sanity_checks": false }}"#,
            hex::encode(tx.serialize())
          )),
          0,
        )
        .await?;

      if res.status != "OK" {
        Err(PublishTransactionError::TransactionRejected(res.reason))?;
      }

      Ok(())
    }
  }
}

mod provides_fee_rates {
  use super::*;

  // Number of blocks the fee estimate will be valid for
  // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c
  //   /src/wallet/wallet2.cpp#L121
  const GRACE_BLOCKS_FOR_FEE_ESTIMATE: u64 = 10;

  impl<T: HttpTransport> ProvidesUnvalidatedFeeRates for MoneroDaemon<T> {
    fn fee_rate(
      &self,
      priority: FeePriority,
    ) -> impl Send + Future<Output = Result<FeeRate, FeeError>> {
      async move {
        #[derive(Deserialize)]
        struct FeeResponse {
          status: String,
          fees: Option<Vec<u64>>,
          fee: u64,
          quantization_mask: u64,
        }

        let res: FeeResponse = self
          .json_rpc_call_internal(
            "get_fee_estimate",
            Some(format!(r#"{{ "grace_blocks": {GRACE_BLOCKS_FOR_FEE_ESTIMATE} }}"#)),
            0,
          )
          .await?;

        if res.status != "OK" {
          Err(FeeError::InvalidFee)?;
        }

        if let Some(fees) = res.fees {
          // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
          // src/wallet/wallet2.cpp#L7615-L7620
          let priority_idx = usize::try_from(if priority.to_u32() >= 4 {
            3
          } else {
            priority.to_u32().saturating_sub(1)
          })
          .map_err(|_| FeeError::InvalidFeePriority)?;

          if priority_idx >= fees.len() {
            Err(FeeError::InvalidFeePriority)?
          } else {
            FeeRate::new(fees[priority_idx], res.quantization_mask).ok_or(FeeError::InvalidFee)
          }
        } else {
          // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
          //   src/wallet/wallet2.cpp#L7569-L7584
          // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
          //   src/wallet/wallet2.cpp#L7660-L7661
          let priority_idx =
            usize::try_from(if priority.to_u32() == 0 { 1 } else { priority.to_u32() - 1 })
              .map_err(|_| FeeError::InvalidFeePriority)?;
          const MULTIPLIERS: [u64; 4] = [1, 5, 25, 1000];
          let fee_multiplier =
            *MULTIPLIERS.get(priority_idx).ok_or(FeeError::InvalidFeePriority)?;

          FeeRate::new(
            res.fee.checked_mul(fee_multiplier).ok_or(FeeError::InvalidFee)?,
            res.quantization_mask,
          )
          .ok_or(FeeError::InvalidFee)
        }
      }
    }
  }
}

/// A prelude of recommended imports to glob import.
pub mod prelude {
  pub use monero_interface::prelude::*;
  pub use crate::{HttpTransport, MoneroDaemon};
}
