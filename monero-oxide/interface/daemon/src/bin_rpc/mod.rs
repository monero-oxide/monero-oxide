use core::{
  ops::{Bound, RangeBounds},
  future::Future,
};

use alloc::{borrow::ToOwned as _, format, vec, vec::Vec};

use monero_oxide::{
  ed25519::Point,
  transaction::{Output, Timelock},
  DEFAULT_LOCK_WINDOW,
};

use monero_interface::*;

use crate::{
  MAX_RESPONSE_SIZE, MIN_RESPONSE_SIZE_IN_BYTES_ESTIMATE, HTTP_OVERHEAD_ESTIMATE,
  REQUEST_SIZE_TARGET, TRANSACTION_SIZE_BOUND, HttpTransport, MoneroDaemon,
};

mod epee;

macro_rules! epee_key_len {
  ($key: literal) => {{
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    {
      // Check this cast is well-formed when compiling
      const _KEY_LEN_IS_LESS_THAN_256: [(); 255 - $key.len()] = [(); _];
      $key.len() as u8
    }
  }};
}

mod blocks_bin;

impl<T: HttpTransport> MoneroDaemon<T> {
  /// Perform a binary call to the specified route with the provided parameters.
  ///
  /// The `response_size_limit` is expected to be in terms of the amount of bytes of data
  /// communicated with the response. A flat amount for the overhead of HTTP will be automatically
  /// applied.
  ///
  /// This method is NOT guaranteed by SemVer and may be removed in a future release. No guarantees
  /// on the safety nor correctness of bespoke calls made with this function are guaranteed.
  #[doc(hidden)]
  pub async fn bin_call<'a>(
    &'a self,
    route: &'a str,
    params: Vec<u8>,
    response_size_limit: usize,
  ) -> Result<Vec<u8>, InterfaceError> {
    let response_size_limit = {
      let response_size_limit = response_size_limit.max(MIN_RESPONSE_SIZE_IN_BYTES_ESTIMATE);
      let full_response_size_limit = HTTP_OVERHEAD_ESTIMATE.saturating_add(response_size_limit);
      full_response_size_limit.min(MAX_RESPONSE_SIZE)
    };

    let mut res = self
      .transport
      .post(route, params, self.response_size_limits.then_some(response_size_limit))
      .await?;

    /*
      If the transport erroneously returned more bytes, truncate it before we expand it into an
      object. This may invalidate it, but it limits the impact of a DoS the transport was supposed
      to prevent. Since this is EPEE-encoded, we should be able to read the values present before
      the cut-off without issue, so long as we stop our deserialization before hitting EOF.
    */
    res.truncate(response_size_limit);

    epee::check_status(&res)?;
    Ok(res)
  }
}

impl<T: HttpTransport> ProvidesUnvalidatedOutputs for MoneroDaemon<T> {
  fn output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>> {
    async move {
      #[expect(clippy::as_conversions)]
      let request = [
        epee::HEADER.as_slice(),
        &[epee::VERSION],
        &[1 << 2],
        &[epee_key_len!("txid")],
        "txid".as_bytes(),
        &[epee::Type::String as u8],
        &[32 << 2],
        &hash,
      ]
      .concat();

      const OUTPUTS_AMOUNT_BOUND: usize =
        TRANSACTION_SIZE_BOUND.div_ceil(Output::SIZE_LOWER_BOUND.0);
      let epee =
        self.bin_call("get_o_indexes.bin", request, OUTPUTS_AMOUNT_BOUND.saturating_mul(8)).await?;

      epee::extract_output_indexes(&epee)
    }
  }

  fn ringct_outputs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<RingCtOutputInformation>, InterfaceError>> {
    async move {
      // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
      //   /src/rpc/core_rpc_server.cpp#L67
      const EXPLICIT_MAX_OUTS: usize = 5000;
      const IMPLICIT_MAX_OUTS: usize = REQUEST_SIZE_TARGET / 32;
      const MAX_OUTS: usize =
        monero_oxide::primitives::const_min!(EXPLICIT_MAX_OUTS, IMPLICIT_MAX_OUTS);

      let expected_request_header_len = 19;
      let expected_request_len =
        expected_request_header_len + 8 + (indexes.len().min(MAX_OUTS) * 25);
      let mut request = Vec::with_capacity(expected_request_len);
      request.extend(epee::HEADER);
      request.push(epee::VERSION);
      request.push(1 << 2);
      request.push(epee_key_len!("outputs"));
      request.extend("outputs".as_bytes());
      #[expect(clippy::as_conversions)]
      request.push((epee::Type::Object as u8) | (epee::Array::Array as u8));
      debug_assert_eq!(request.len(), expected_request_header_len);

      let mut res = Vec::with_capacity(indexes.len());
      let mut first_iter = true;
      for indexes in indexes.chunks(MAX_OUTS) {
        // Form the request
        {
          request.truncate(expected_request_header_len);

          let indexes_len_u64 =
            u64::try_from(indexes.len()).expect("requesting more than 2**64 indexes?");
          // TODO: This can truncate some of the indexes requested if an absurd amount is requested
          // https://github.com/monero-oxide/monero-oxide/issues/93
          request.extend(((indexes_len_u64 << 2) | 0b11).to_le_bytes());

          for index in indexes {
            request.push(2 << 2);

            request.push(epee_key_len!("amount"));
            request.extend("amount".as_bytes());
            #[expect(clippy::as_conversions)]
            request.push(epee::Type::Uint8 as u8);
            request.push(0);

            request.push(epee_key_len!("index"));
            request.extend("index".as_bytes());
            #[expect(clippy::as_conversions)]
            request.push(epee::Type::Uint64 as u8);
            request.extend(&index.to_le_bytes());
          }

          // Only checked on the first iteration as the final chunk may be shorter
          if first_iter {
            debug_assert_eq!(expected_request_len, request.len());
            first_iter = false;
          }
        }

        // This is the size of the data, doubled to account for epee's structure
        const BOUND_PER_OUT: usize = 2 * (8 + 8 + 32 + 32 + 32 + 1);

        let outs = self
          .bin_call("get_outs.bin", request.clone(), indexes.len().saturating_mul(BOUND_PER_OUT))
          .await?;

        epee::accumulate_outs(&outs, indexes.len(), &mut res)?;
      }

      Ok(res)
    }
  }
}

impl<T: HttpTransport> ProvidesUnvalidatedDecoys for MoneroDaemon<T> {
  fn ringct_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>> {
    async move {
      let from = match range.start_bound() {
        Bound::Included(from) => *from,
        Bound::Excluded(from) => from.checked_add(1).ok_or_else(|| {
          InterfaceError::InternalError("range's from wasn't representable".to_owned())
        })?,
        Bound::Unbounded => 0,
      };
      let to = match range.end_bound() {
        Bound::Included(to) => *to,
        Bound::Excluded(to) => to.checked_sub(1).ok_or_else(|| {
          InterfaceError::InternalError("range's to wasn't representable".to_owned())
        })?,
        Bound::Unbounded => self.latest_block_number().await?,
      };
      if from > to {
        Err(InterfaceError::InternalError(format!(
          "malformed range: inclusive start {from}, inclusive end {to}"
        )))?;
      }

      let zero_zero_case = (from == 0) && (to == 0);

      #[expect(clippy::as_conversions)]
      let request = [
        epee::HEADER.as_slice(),
        &[epee::VERSION],
        &[5 << 2],
        &[epee_key_len!("from_height")],
        "from_height".as_bytes(),
        &[epee::Type::Uint64 as u8],
        &u64::try_from(from)
          .map_err(|_| {
            InterfaceError::InternalError("range's from wasn't representable as a `u64`".to_owned())
          })?
          .to_le_bytes(),
        &[epee_key_len!("to_height")],
        "to_height".as_bytes(),
        &[epee::Type::Uint64 as u8],
        &(if zero_zero_case {
          1u64
        } else {
          u64::try_from(to).map_err(|_| {
            InterfaceError::InternalError("range's to wasn't representable as a `u64`".to_owned())
          })?
        })
        .to_le_bytes(),
        &[epee_key_len!("cumulative")],
        "cumulative".as_bytes(),
        &[epee::Type::Bool as u8],
        &[1],
        &[epee_key_len!("compress")],
        "compress".as_bytes(),
        &[epee::Type::Bool as u8],
        &[0], // TODO: Use compression
        &[epee_key_len!("amounts")],
        "amounts".as_bytes(),
        &[(epee::Type::Uint8 as u8) | (epee::Array::Array as u8)],
        &[1 << 2],
        &[0],
      ]
      .concat();

      let distributions = self
        .bin_call(
          "get_output_distribution.bin",
          request,
          to.saturating_sub(from).saturating_add(2).saturating_mul(8),
        )
        .await?;

      let start_height = epee::extract_start_height(&distributions)?;

      // start_height is also actually a block number, and it should be at least `from`
      // It may be after depending on when these outputs first appeared on the blockchain
      // Unfortunately, we can't validate without a binary search to find the RingCT activation
      // block and an iterative search from there, so we solely sanity check it
      if start_height < from {
        Err(InterfaceError::InvalidInterface(format!(
          "requested distribution from {from} and got from {start_height}"
        )))?;
      }
      // It shouldn't be after `to` though
      if start_height > to {
        Err(InterfaceError::InvalidInterface(format!(
          "requested distribution to {to} and got from {start_height}"
        )))?;
      }

      let expected_len = if zero_zero_case {
        2
      } else {
        (to - start_height).checked_add(1).ok_or_else(|| {
          InterfaceError::InternalError("expected length of distribution exceeded usize".to_owned())
        })?
      };

      let mut distribution = epee::extract_distribution(&distributions, expected_len)?;

      // Requesting to = 0 returns the distribution for the entire chain
      // We work around this by requesting 0, 1 (yielding two blocks), then popping the second
      // block
      if zero_zero_case {
        distribution.pop();
      }

      Ok(distribution)
    }
  }

  fn unlocked_ringct_outputs(
    &self,
    indexes: &[u64],
    evaluate_unlocked: EvaluateUnlocked,
  ) -> impl Send + Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>> {
    async move {
      let outs = <Self as ProvidesOutputs>::ringct_outputs(self, indexes).await?;

      // Only need to fetch transactions if we're doing a deterministic check on the timelock
      let txs =
        if matches!(evaluate_unlocked, EvaluateUnlocked::FingerprintableDeterministic { .. }) {
          <Self as ProvidesTransactions>::pruned_transactions(
            self,
            &outs.iter().map(|out| out.transaction).collect::<Vec<_>>(),
          )
          .await?
        } else {
          vec![]
        };

      // TODO: https://github.com/serai-dex/serai/issues/104
      outs
        .iter()
        .enumerate()
        .map(|(i, out)| {
          /*
            If the key is invalid, preventing it from being used as a decoy, return `None` to
            trigger selection of a replacement decoy.
          */
          let Some(key) = out.key.decompress() else {
            return Ok(None);
          };
          Ok(
            (match evaluate_unlocked {
              EvaluateUnlocked::Normal => out.unlocked,
              EvaluateUnlocked::FingerprintableDeterministic { block_number } => {
                // https://github.com/monero-project/monero/blob
                //   /cc73fe71162d564ffda8e549b79a350bca53c454/src/cryptonote_config.h#L90
                const ACCEPTED_TIMELOCK_DELTA: usize = 1;

                let global_timelock_satisfied = out
                  .block_number
                  .checked_add(DEFAULT_LOCK_WINDOW - 1)
                  .is_some_and(|locked| locked <= block_number);

                // https://github.com/monero-project/monero/blob
                //   /cc73fe71162d564ffda8e549b79a350bca53c454/src/cryptonote_core
                //   /blockchain.cpp#L3836
                let transaction_timelock_satisfied =
                  Timelock::Block(block_number.saturating_add(ACCEPTED_TIMELOCK_DELTA)) >=
                    txs[i].prefix().additional_timelock;

                global_timelock_satisfied && transaction_timelock_satisfied
              }
            })
            .then_some([key, out.commitment]),
          )
        })
        .collect()
    }
  }
}
