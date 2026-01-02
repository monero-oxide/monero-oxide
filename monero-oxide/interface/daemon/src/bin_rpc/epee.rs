use std_shims::prelude::*;

use monero_oxide::{
  io::read_u64,
  ed25519::CompressedPoint,
  transaction::{Pruned, Transaction},
  block::Block,
};

use monero_epee::{EpeeError as OriginalEpeeError, EpeeEntry, Epee};
pub(super) use monero_epee::{HEADER, VERSION, Type, Array};

use crate::{
  InterfaceError, PrunedTransactionWithPrunableHash, UnvalidatedScannableBlock,
  RingCtOutputInformation,
};

struct EpeeError(OriginalEpeeError);
impl From<EpeeError> for InterfaceError {
  fn from(err: EpeeError) -> InterfaceError {
    InterfaceError::InvalidInterface(format!("EpeeError::{:?}", err.0))
  }
}

/// Read a `Vec<u64>` from a `epee`-encoded buffer.
///
/// This assumes the claimed length is actually present within the byte buffer. This will be the
/// case for an array encoded within a length-checked string
fn read_u64_array_from_epee(len: usize, mut epee: &[u8]) -> Result<Vec<u64>, InterfaceError> {
  // This is safe to pre-allocate due to the byte buffer being prior-checked to have this many items
  let mut res = Vec::with_capacity(len);
  for _ in 0 .. len {
    res.push(read_u64(&mut epee).map_err(|_| {
      InterfaceError::InternalError(
        "incomplete array despite precondition the array is complete".to_owned(),
      )
    })?);
  }
  Ok(res)
}

/*
  `EpeeEntry` must live for less time than its iterator, yet this makes it very tricky to work
  with. If we wrote a function which takes an iterator, then returns an entry, the entry's
  lifetime _must_ outlive the function (because it's returned from the function). At the same time,
  this prevents the iterator from being iterated within the function's body over because it's
  mutably borrowed for a lifetime exceeding the function.

  The solution, however ugly, is to handle the field _inside_ the iteration over the fields. We use
  the following macro to generate the code for this.
*/
macro_rules! optional_field {
  ($fields: ident, $field: literal, $body: expr) => {
    loop {
      let Some(entry) = $fields.next() else { break Ok::<_, EpeeError>(None) };
      let entry = match entry {
        Ok(entry) => entry,
        Err(e) => Err(EpeeError(e))?,
      };
      if entry.0.consume() == $field.as_bytes() {
        break Ok(Some($body(entry.1).map_err(EpeeError)?));
      }
    }
  };
}
macro_rules! field {
  ($fields: ident, $field: literal, $body: expr) => {
    optional_field!($fields, $field, $body)?.ok_or_else(|| {
      InterfaceError::InvalidInterface(format!("expected field {} but it wasn't present", $field))
    })
  };
}

/// A wrapper to call `to_fixed_len_str` via, since `field` assumes the body only takes a single
/// argument.
// Unfortunately, callers cannot simply use a lambda due to needing to define these lifetimes.
struct FixedLenStr(usize);
impl FixedLenStr {
  #[expect(single_use_lifetimes, clippy::elidable_lifetime_names, clippy::wrong_self_convention)]
  fn to_fixed_len_str<'encoding, 'parent>(
    self,
    entry: EpeeEntry<'encoding, 'parent, &'encoding [u8]>,
  ) -> Result<&'encoding [u8], monero_epee::EpeeError> {
    entry.to_fixed_len_str(self.0).map(monero_epee::String::consume)
  }
}

/// Check the `status` field within an `epee`-encoded object.
pub(super) fn check_status(epee: &[u8]) -> Result<(), InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.entry().map_err(EpeeError)?.fields().map_err(EpeeError)?;
  let status = field!(epee, "status", EpeeEntry::to_str)?;
  if status.consume() != b"OK" {
    return Err(InterfaceError::InvalidInterface("epee `status` wasn't \"OK\"".to_owned()));
  }
  Ok(())
}

/// Extract the `start_height` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the caller.
pub(super) fn extract_start_height(epee: &[u8]) -> Result<usize, InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.entry().map_err(EpeeError)?.fields().map_err(EpeeError)?;
  /*
    `distributions` is technically an array, but we assume only one distribution was requested,
    which allows us to treat it as a unit value and immediately access its fields.
  */
  let mut distributions = field!(epee, "distributions", EpeeEntry::fields)?;
  let start_height = field!(distributions, "start_height", EpeeEntry::to_u64)?;
  usize::try_from(start_height).map_err(|_| {
    InterfaceError::InvalidInterface("`start_height` did not fit within a `usize`".to_owned())
  })
}

/// Extract the `distribution` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the caller.
pub(super) fn extract_distribution(
  epee: &[u8],
  expected_len: usize,
) -> Result<Vec<u64>, InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.entry().map_err(EpeeError)?.fields().map_err(EpeeError)?;
  let mut distributions = field!(epee, "distributions", EpeeEntry::fields)?;

  let fixed_len_str = FixedLenStr(expected_len.checked_mul(8).ok_or_else(|| {
    InterfaceError::InternalError(
      "requested a distribution whose byte length doesn't fit within a `usize`".to_owned(),
    )
  })?);
  let distribution =
    field!(distributions, "distribution", |value| fixed_len_str.to_fixed_len_str(value))?;
  read_u64_array_from_epee(expected_len, distribution)
}

#[expect(single_use_lifetimes, clippy::elidable_lifetime_names)]
fn epee_32<'encoding, 'parent>(
  entry: EpeeEntry<'encoding, 'parent, &'encoding [u8]>,
) -> Result<[u8; 32], EpeeError> {
  Ok(
    entry
      .to_fixed_len_str(32)
      .map_err(EpeeError)?
      .consume()
      .try_into()
      .expect("32-byte string couldn't be converted to a 32-byte array"),
  )
}

/// Accumulate a set of outs from `get_outs.bin`.
pub(super) fn accumulate_outs(
  epee: &[u8],
  amount: usize,
  res: &mut Vec<RingCtOutputInformation>,
) -> Result<(), InterfaceError> {
  let start = res.len();

  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.entry().map_err(EpeeError)?.fields().map_err(EpeeError)?;
  let mut outs = field!(epee, "outs", EpeeEntry::iterate)?;
  while let Some(out) = outs.next() {
    let mut out = out.map_err(EpeeError)?.fields().map_err(EpeeError)?;

    let mut block_number = None;
    let mut key = None;
    let mut commitment = None;
    let mut transaction = None;
    let mut unlocked = None;

    while let Some(out) = out.next() {
      let (item_key, value) = out.map_err(EpeeError)?;
      match item_key.consume() {
        b"height" => block_number = Some(value.to_u64().map_err(EpeeError)?),
        b"key" => key = Some(CompressedPoint::from(epee_32(value)?)),
        b"mask" => commitment = Some(CompressedPoint::from(epee_32(value)?)),
        b"txid" => transaction = Some(epee_32(value)?),
        b"unlocked" => unlocked = Some(value.to_bool().map_err(EpeeError)?),
        _ => continue,
      }
    }

    let Some((block_number, key, commitment, transaction, unlocked)) =
      (|| Some((block_number?, key?, commitment?, transaction?, unlocked?)))()
    else {
      Err(InterfaceError::InvalidInterface(
        "missing field in output from `get_outs.bin`".to_owned(),
      ))?
    };

    let block_number = usize::try_from(block_number).map_err(|_| {
      InterfaceError::InvalidInterface(
        "`get_outs.bin` returned an block number not representable within a `usize`".to_owned(),
      )
    })?;
    let commitment = commitment.decompress().ok_or_else(|| {
      InterfaceError::InvalidInterface("`get_outs.bin` returned an invalid commitment".to_owned())
    })?;

    res.push(RingCtOutputInformation { block_number, key, commitment, transaction, unlocked });
  }

  if res.len() != (start + amount) {
    Err(InterfaceError::InvalidInterface(
      "`get_outs.bin` had a distinct amount of outs than expected".to_owned(),
    ))?;
  }

  Ok(())
}

/// Returns `None` if this methodology isn't applicable.
pub(super) fn extract_blocks_from_blocks_bin(
  blocks_bin: &[u8],
) -> Result<Option<impl use<'_> + Iterator<Item = UnvalidatedScannableBlock>>, InterfaceError> {
  let mut epee = Epee::new(blocks_bin).map_err(EpeeError)?;
  let mut epee = epee.entry().map_err(EpeeError)?.fields().map_err(EpeeError)?;

  let mut res = vec![];
  let mut all_output_indexes = vec![];
  while let Some(epee) = epee.next() {
    let (key, value) = epee.map_err(EpeeError)?;
    match key.consume() {
      b"blocks" => {
        let mut blocks = value.iterate().map_err(EpeeError)?;
        while let Some(block) = blocks.next() {
          let mut block_fields = block.map_err(EpeeError)?.fields().map_err(EpeeError)?;
          let mut block = None;
          let mut transactions = vec![];
          while let Some(field) = block_fields.next() {
            let (key, value) = field.map_err(EpeeError)?;
            match key.consume() {
              b"block" => {
                let mut encoding = value.to_str().map_err(EpeeError)?.consume();
                block = Some(Block::read(&mut encoding).map_err(|e| {
                  InterfaceError::InvalidInterface(format!("invalid block: {e:?}"))
                })?);
                if !encoding.is_empty() {
                  Err(InterfaceError::InvalidInterface(
                    "block had extraneous bytes after it".to_owned(),
                  ))?;
                }
              }
              b"txs" => {
                let mut transaction_entries = value.iterate().map_err(EpeeError)?;
                while let Some(transaction) = transaction_entries.next() {
                  let mut fields = transaction.map_err(EpeeError)?.fields().map_err(EpeeError)?;
                  let mut transaction = None;
                  let mut prunable_hash = None;
                  while let Some(field) = fields.next() {
                    let (key, value) = field.map_err(EpeeError)?;
                    match key.consume() {
                      b"blob" => {
                        let mut encoding = value.to_str().map_err(EpeeError)?.consume();
                        transaction =
                          Some(Transaction::<Pruned>::read(&mut encoding).map_err(|e| {
                            InterfaceError::InvalidInterface(format!("invalid transaction: {e:?}"))
                          })?);
                        if !encoding.is_empty() {
                          Err(InterfaceError::InvalidInterface(
                            "transaction had extraneous bytes after it".to_owned(),
                          ))?;
                        }
                      }
                      b"prunable_hash" => prunable_hash = Some(epee_32(value)?),
                      _ => {}
                    }
                  }
                  let Some(transaction) = transaction else {
                    Err(InterfaceError::InvalidInterface(
                      "transaction without transaction encoding".to_owned(),
                    ))?
                  };

                  // Only use the prunable hash if this transaction has a well-defined prunable hash
                  let prunable_hash =
                    prunable_hash.filter(|_| !matches!(transaction, Transaction::V1 { .. }));

                  /*
                    If this is a transaction which SHOULD have a prunable hash, yet the prunable
                    hash was either missing or `[0; 32]` (an uninitialized value with statistically
                    negligible probability of occurring natturally), return `None`. This signifies
                    this methodology shouldn't be used.

                    https://github.com/monero-project/monero/issues/10120
                  */
                  if matches!(transaction, Transaction::V2 { proofs: Some(_), .. }) &&
                    (prunable_hash.is_none() || (prunable_hash == Some([0; 32])))
                  {
                    return Ok(None);
                  }

                  let transaction =
                    PrunedTransactionWithPrunableHash::new(transaction, prunable_hash).ok_or_else(
                      || {
                        InterfaceError::InvalidInterface(
                          "non-v1 transaction missing prunable hash".to_owned(),
                        )
                      },
                    )?;
                  transactions.push(transaction);
                }
              }
              _ => {}
            }
          }

          let Some(block) = block else {
            Err(InterfaceError::InvalidInterface(
              "block entry itself was missing the block".to_owned(),
            ))?
          };
          res.push((block, transactions));
        }
      }
      b"output_indices" => {
        // Iterate all blocks
        let mut blocks_transaction_output_indexes = value.iterate().map_err(EpeeError)?;
        while let Some(block_transaction_output_indexes) = blocks_transaction_output_indexes.next()
        {
          // Iterate this block
          let block_transaction_output_indexes =
            block_transaction_output_indexes.map_err(EpeeError)?;
          let mut fields = block_transaction_output_indexes.fields().map_err(EpeeError)?;
          let Some(mut block_transaction_output_indexes) =
            optional_field!(fields, "indices", EpeeEntry::iterate)?
          else {
            continue;
          };
          while let Some(transaction_output_indexes) = block_transaction_output_indexes.next() {
            // Iterate this transaction
            let transaction_output_indexes = transaction_output_indexes.map_err(EpeeError)?;
            let mut fields = transaction_output_indexes.fields().map_err(EpeeError)?;
            let Some(mut transaction_output_indexes) =
              optional_field!(fields, "indices", EpeeEntry::iterate)?
            else {
              continue;
            };
            while let Some(index) = transaction_output_indexes.next() {
              all_output_indexes.push(index.map_err(EpeeError)?.to_u64().map_err(EpeeError)?);
            }
          }
        }
      }
      _ => {}
    }
  }

  // From the flattened view of output indexes, identify the first output index for a RingCT
  // transaction within each block
  let mut all_output_indexes = all_output_indexes.as_slice();
  let mut handle_transaction = |output_index_for_first_ringct_output: &mut Option<u64>,
                                transaction: &Transaction<Pruned>| {
    let outputs = transaction.prefix().outputs.len();
    if all_output_indexes.len() < outputs {
      return Err(InterfaceError::InvalidInterface(
        "block entry omitted output indexes for present transactions".to_owned(),
      ));
    }

    if (!matches!(transaction, Transaction::V1 { .. })) && (outputs != 0) {
      *output_index_for_first_ringct_output =
        output_index_for_first_ringct_output.or(Some(all_output_indexes[0]));
    }
    all_output_indexes = &all_output_indexes[outputs ..];
    Ok(())
  };
  let mut result = Vec::with_capacity(res.len());
  for (block, transactions) in res {
    let mut output_index_for_first_ringct_output = None;
    handle_transaction(
      &mut output_index_for_first_ringct_output,
      &block.miner_transaction().clone().into(),
    )?;
    for transaction in &transactions {
      handle_transaction(&mut output_index_for_first_ringct_output, transaction.as_ref())?;
    }
    result.push(UnvalidatedScannableBlock {
      block,
      transactions,
      output_index_for_first_ringct_output,
    });
  }
  if !all_output_indexes.is_empty() {
    Err(InterfaceError::InvalidInterface(
      "`get_blocks.bin` had a distinct amount of output indexes than transaction outputs"
        .to_owned(),
    ))?;
  }

  Ok(Some(result.into_iter()))
}

pub(super) fn extract_output_indexes(epee: &[u8]) -> Result<Vec<u64>, InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.entry().map_err(EpeeError)?.fields().map_err(EpeeError)?;
  let Some(mut indexes) = optional_field!(epee, "o_indexes", EpeeEntry::iterate)? else {
    return Ok(vec![]);
  };

  let mut res = vec![];
  while let Some(index) = indexes.next() {
    res.push(index.map_err(EpeeError)?.to_u64().map_err(EpeeError)?);
  }
  Ok(res)
}
