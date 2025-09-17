#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::time::Duration;
use std::collections::{HashSet, HashMap};

use curve25519_dalek::EdwardsPoint;

use monero_oxide::{
  ringct::{
    mlsag::{RingMatrix, Mlsag},
    bulletproofs::BatchVerifier,
    RctPrunable,
  },
  transaction::{Input, Pruned, TransactionPrefix, Transaction},
  block::Block,
  io::CompressedPoint,
};

use monero_rpc::{RpcError, Rpc, DecoyRpc};
use monero_simple_request_rpc::SimpleRequestRpc;

/// Check the block's transactions, when pruned, behave as expected.
///
/// Returns the full list of transactions for the block.
async fn check_pruned_transaction(
  rpc: &impl Rpc,
  block: &Block,
) -> Result<Vec<Transaction>, RpcError> {
  {
    let pruned_miner_transaction = Transaction::<Pruned>::from(block.miner_transaction.clone());
    let miner_transaction_hash = block.miner_transaction.hash();
    assert_eq!(rpc.get_transaction(miner_transaction_hash).await?, block.miner_transaction,);
    assert_eq!(rpc.get_pruned_transaction(miner_transaction_hash).await?, pruned_miner_transaction);
  }
  let full;
  if !block.transactions.is_empty() {
    full = rpc.get_transactions(&block.transactions).await?;
    let pruned = rpc.get_pruned_transactions(&block.transactions).await?;
    assert_eq!(full.len(), pruned.len());
    for (tx, pruned) in full.iter().cloned().zip(pruned) {
      assert_eq!(Transaction::<Pruned>::from(tx), pruned, "pruned TX differed");
    }
  } else {
    full = vec![];
  }
  Ok(full)
}

/// Fetch all referenced outputs.
async fn fetch_referenced_outputs(
  rpc: &impl Rpc,
  txs: &[Transaction],
) -> Result<HashMap<(u64, u64), (CompressedPoint, EdwardsPoint)>, RpcError> {
  let referenced = txs
    .iter()
    .flat_map(|tx| {
      tx.prefix().inputs.iter().map(|input| match input {
        Input::Gen(_) => panic!("non-miner transaction with Input::Gen"),
        Input::ToKey { amount, key_offsets, .. } => {
          // TODO
          if amount.is_some() {
            None?;
          }

          let mut accum = 0;
          Some(
            (if amount.is_none() { key_offsets.as_slice().iter() } else { [].as_slice().iter() })
              .map(move |offset| {
                accum += *offset;
                accum
              }),
          )
        }
      })
    })
    .flatten()
    .flatten()
    .collect::<HashSet<u64>>()
    .into_iter()
    .collect::<Vec<_>>();
  let outputs = rpc.get_outs(&referenced).await?;
  Ok(
    referenced
      .into_iter()
      .map(|index| (0, index))
      .zip(outputs.into_iter().map(|info| (info.key.into(), info.commitment)))
      .collect(),
  )
}

/// Check the transactions' sanity.
fn check_sanity(txs: &[Transaction]) {
  for tx in txs {
    match tx {
      Transaction::V1 { prefix: _, signatures } => {
        assert!(!signatures.is_empty(), "V1 transaction without signatures");
        continue;
      }
      Transaction::V2 { prefix: _, proofs: None } => {
        panic!("V2 non-miner transaction without proofs");
      }
      Transaction::V2 { prefix: _, proofs: Some(_) } => {}
    }
  }
}

fn verify_mlsags(
  outputs: &HashMap<(u64, u64), (CompressedPoint, EdwardsPoint)>,
  prefix: &TransactionPrefix,
  sig_hash: &[u8; 32],
  mlsags: &[Mlsag],
  pseudo_outs: &[CompressedPoint],
) {
  assert_eq!(prefix.inputs.len(), mlsags.len(), "distinct amount of inputs and MLSAGs");
  assert_eq!(prefix.inputs.len(), pseudo_outs.len(), "distinct amount of inputs and pseudo-outs");
  for (i, mlsag) in mlsags.iter().enumerate() {
    match &prefix.inputs[i] {
      Input::Gen(_) => panic!("non-miner transaction had `Input::Gen`"),
      Input::ToKey { amount, key_offsets, key_image } => {
        // TODO
        if amount.is_some() {
          continue;
        }

        let mut accum = 0;
        let outputs = key_offsets
          .iter()
          .map(|offset| {
            accum += offset;
            let output = outputs[&(amount.unwrap_or(0), accum)];
            [output.0, output.1.compress().into()]
          })
          .collect::<Vec<_>>();
        mlsag
          .verify(
            sig_hash,
            &RingMatrix::individual(&outputs, pseudo_outs[i]).unwrap(),
            &[*key_image],
          )
          .expect("failed to verify MLSAG");
      }
    }
  }
}

fn check_ringct_membership_proofs(
  txs: &[Transaction],
  outputs: &HashMap<(u64, u64), (CompressedPoint, EdwardsPoint)>,
) {
  for tx in txs {
    #[allow(clippy::single_match)]
    match tx {
      Transaction::V2 { prefix, proofs: Some(ref proofs) } => {
        let sig_hash =
          tx.signature_hash().expect("no signature hash for V2 transaction with proofs");
        match &proofs.prunable {
          RctPrunable::AggregateMlsagBorromean { .. } => {
            // TODO
          }
          RctPrunable::MlsagBorromean { mlsags, .. } => {
            let pseudo_outs = &proofs.base.pseudo_outs;
            verify_mlsags(outputs, prefix, &sig_hash, mlsags, pseudo_outs);
          }
          RctPrunable::MlsagBulletproofs { mlsags, pseudo_outs, .. } |
          RctPrunable::MlsagBulletproofsCompactAmount { mlsags, pseudo_outs, .. } => {
            verify_mlsags(outputs, prefix, &sig_hash, mlsags, pseudo_outs);
          }
          RctPrunable::Clsag { clsags, pseudo_outs, .. } => {
            assert_eq!(prefix.inputs.len(), clsags.len(), "distinct amount of inputs and CLSAGs");
            assert_eq!(
              prefix.inputs.len(),
              pseudo_outs.len(),
              "distinct amount of inputs and pseudo-outs"
            );
            for (i, clsag) in clsags.iter().enumerate() {
              match &prefix.inputs[i] {
                Input::Gen(_) => panic!("non-miner transaction had `Input::Gen`"),
                Input::ToKey { amount, key_offsets, key_image } => {
                  // TODO
                  if amount.is_some() {
                    continue;
                  }

                  let mut accum = 0;
                  let outputs = key_offsets
                    .iter()
                    .map(|offset| {
                      accum += offset;
                      let output = outputs[&(amount.unwrap_or(0), accum)];
                      [output.0, output.1.compress().into()]
                    })
                    .collect::<Vec<_>>();
                  clsag
                    .verify(outputs, key_image, &pseudo_outs[i], &sig_hash)
                    .expect("failed to verify CLSAG");
                }
              }
            }
          }
        }
      }
      _ => {}
    }
  }
}

/// Check the transactions' range proofs.
fn check_range_proofs(txs: &[Transaction]) {
  let mut batch = BatchVerifier::new();
  for tx in txs {
    match tx {
      Transaction::V1 { .. } => {}
      Transaction::V2 { prefix: _, proofs } => {
        let Some(proofs) = proofs else { panic!("non-miner V2 transaction without proofs") };
        match &proofs.prunable {
          RctPrunable::AggregateMlsagBorromean { borromean, .. } |
          RctPrunable::MlsagBorromean { borromean, .. } => {
            assert_eq!(borromean.len(), proofs.base.commitments.len());
            for (borromean, commitment) in borromean.iter().zip(&proofs.base.commitments) {
              assert!(
                borromean.verify(commitment),
                "couldn't verify borromean range proof on mainnet"
              );
            }
          }
          RctPrunable::MlsagBulletproofs { bulletproof, .. } |
          RctPrunable::MlsagBulletproofsCompactAmount { bulletproof, .. } |
          RctPrunable::Clsag { bulletproof, .. } => {
            assert!(bulletproof.batch_verify(
              &mut rand_core::OsRng,
              &mut batch,
              &proofs.base.commitments
            ));
          }
        }
      }
    }
  }
  assert!(batch.verify(), "couldn't verify range proofs on mainnet");
}

async fn check_block(rpc: &impl Rpc, block: &Block) -> Result<(), RpcError> {
  let number = block.number().expect("on-chain block didn't have number");
  if rpc.get_block_hash(number).await? != block.hash() {
    panic!("calculated distinct block hash for {number}");
  }

  // TODO: This is IO bound
  let txs = check_pruned_transaction(rpc, block).await?;
  let outputs = fetch_referenced_outputs(rpc, &txs).await?;
  // TODO: This is compute bound
  check_sanity(&txs);
  check_ringct_membership_proofs(&txs, &outputs);
  check_range_proofs(&txs);
  // TODO: After fetching one block's transactions, fetch the next while we do this block's compute

  Ok(())
}

#[tokio::main]
async fn main() {
  let args = std::env::args().collect::<Vec<String>>();

  // Read start block as the first arg
  let start_block =
    args.get(1).expect("no start block specified").parse::<usize>().expect("invalid start block");
  // Read end block as the second arg
  let end_block =
    args.get(2).expect("no end block specified").parse::<usize>().expect("invalid end block");

  // Read further args as RPC URLs
  let default_nodes = vec![
    "http://xmr-node.cakewallet.com:18081".to_string(),
    "https://node.sethforprivacy.com".to_string(),
  ];
  let mut specified_nodes = vec![];
  {
    let mut i = 0;
    loop {
      let Some(node) = args.get(3 + i) else { break };
      specified_nodes.push(node.clone());
      i += 1;
    }
  }
  let nodes = if specified_nodes.is_empty() { default_nodes } else { specified_nodes };

  let mut rpcs = vec![];
  for node in nodes {
    if let Ok(node) =
      SimpleRequestRpc::with_custom_timeout(node.clone(), Duration::from_secs(60)).await
    {
      rpcs.push(node);
    } else {
      println!("couldn't create SimpleRequestRpc connected to {node}");
    }
  }

  let mut rpc = 0;
  for number in start_block ..= end_block {
    println!("Verifying block {number}");

    let mut block = None;
    for _ in 0 .. rpcs.len() {
      // Rotate which RPC we use
      rpc += 1;
      let rpc = rpc % rpcs.len();

      // TODO: contiguous_blocks
      match rpcs[rpc].get_block_by_number(number).await {
        Ok(block_val) => {
          block = Some(block_val);
          break;
        }
        Err(e) => println!("failed to fetch block {number} with RPC {rpc}: {e:?}"),
      }
    }
    let block = block.expect("failed to fetch block {number} from any RPC");

    let mut checked = false;
    for _ in 0 .. rpcs.len() {
      rpc += 1;
      let rpc = rpc % rpcs.len();
      match check_block(&rpcs[rpc], &block).await {
        Ok(()) => {
          checked = true;
          break;
        }
        Err(e) => println!("failed to check block {number} with RPC {rpc}: {e:?}"),
      }
    }
    if !checked {
      panic!("failed to check block {number} with any RPC");
    }
  }
}
