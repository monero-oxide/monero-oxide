#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

use serde::Deserialize;
use serde_json::json;

use monero_oxide::{
  ed25519::{Scalar, CompressedPoint, Commitment},
  ringct::{RctPrunable, bulletproofs::BatchVerifier},
  transaction::{Input, Transaction},
  block::Block,
};

use monero_simple_request_rpc::{prelude::*, SimpleRequestTransport};

use tokio::task::JoinHandle;

async fn check_block<T: HttpTransport>(rpc: MoneroDaemon<T>, block_i: usize) {
  let hash = loop {
    match rpc.block_hash(block_i).await {
      Ok(hash) => break hash,
      Err(InterfaceError::InterfaceError(e)) => {
        println!("get_block_hash InterfaceError: {e}");
        continue;
      }
      Err(e) => panic!("couldn't get block {block_i}'s hash: {e:?}"),
    }
  };

  // TODO: Grab the JSON to also check it was deserialized correctly
  #[derive(Deserialize, Debug)]
  struct BlockResponse {
    blob: String,
  }
  let res: BlockResponse = loop {
    match rpc
      .json_rpc_call(
        "get_block",
        Some(json!({ "hash": hex::encode(hash) }).to_string()),
        usize::MAX,
      )
      .await
    {
      Ok(res) => break serde_json::from_str(&res).unwrap(),
      Err(InterfaceError::InterfaceError(e)) => {
        println!("get_block InterfaceError: {e}");
        continue;
      }
      Err(e) => panic!("couldn't get block {block_i} via block.hash(): {e:?}"),
    }
  };

  let blob = hex::decode(res.blob).expect("node returned non-hex block");
  let block = Block::read(&mut blob.as_slice())
    .unwrap_or_else(|e| panic!("couldn't deserialize block {block_i}: {e}"));
  assert_eq!(block.hash(), hash, "hash differs");
  assert_eq!(block.serialize(), blob, "serialization differs");

  let txs_len = 1 + block.transactions.len();

  if !block.transactions.is_empty() {
    // Test getting pruned transactions
    loop {
      match rpc.pruned_transactions(&block.transactions).await {
        Ok(_) => break,
        Err(TransactionsError::InterfaceError(InterfaceError::InterfaceError(e))) => {
          println!("get_pruned_transactions InterfaceError: {e}");
          continue;
        }
        Err(e) => panic!("couldn't call get_pruned_transactions: {e:?}"),
      }
    }

    let txs = loop {
      match rpc.transactions(&block.transactions).await {
        Ok(txs) => break txs,
        Err(TransactionsError::InterfaceError(InterfaceError::InterfaceError(e))) => {
          println!("get_transactions InterfaceError: {e}");
          continue;
        }
        Err(e) => panic!("couldn't call get_transactions: {e:?}"),
      }
    };

    let mut batch = BatchVerifier::new();
    for tx in txs {
      match tx {
        Transaction::V1 { prefix: _, signatures } => {
          assert!(!signatures.is_empty());
          continue;
        }
        Transaction::V2 { prefix: _, proofs: None } => {
          panic!("proofs were empty in non-miner v2 transaction");
        }
        Transaction::V2 { ref prefix, proofs: Some(ref proofs) } => {
          let sig_hash = tx.signature_hash().expect("no signature hash for TX with proofs");
          // Verify all proofs we support proving for
          // This is due to having debug_asserts calling verify within their proving, and CLSAG
          // multisig explicitly calling verify as part of its signing process
          // Accordingly, making sure our signature_hash algorithm is correct is great, and further
          // making sure the verification functions are valid is appreciated
          match &proofs.prunable {
            RctPrunable::AggregateMlsagBorromean { .. } | RctPrunable::MlsagBorromean { .. } => {}
            RctPrunable::MlsagBulletproofs { bulletproof, .. } |
            RctPrunable::MlsagBulletproofsCompactAmount { bulletproof, .. } => {
              assert!(bulletproof.batch_verify(
                &mut rand_core::OsRng,
                &mut batch,
                &proofs.base.commitments
              ));
            }
            RctPrunable::Clsag { bulletproof, clsags, pseudo_outs } => {
              assert!(bulletproof.batch_verify(
                &mut rand_core::OsRng,
                &mut batch,
                &proofs.base.commitments
              ));

              for (i, clsag) in clsags.iter().enumerate() {
                let (amount, key_offsets, image) = match &prefix.inputs[i] {
                  Input::Gen(_) => panic!("Input::Gen"),
                  Input::ToKey { amount, key_offsets, key_image } => {
                    (amount, key_offsets, key_image)
                  }
                };

                let mut running_sum = 0;
                let mut actual_indexes = vec![];
                for offset in key_offsets {
                  running_sum += offset;
                  actual_indexes.push(running_sum);
                }

                async fn get_outs<T: HttpTransport>(
                  rpc: &MoneroDaemon<T>,
                  amount: u64,
                  indexes: &[u64],
                ) -> Vec<[CompressedPoint; 2]> {
                  #[derive(Deserialize, Debug)]
                  struct Out {
                    key: String,
                    mask: String,
                  }

                  #[derive(Deserialize, Debug)]
                  struct Outs {
                    outs: Vec<Out>,
                  }

                  let outs: Outs = loop {
                    match rpc
                      .rpc_call(
                        "get_outs",
                        Some(
                          json!({
                            "get_txid": true,
                            "outputs": indexes.iter().map(|o| json!({
                              "amount": amount,
                              "index": o
                            })).collect::<Vec<_>>()
                          })
                          .to_string(),
                        ),
                        usize::MAX,
                      )
                      .await
                    {
                      Ok(outs) => break serde_json::from_str(&outs).unwrap(),
                      Err(InterfaceError::InterfaceError(e)) => {
                        println!("get_outs InterfaceError: {e}");
                        continue;
                      }
                      Err(e) => panic!("couldn't connect to RPC to get outs: {e:?}"),
                    }
                  };

                  let rpc_point = |point: &str| {
                    CompressedPoint::from(
                      <[u8; 32]>::try_from(
                        hex::decode(point).expect("invalid hex for ring member"),
                      )
                      .expect("invalid point len for ring member"),
                    )
                  };

                  outs
                    .outs
                    .iter()
                    .map(|out| {
                      let mask = rpc_point(&out.mask);
                      if amount != 0 {
                        assert_eq!(mask, Commitment::new(Scalar::ONE, amount).commit().compress());
                      }
                      [rpc_point(&out.key), mask]
                    })
                    .collect()
                }

                clsag
                  .verify(
                    get_outs(&rpc, amount.unwrap_or(0), &actual_indexes).await,
                    image,
                    &pseudo_outs[i],
                    &sig_hash,
                  )
                  .unwrap();
              }
            }
          }
        }
      }
    }
    assert!(batch.verify());
  }

  println!("Deserialized, hashed, and reserialized {block_i} with {txs_len} TXs");
}

#[tokio::main]
async fn main() {
  let args = std::env::args().collect::<Vec<String>>();

  // Read start block as the first arg
  let mut block_i =
    args.get(1).expect("no start block specified").parse::<usize>().expect("invalid start block");

  // How many blocks to work on at once
  let async_parallelism: usize =
    args.get(2).unwrap_or(&"8".to_owned()).parse::<usize>().expect("invalid parallelism argument");

  // Read further args as RPC URLs
  let default_nodes = vec![
    "http://xmr-node-uk.cakewallet.com:18081".to_owned(),
    "http://xmr-node-eu.cakewallet.com:18081".to_owned(),
  ];
  let mut specified_nodes = vec![];
  {
    let mut i = 0;
    while let Some(node) = args.get(3 + i) {
      specified_nodes.push(node.clone());
      i += 1;
    }
  }
  let nodes = if specified_nodes.is_empty() { default_nodes } else { specified_nodes };

  let rpc = async |url: String| {
    SimpleRequestTransport::new(url.clone())
      .await
      .unwrap_or_else(|_| panic!("couldn't create SimpleRequestTransport connected to {url}"))
  };
  let main_rpc = rpc(nodes[0].clone()).await;
  let mut rpcs = vec![];
  for i in 0 .. async_parallelism {
    rpcs.push(rpc(nodes[i % nodes.len()].clone()).await);
  }

  let mut rpc_i = 0;
  let mut handles: Vec<JoinHandle<()>> = vec![];
  let mut latest_block_number = 0;
  loop {
    let new_latest_block_number =
      main_rpc.latest_block_number().await.expect("couldn't call get_latest_block_number");
    if new_latest_block_number == latest_block_number {
      break;
    }
    latest_block_number = new_latest_block_number;

    while block_i <= latest_block_number {
      if handles.len() >= async_parallelism {
        // Guarantee one handle is complete
        handles.swap_remove(0).await.unwrap();

        // Remove all of the finished handles
        let mut i = 0;
        while i < handles.len() {
          if handles[i].is_finished() {
            handles.swap_remove(i).await.unwrap();
            continue;
          }
          i += 1;
        }
      }

      handles.push(tokio::spawn(check_block(rpcs[rpc_i].clone(), block_i)));
      rpc_i = (rpc_i + 1) % rpcs.len();
      block_i += 1;
    }
  }
}
