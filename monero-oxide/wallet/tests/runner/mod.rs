use std_shims::sync::LazyLock;

use zeroize::Zeroizing;
use rand_core::OsRng;

#[cfg(feature = "compile-time-generators")]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(not(feature = "compile-time-generators"))]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT_TABLE;

use tokio::sync::Mutex;

use monero_simple_request_rpc::{prelude::MoneroDaemon, SimpleRequestTransport};
use monero_wallet::{
  ed25519::{Scalar, Point},
  ringct::RctType,
  transaction::Transaction,
  block::Block,
  interface::prelude::*,
  address::{Network, AddressType, MoneroAddress},
  DEFAULT_LOCK_WINDOW, ViewPair, GuaranteedViewPair, WalletOutput, Scanner,
};

mod builder;
pub use builder::SignableTransactionBuilder;

pub fn ring_len(rct_type: RctType) -> u8 {
  match rct_type {
    RctType::ClsagBulletproof => 11,
    RctType::ClsagBulletproofPlus => 16,
    RctType::AggregateMlsagBorromean |
    RctType::MlsagBorromean |
    RctType::MlsagBulletproofs |
    RctType::MlsagBulletproofsCompactAmount => panic!("ring size unknown for RctType"),
  }
}

pub fn random_address() -> (Scalar, ViewPair, MoneroAddress) {
  let spend = Scalar::random(&mut OsRng).into();
  let spend_pub = Point::from(&spend * ED25519_BASEPOINT_TABLE);
  let view = Scalar::random(&mut OsRng).into();
  (
    Scalar::from(spend),
    ViewPair::new(spend_pub, Zeroizing::new(Scalar::from(view))).unwrap(),
    MoneroAddress::new(
      Network::Mainnet,
      AddressType::Legacy,
      spend_pub,
      Point::from(&view * ED25519_BASEPOINT_TABLE),
    ),
  )
}

#[allow(unused)]
pub fn random_guaranteed_address() -> (Scalar, GuaranteedViewPair, MoneroAddress) {
  let spend = Scalar::random(&mut OsRng).into();
  let spend_pub = Point::from(&spend * ED25519_BASEPOINT_TABLE);
  let view = Scalar::random(&mut OsRng).into();
  (
    Scalar::from(spend),
    GuaranteedViewPair::new(spend_pub, Zeroizing::new(Scalar::from(view))).unwrap(),
    MoneroAddress::new(
      Network::Mainnet,
      AddressType::Legacy,
      spend_pub,
      Point::from(&view * ED25519_BASEPOINT_TABLE),
    ),
  )
}

// TODO: Support transactions already on-chain
// TODO: Don't have a side effect of mining blocks more blocks than needed under race conditions
pub async fn mine_until_unlocked(
  rpc: &MoneroDaemon<SimpleRequestTransport>,
  addr: &MoneroAddress,
  tx_hash: [u8; 32],
) -> Block {
  // mine until tx is in a block
  let mut height = rpc.latest_block_number().await.unwrap() + 1;
  let mut found = false;
  let mut block = None;
  while !found {
    let inner_block = rpc.block_by_number(height - 1).await.unwrap();
    found = match inner_block.transactions.iter().find(|&&x| x == tx_hash) {
      Some(_) => {
        block = Some(inner_block);
        true
      }
      None => {
        height = rpc.generate_blocks(addr, 1).await.unwrap().1 + 1;
        false
      }
    }
  }

  // Mine until tx's outputs are unlocked
  for _ in 0 .. (DEFAULT_LOCK_WINDOW - 1) {
    rpc.generate_blocks(addr, 1).await.unwrap();
  }

  block.unwrap()
}

// Mines 60 blocks and returns an unlocked miner TX output.
#[allow(dead_code)]
pub async fn get_miner_tx_output(
  rpc: &MoneroDaemon<SimpleRequestTransport>,
  view: &ViewPair,
) -> WalletOutput {
  let mut scanner = Scanner::new(view.clone());

  // Mine 60 blocks to unlock a miner TX
  let start = rpc.latest_block_number().await.unwrap() + 1;
  rpc.generate_blocks(&view.legacy_address(Network::Mainnet), 60).await.unwrap();

  let block = rpc.block_by_number(start).await.unwrap();
  scanner
    .scan(rpc.expand_to_scannable_block(block).await.unwrap())
    .unwrap()
    .ignore_additional_timelock()
    .swap_remove(0)
}

/// Make sure the weight and fee match the expected calculation.
pub fn check_weight_and_fee(tx: &Transaction, fee_rate: FeeRate) {
  let Transaction::V2 { proofs: Some(ref proofs), .. } = tx else { panic!("TX wasn't RingCT") };
  let fee = proofs.base.fee;

  let weight = tx.weight();
  let expected_weight = fee_rate.calculate_weight_from_fee(fee).unwrap();
  assert_eq!(weight, expected_weight);

  let expected_fee = fee_rate.calculate_fee_from_weight(weight);
  assert_eq!(fee, expected_fee);
}

pub async fn rpc() -> MoneroDaemon<SimpleRequestTransport> {
  let rpc =
    SimpleRequestTransport::new("http://monero:oxide@127.0.0.1:18081".to_owned()).await.unwrap();

  const BLOCKS_TO_MINE: usize = 110;

  // Only run once
  if (rpc.latest_block_number().await.unwrap() + 1) > BLOCKS_TO_MINE {
    return rpc;
  }

  let addr = MoneroAddress::new(
    Network::Mainnet,
    AddressType::Legacy,
    Point::from(&Scalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE),
    Point::from(&Scalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE),
  );

  // Mine enough blocks to ensure decoy availability
  rpc.generate_blocks(&addr, BLOCKS_TO_MINE).await.unwrap();

  rpc
}

pub(crate) static SEQUENTIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = runner::SEQUENTIAL.lock().await;
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  }
}

#[macro_export]
macro_rules! test {
  (
    $name: ident,
    (
      $first_tx: expr,
      $first_checks: expr,
    ),
    $((
      $tx: expr,
      $checks: expr,
    )$(,)?),*
  ) => {
    async_sequential! {
      async fn $name() {
        use core::any::Any;
        #[cfg(feature = "multisig")]
        use std::collections::HashMap;

        use zeroize::Zeroizing;
        use rand_core::{RngCore, OsRng};

        #[cfg(feature = "compile-time-generators")]
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        #[cfg(not(feature = "compile-time-generators"))]
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT_TABLE;

        #[cfg(feature = "multisig")]
        use frost::{
          curve::Ed25519,
          Participant,
          tests::{THRESHOLD, key_gen},
        };

        use monero_wallet::{
          ed25519::*,
          ringct::RctType,
          transaction::Pruned,
          interface::prelude::*,
          address::Network,
          ViewPair, Scanner, OutputWithDecoys,
          send::{Change, SignableTransaction, Eventuality},
        };

        use runner::{
          SignableTransactionBuilder, ring_len, random_address, rpc, mine_until_unlocked,
          get_miner_tx_output, check_weight_and_fee,
        };

        type Builder = SignableTransactionBuilder;

        // Run each function as both a single signer and as a multisig
        #[allow(clippy::redundant_closure_call)]
        for multisig in [false, true] {
          // Only run the multisig variant if multisig is enabled
          if multisig {
            #[cfg(not(feature = "multisig"))]
            continue;
          }

          let spend = Zeroizing::new(Scalar::random(&mut OsRng));
          #[cfg(feature = "multisig")]
          let keys = key_gen::<_, Ed25519>(&mut OsRng);

          let spend_pub = Point::from(if !multisig {
            &(*spend).into() * ED25519_BASEPOINT_TABLE
          } else {
            #[cfg(not(feature = "multisig"))]
            panic!("Multisig branch called without the multisig feature");
            #[cfg(feature = "multisig")]
            keys[&Participant::new(1).unwrap()].group_key().0
          });

          let rpc = rpc().await;

          let view = Zeroizing::new(Scalar::random(&mut OsRng));
          let mut outgoing_view = Zeroizing::new([0; 32]);
          OsRng.fill_bytes(outgoing_view.as_mut());
          let view = ViewPair::new(spend_pub, view).unwrap();
          let addr = view.legacy_address(Network::Mainnet);

          let miner_tx = get_miner_tx_output(&rpc, &view).await;

          let rct_type = match rpc.block_by_number(
            rpc.latest_block_number().await.unwrap()
          ).await.unwrap().header.hardfork_version {
            14 => RctType::ClsagBulletproof,
            15 | 16 => RctType::ClsagBulletproofPlus,
            _ => panic!("unrecognized hardfork version"),
          };

          let builder = SignableTransactionBuilder::new(
            rct_type,
            outgoing_view,
            Change::new(
              ViewPair::new(
                Point::from(
                  &Scalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE
                ),
                Zeroizing::new(Scalar::random(&mut OsRng))
              ).unwrap(),
              None,
            ),
            rpc.fee_rate(FeePriority::Unimportant, u64::MAX).await.unwrap(),
          );

          let sign = |tx: SignableTransaction| {
            let spend = spend.clone();
            #[cfg(feature = "multisig")]
            let keys = keys.clone();

            assert_eq!(&SignableTransaction::read(&mut tx.serialize().as_slice()).unwrap(), &tx);

            let eventuality = Eventuality::from(tx.clone());

            let tx = if !multisig {
              tx.sign(&mut OsRng, &spend).unwrap()
            } else {
              #[cfg(not(feature = "multisig"))]
              panic!("multisig branch called without the multisig feature");
              #[cfg(feature = "multisig")]
              {
                let mut machines = HashMap::new();
                for i in (1 ..= THRESHOLD).map(|i| Participant::new(i).unwrap()) {
                  machines.insert(i, tx.clone().multisig(keys[&i].clone()).unwrap());
                }

                frost::tests::sign_without_caching(&mut OsRng, machines, &[])
              }
            };

            assert_eq!(&eventuality.extra(), &tx.prefix().extra, "eventuality extra was distinct");
            assert!(eventuality.matches(&tx.clone().into()), "eventuality didn't match");

            tx
          };

          // TODO: Generate a distinct wallet for each transaction to prevent overlap
          let next_addr = addr;

          let temp = Box::new({
            let mut builder = builder.clone();

            let input = OutputWithDecoys::fingerprintable_deterministic_new(
              &mut OsRng,
              &rpc,
              ring_len(rct_type),
              rpc.latest_block_number().await.unwrap(),
              miner_tx,
            ).await.unwrap();
            builder.add_input(input);

            let (tx, state) = ($first_tx)(rpc.clone(), builder, next_addr).await;
            let fee_rate = tx.fee_rate().clone();
            let signed = sign(tx);
            rpc.publish_transaction(&signed).await.unwrap();
            let block =
              mine_until_unlocked(&rpc, &random_address().2, signed.hash()).await;
            let block = rpc.expand_to_scannable_block(block).await.unwrap();
            assert_eq!(rpc.scannable_block(block.block.hash()).await.unwrap(), block);
            assert_eq!(
              rpc.scannable_block_by_number(block.block.number()).await.unwrap(),
              block,
            );
            let tx = rpc.transaction(signed.hash()).await.unwrap();
            assert_eq!(
              rpc.pruned_transaction(signed.hash()).await.unwrap(),
              Transaction::<Pruned>::from(tx.clone()),
            );
            check_weight_and_fee(&tx, fee_rate);
            let scanner = Scanner::new(view.clone());
            ($first_checks)(rpc.clone(), block, tx, scanner, state).await
          });
          #[allow(unused_variables, unused_mut, unused_assignments)]
          let mut carried_state: Box<dyn Any> = temp;

          $(
            let (tx, state) = ($tx)(
              rct_type,
              rpc.clone(),
              builder.clone(),
              next_addr,
              *carried_state.downcast().unwrap()
            ).await;
            let fee_rate = tx.fee_rate().clone();
            let signed = sign(tx);
            rpc.publish_transaction(&signed).await.unwrap();
            let block =
              mine_until_unlocked(&rpc, &random_address().2, signed.hash()).await;
            let block = rpc.expand_to_scannable_block(block).await.unwrap();
            assert_eq!(rpc.scannable_block(block.block.hash()).await.unwrap(), block);
            assert_eq!(
              rpc.scannable_block_by_number(block.block.number()).await.unwrap(),
              block,
            );
            let tx = rpc.transaction(signed.hash()).await.unwrap();
            assert_eq!(
              rpc.pruned_transaction(signed.hash()).await.unwrap(),
              Transaction::<Pruned>::from(tx.clone()),
            );
            if stringify!($name) != "spend_one_input_to_two_outputs_no_change" {
              // Skip weight and fee check for the above test because when there is no change,
              // the change is added to the fee
              check_weight_and_fee(&tx, fee_rate);
            }
            #[allow(unused_assignments)]
            {
              let scanner = Scanner::new(view.clone());
              carried_state = Box::new(($checks)(rpc.clone(), block, tx, scanner, state).await);
            }
          )*

          // Check the entire chain with `contiguous_scannable_blocks`
          {
            let number = rpc.latest_block_number().await.unwrap();
            let chain = rpc.contiguous_scannable_blocks(0 ..= number).await.unwrap();
            for i in 0 ..= number {
              assert_eq!(
                rpc.expand_to_scannable_block(rpc.block_by_number(i).await.unwrap()).await.unwrap(),
                chain[i],
              );
              assert_eq!(chain[i].block.number(), i);
            }
          }
        }
      }
    }
  }
}
