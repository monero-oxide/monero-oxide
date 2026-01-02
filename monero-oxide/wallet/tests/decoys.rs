#![expect(missing_docs)]

use monero_simple_request_rpc::{prelude::MoneroDaemon, SimpleRequestTransport};
use monero_wallet::{DEFAULT_LOCK_WINDOW, transaction::Transaction, WalletOutput};

mod runner;

type Rpc = MoneroDaemon<SimpleRequestTransport>;

test!(
  select_latest_output_as_decoy_canonical,
  (
    // First make an initial tx0
    async |_, mut builder: Builder, addr| {
      builder.add_payment(addr, 2_000_000_000_000);
      (builder.build().unwrap(), ())
    },
    async |_rpc: Rpc, block, tx: Transaction, mut scanner: Scanner, ()| {
      let output = scanner.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 2_000_000_000_000);
      output
    },
  ),
  (
    // Then make a second tx1
    async |rct_type: RctType, rpc: Rpc, mut builder: Builder, addr, state: _| {
      let output_tx0: WalletOutput = state;

      let input = OutputWithDecoys::fingerprintable_deterministic_new(
        &mut OsRng,
        &rpc,
        ring_len(rct_type),
        rpc.latest_block_number().await.unwrap(),
        output_tx0.clone(),
      )
      .await
      .unwrap();
      builder.add_input(input);
      builder.add_payment(addr, 1_000_000_000_000);

      (builder.build().unwrap(), (rct_type, output_tx0))
    },
    // Then make sure DSA selects freshly unlocked output from tx1 as a decoy
    async |rpc: Rpc, _, tx: Transaction, _: Scanner, state: (_, _)| {
      use rand_core::OsRng;

      let block_number = rpc.latest_block_number().await.unwrap();
      let height = block_number + 1;

      let most_recent_o_index = rpc.output_indexes(tx.hash()).await.unwrap().pop().unwrap();

      // Make sure output from tx1 is in the block in which it unlocks
      let out_tx1 = rpc.ringct_outputs(&[most_recent_o_index]).await.unwrap().swap_remove(0);
      assert_eq!(out_tx1.block_number, height - DEFAULT_LOCK_WINDOW);
      assert!(out_tx1.unlocked);

      // Select decoys using spendable output from tx0 as the real, and make sure DSA selects
      // the freshly unlocked output from tx1 as a decoy
      let (rct_type, output_tx0): (RctType, WalletOutput) = state;
      let mut selected_fresh_decoy = false;
      let mut attempts = 1000;
      while !selected_fresh_decoy && attempts > 0 {
        let decoys = OutputWithDecoys::fingerprintable_deterministic_new(
          &mut OsRng, // TODO: use a seeded RNG to consistently select the latest output
          &rpc,
          ring_len(rct_type),
          block_number,
          output_tx0.clone(),
        )
        .await
        .unwrap()
        .decoys()
        .clone();

        selected_fresh_decoy = decoys.positions().contains(&most_recent_o_index);
        attempts -= 1;
      }

      assert!(selected_fresh_decoy);
      assert_eq!(height, rpc.latest_block_number().await.unwrap() + 1);
    },
  ),
);

test!(
  select_latest_output_as_decoy,
  (
    // First make an initial tx0
    async |_, mut builder: Builder, addr| {
      builder.add_payment(addr, 2_000_000_000_000);
      (builder.build().unwrap(), ())
    },
    async |_rpc: Rpc, block, tx: Transaction, mut scanner: Scanner, ()| {
      let output = scanner.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 2_000_000_000_000);
      output
    },
  ),
  (
    // Then make a second tx1
    async |rct_type: RctType, rpc: Rpc, mut builder: Builder, addr, output_tx0: WalletOutput| {
      let rpc: Rpc = rpc;

      let input = OutputWithDecoys::new(
        &mut OsRng,
        &rpc,
        ring_len(rct_type),
        rpc.latest_block_number().await.unwrap(),
        output_tx0.clone(),
      )
      .await
      .unwrap();
      builder.add_input(input);
      builder.add_payment(addr, 1_000_000_000_000);

      (builder.build().unwrap(), (rct_type, output_tx0))
    },
    // Then make sure DSA selects freshly unlocked output from tx1 as a decoy
    async |rpc: Rpc, _, tx: Transaction, _: Scanner, state: (_, _)| {
      use rand_core::OsRng;

      let block_number = rpc.latest_block_number().await.unwrap();
      let height = block_number + 1;

      let most_recent_o_index = rpc.output_indexes(tx.hash()).await.unwrap().pop().unwrap();

      // Make sure output from tx1 is in the block in which it unlocks
      let out_tx1 = rpc.ringct_outputs(&[most_recent_o_index]).await.unwrap().swap_remove(0);
      assert_eq!(out_tx1.block_number, height - DEFAULT_LOCK_WINDOW);
      assert!(out_tx1.unlocked);

      // Select decoys using spendable output from tx0 as the real, and make sure DSA selects
      // the freshly unlocked output from tx1 as a decoy
      let (rct_type, output_tx0): (RctType, WalletOutput) = state;
      let mut selected_fresh_decoy = false;
      let mut attempts = 1000;
      while !selected_fresh_decoy && attempts > 0 {
        let decoys = OutputWithDecoys::new(
          &mut OsRng, // TODO: use a seeded RNG to consistently select the latest output
          &rpc,
          ring_len(rct_type),
          block_number,
          output_tx0.clone(),
        )
        .await
        .unwrap()
        .decoys()
        .clone();

        selected_fresh_decoy = decoys.positions().contains(&most_recent_o_index);
        attempts -= 1;
      }

      assert!(selected_fresh_decoy);
      assert_eq!(height, rpc.latest_block_number().await.unwrap() + 1);
    },
  ),
);
