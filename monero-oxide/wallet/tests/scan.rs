#![expect(missing_docs)]

use monero_simple_request_rpc::{prelude::MoneroDaemon, SimpleRequestTransport};
use monero_wallet::{
  transaction::Transaction, address::SubaddressIndex, extra::PaymentId, GuaranteedScanner,
};

mod runner;

type Rpc = MoneroDaemon<SimpleRequestTransport>;
type Tx = Transaction;

test!(
  scan_standard_address,
  (
    async |_, mut builder: Builder, _| {
      let view = runner::random_address().1;
      let scanner = Scanner::new(view.clone());
      builder.add_payment(view.legacy_address(Network::Mainnet), 5);
      (builder.build().unwrap(), scanner)
    },
    async |_rpc: Rpc, block, tx: Transaction, _, mut state: Scanner| {
      let output = state.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      let dummy_payment_id = PaymentId::Encrypted([0u8; 8]);
      assert_eq!(output.payment_id(), Some(dummy_payment_id));
    },
  ),
);

test!(
  scan_subaddress,
  (
    async |_, mut builder: Builder, _| {
      let subaddress = SubaddressIndex::new(0, 1).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      builder.add_payment(view.subaddress(Network::Mainnet, subaddress), 5);
      (builder.build().unwrap(), (scanner, subaddress))
    },
    async |_rpc: Rpc, block, tx: Transaction, _, mut state: (Scanner, SubaddressIndex)| {
      let output = state.0.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.subaddress(), Some(state.1));
    },
  ),
);

test!(
  scan_integrated_address,
  (
    async |_, mut builder: Builder, _| {
      let view = runner::random_address().1;
      let scanner = Scanner::new(view.clone());

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.legacy_integrated_address(Network::Mainnet, payment_id), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    async |_rpc: Rpc, block, tx: Transaction, _, mut state: (Scanner, [u8; 8])| {
      let output = state.0.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(state.1)));
    },
  ),
);

test!(
  scan_guaranteed,
  (
    async |_, mut builder: Builder, _| {
      let view = runner::random_guaranteed_address().1;
      let scanner = GuaranteedScanner::new(view.clone());
      builder.add_payment(view.address(Network::Mainnet, None, None), 5);
      (builder.build().unwrap(), scanner)
    },
    async |_rpc: Rpc, block, tx: Transaction, _, mut scanner: GuaranteedScanner| {
      let output = scanner.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.subaddress(), None);
    },
  ),
);

test!(
  scan_guaranteed_subaddress,
  (
    async |_, mut builder: Builder, _| {
      let subaddress = SubaddressIndex::new(0, 2).unwrap();

      let view = runner::random_guaranteed_address().1;
      let mut scanner = GuaranteedScanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      builder.add_payment(view.address(Network::Mainnet, Some(subaddress), None), 5);
      (builder.build().unwrap(), (scanner, subaddress))
    },
    async |_rpc: Rpc, block, tx: Tx, _, mut state: (GuaranteedScanner, SubaddressIndex)| {
      let output = state.0.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.subaddress(), Some(state.1));
    },
  ),
);

test!(
  scan_guaranteed_integrated,
  (
    async |_, mut builder: Builder, _| {
      let view = runner::random_guaranteed_address().1;
      let scanner = GuaranteedScanner::new(view.clone());
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.address(Network::Mainnet, None, Some(payment_id)), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    async |_rpc: Rpc, block, tx: Transaction, _, mut state: (GuaranteedScanner, [u8; 8])| {
      let output = state.0.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(state.1)));
    },
  ),
);

test!(
  scan_guaranteed_integrated_subaddress,
  (
    async |_, mut builder: Builder, _| {
      let subaddress = SubaddressIndex::new(0, 3).unwrap();

      let view = runner::random_guaranteed_address().1;
      let mut scanner = GuaranteedScanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.address(Network::Mainnet, Some(subaddress), Some(payment_id)), 5);
      (builder.build().unwrap(), (scanner, payment_id, subaddress))
    },
    async |_rpc, block, tx: Tx, _, mut state: (GuaranteedScanner, [u8; 8], SubaddressIndex)| {
      let output = state.0.scan(block).unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(state.1)));
      assert_eq!(output.subaddress(), Some(state.2));
    },
  ),
);
