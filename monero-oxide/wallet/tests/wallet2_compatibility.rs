#![expect(missing_docs)]

use rand_core::{RngCore as _, OsRng};

use serde::Deserialize;
use serde_json::json;

use monero_simple_request_rpc::{prelude::MoneroDaemon, SimpleRequestTransport};
use monero_wallet::{
  transaction::Transaction,
  interface::prelude::*,
  address::{Network, SubaddressIndex, MoneroAddress},
  extra::{MAX_ARBITRARY_DATA_SIZE, Extra, PaymentId},
  Scanner,
};

mod runner;

type Rpc = MoneroDaemon<SimpleRequestTransport>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressSpec {
  Legacy,
  LegacyIntegrated([u8; 8]),
  Subaddress(SubaddressIndex),
}

async fn make_integrated_address(rpc: &Rpc, payment_id: [u8; 8]) -> String {
  #[derive(Debug, Deserialize)]
  struct IntegratedAddressResponse {
    integrated_address: String,
  }

  let res: IntegratedAddressResponse = serde_json::from_str(
    &rpc
      .json_rpc_call(
        "make_integrated_address",
        Some(json!({ "payment_id": hex::encode(payment_id) }).to_string()),
        usize::MAX,
      )
      .await
      .unwrap(),
  )
  .unwrap();

  res.integrated_address
}

async fn initialize_rpcs() -> (Rpc, Rpc, MoneroAddress) {
  let wallet_rpc = SimpleRequestTransport::new("http://127.0.0.1:18083".to_owned()).await.unwrap();
  let daemon_rpc = runner::rpc().await;

  #[derive(Debug, Deserialize)]
  struct AddressResponse {
    address: String,
  }

  let mut wallet_id = [0; 8];
  OsRng.fill_bytes(&mut wallet_id);
  wallet_rpc
    .json_rpc_call(
      "create_wallet",
      Some(json!({ "filename": hex::encode(wallet_id), "language": "English" }).to_string()),
      usize::MAX,
    )
    .await
    .unwrap();

  let address: AddressResponse = serde_json::from_str(
    &wallet_rpc
      .json_rpc_call("get_address", Some(json!({ "account_index": 0 }).to_string()), usize::MAX)
      .await
      .unwrap(),
  )
  .unwrap();

  // Fund the new wallet
  let address = MoneroAddress::from_str(Network::Mainnet, &address.address).unwrap();
  daemon_rpc.generate_blocks(&address, 70).await.unwrap();

  (wallet_rpc, daemon_rpc, address)
}

async fn from_wallet_rpc_to_self(spec: AddressSpec) {
  // initialize rpc
  let (wallet_rpc, daemon_rpc, wallet_rpc_addr) = initialize_rpcs().await;

  // make an addr
  let (_, view_pair, _) = runner::random_address();
  let addr = match spec {
    AddressSpec::Legacy => view_pair.legacy_address(Network::Mainnet),
    AddressSpec::LegacyIntegrated(payment_id) => {
      view_pair.legacy_integrated_address(Network::Mainnet, payment_id)
    }
    AddressSpec::Subaddress(index) => view_pair.subaddress(Network::Mainnet, index),
  };

  // refresh & make a tx
  wallet_rpc.json_rpc_call("refresh", None, usize::MAX).await.unwrap();

  #[derive(Debug, Deserialize)]
  struct TransferResponse {
    tx_hash: String,
  }
  let tx: TransferResponse = serde_json::from_str(
    &wallet_rpc
      .json_rpc_call(
        "transfer",
        Some(
          json!({
              "destinations": [{"address": addr.to_string(), "amount": 1_000_000_000_000u64 }],
          })
          .to_string(),
        ),
        usize::MAX,
      )
      .await
      .unwrap(),
  )
  .unwrap();
  let tx_hash = hex::decode(tx.tx_hash).unwrap().try_into().unwrap();

  let fee_rate = daemon_rpc.fee_rate(FeePriority::Unimportant, u64::MAX).await.unwrap();

  // unlock it
  let block = runner::mine_until_unlocked(&daemon_rpc, &wallet_rpc_addr, tx_hash).await;
  let block = daemon_rpc.expand_to_scannable_block(block).await.unwrap();

  // Create the scanner
  let mut scanner = Scanner::new(view_pair);
  if let AddressSpec::Subaddress(index) = spec {
    scanner.register_subaddress(index);
  }

  // Retrieve it and scan it
  let output = scanner.scan(block).unwrap().not_additionally_locked().swap_remove(0);
  assert_eq!(output.transaction(), tx_hash);

  runner::check_weight_and_fee(&daemon_rpc.transaction(tx_hash).await.unwrap(), fee_rate);

  match spec {
    AddressSpec::Subaddress(index) => {
      assert_eq!(output.subaddress(), Some(index));
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted([0u8; 8])));
    }
    AddressSpec::LegacyIntegrated(payment_id) => {
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(payment_id)));
      assert_eq!(output.subaddress(), None);
    }
    AddressSpec::Legacy => {
      assert_eq!(output.subaddress(), None);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted([0u8; 8])));
    }
  }
  assert_eq!(output.commitment().amount, 1_000_000_000_000);
}

async_sequential!(
  async fn receipt_of_wallet_rpc_tx_standard() {
    from_wallet_rpc_to_self(AddressSpec::Legacy).await;
  }

  async fn receipt_of_wallet_rpc_tx_subaddress() {
    from_wallet_rpc_to_self(AddressSpec::Subaddress(SubaddressIndex::new(0, 1).unwrap())).await;
  }

  async fn receipt_of_wallet_rpc_tx_integrated() {
    let mut payment_id = [0u8; 8];
    OsRng.fill_bytes(&mut payment_id);
    from_wallet_rpc_to_self(AddressSpec::LegacyIntegrated(payment_id)).await;
  }
);

#[derive(PartialEq, Eq, Debug, Deserialize)]
struct Index {
  major: u32,
  minor: u32,
}

#[derive(Debug, Deserialize)]
struct Transfer {
  payment_id: String,
  subaddr_index: Index,
  amount: u64,
}

#[derive(Debug, Deserialize)]
struct TransfersResponse {
  transfer: Transfer,
  transfers: Vec<Transfer>,
}

test!(
  send_to_wallet_rpc_standard,
  (
    async |_, mut builder: Builder, _| {
      // initialize rpc
      let (wallet_rpc, _, wallet_rpc_addr) = initialize_rpcs().await;

      // add destination
      builder.add_payment(wallet_rpc_addr, 1_000_000);
      (builder.build().unwrap(), wallet_rpc)
    },
    async |_, _, tx: Transaction, _, data: Rpc| {
      // confirm receipt
      data.json_rpc_call("refresh", None, usize::MAX).await.unwrap();
      let transfer: TransfersResponse = serde_json::from_str(
        &data
          .json_rpc_call(
            "get_transfer_by_txid",
            Some(json!({ "txid": hex::encode(tx.hash()) }).to_string()),
            usize::MAX,
          )
          .await
          .unwrap(),
      )
      .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.transfer.amount, 1_000_000);
      assert_eq!(transfer.transfer.payment_id, hex::encode([0u8; 8]));
    },
  ),
);

test!(
  send_to_wallet_rpc_subaddress,
  (
    async |_, mut builder: Builder, _| {
      // initialize rpc
      let (wallet_rpc, _, _) = initialize_rpcs().await;

      // make the subaddress
      #[derive(Debug, Deserialize)]
      struct AccountResponse {
        address: String,
        account_index: u32,
      }
      let addr: AccountResponse = serde_json::from_str(
        &wallet_rpc.json_rpc_call("create_account", None, usize::MAX).await.unwrap(),
      )
      .unwrap();
      assert!(addr.account_index != 0);

      builder
        .add_payment(MoneroAddress::from_str(Network::Mainnet, &addr.address).unwrap(), 1_000_000);
      (builder.build().unwrap(), (wallet_rpc, addr.account_index))
    },
    async |_, _, tx: Transaction, _, data: (Rpc, u32)| {
      // confirm receipt
      data.0.json_rpc_call("refresh", None, usize::MAX).await.unwrap();
      let transfer: TransfersResponse = serde_json::from_str(
        &data
          .0
          .json_rpc_call(
            "get_transfer_by_txid",
            Some(json!({ "txid": hex::encode(tx.hash()), "account_index": data.1 }).to_string()),
            usize::MAX,
          )
          .await
          .unwrap(),
      )
      .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: data.1, minor: 0 });
      assert_eq!(transfer.transfer.amount, 1_000_000);
      assert_eq!(transfer.transfer.payment_id, hex::encode([0u8; 8]));

      // Make sure only one R was included in TX extra
      assert!(Extra::read(&mut tx.prefix().extra.as_slice()).unwrap().keys().unwrap().1.is_none());
    },
  ),
);

test!(
  send_to_wallet_rpc_subaddresses,
  (
    async |_, mut builder: Builder, _| {
      // initialize rpc
      let (wallet_rpc, daemon_rpc, _) = initialize_rpcs().await;

      // make the subaddress
      #[derive(Debug, Deserialize)]
      struct AddressesResponse {
        addresses: Vec<String>,
        address_index: u32,
      }
      let addrs: AddressesResponse = serde_json::from_str(
        &wallet_rpc
          .json_rpc_call(
            "create_address",
            Some(json!({ "account_index": 0, "count": 2 }).to_string()),
            usize::MAX,
          )
          .await
          .unwrap(),
      )
      .unwrap();
      assert!(addrs.address_index != 0);
      assert!(addrs.addresses.len() == 2);

      builder.add_payments(&[
        (MoneroAddress::from_str(Network::Mainnet, &addrs.addresses[0]).unwrap(), 1_000_000),
        (MoneroAddress::from_str(Network::Mainnet, &addrs.addresses[1]).unwrap(), 2_000_000),
      ]);
      (builder.build().unwrap(), (wallet_rpc, daemon_rpc, addrs.address_index))
    },
    async |_, _, tx: Transaction, _, data: (Rpc, Rpc, u32)| {
      // confirm receipt
      data.0.json_rpc_call("refresh", None, usize::MAX).await.unwrap();
      let transfer: TransfersResponse = serde_json::from_str(
        &data
          .0
          .json_rpc_call(
            "get_transfer_by_txid",
            Some(json!({ "txid": hex::encode(tx.hash()), "account_index": 0 }).to_string()),
            usize::MAX,
          )
          .await
          .unwrap(),
      )
      .unwrap();

      assert_eq!(transfer.transfers.len(), 2);
      for t in transfer.transfers {
        match t.amount {
          1_000_000 => assert_eq!(t.subaddr_index, Index { major: 0, minor: data.2 }),
          2_000_000 => assert_eq!(t.subaddr_index, Index { major: 0, minor: data.2 + 1 }),
          _ => unreachable!(),
        }
      }

      // Make sure 3 additional pub keys are included in TX extra
      let keys = Extra::read(&mut tx.prefix().extra.as_slice()).unwrap().keys().unwrap().1.unwrap();

      assert_eq!(keys.len(), 3);
    },
  ),
);

test!(
  send_to_wallet_rpc_integrated,
  (
    async |_, mut builder: Builder, _| {
      // initialize rpc
      let (wallet_rpc, _, _) = initialize_rpcs().await;

      // make the addr
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);
      let addr = make_integrated_address(&wallet_rpc, payment_id).await;

      builder.add_payment(MoneroAddress::from_str(Network::Mainnet, &addr).unwrap(), 1_000_000);
      (builder.build().unwrap(), (wallet_rpc, payment_id))
    },
    async |_, _, tx: Transaction, _, data: (Rpc, [u8; 8])| {
      // confirm receipt
      data.0.json_rpc_call("refresh", None, usize::MAX).await.unwrap();
      let transfer: TransfersResponse = serde_json::from_str(
        &data
          .0
          .json_rpc_call(
            "get_transfer_by_txid",
            Some(json!({ "txid": hex::encode(tx.hash()) }).to_string()),
            usize::MAX,
          )
          .await
          .unwrap(),
      )
      .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.transfer.payment_id, hex::encode(data.1));
      assert_eq!(transfer.transfer.amount, 1_000_000);
    },
  ),
);

test!(
  send_to_wallet_rpc_with_arb_data,
  (
    async |_, mut builder: Builder, _| {
      // initialize rpc
      let (wallet_rpc, _, wallet_rpc_addr) = initialize_rpcs().await;

      // add destination
      builder.add_payment(wallet_rpc_addr, 1_000_000);

      // Make 2 data that is the full 255 bytes
      for _ in 0 .. 2 {
        let data = vec![b'a'; MAX_ARBITRARY_DATA_SIZE];
        builder.add_data(data).unwrap();
      }

      (builder.build().unwrap(), wallet_rpc)
    },
    async |_, _, tx: Transaction, _, data: Rpc| {
      // confirm receipt
      data.json_rpc_call("refresh", None, usize::MAX).await.unwrap();
      let transfer: TransfersResponse = serde_json::from_str(
        &data
          .json_rpc_call(
            "get_transfer_by_txid",
            Some(json!({ "txid": hex::encode(tx.hash()) }).to_string()),
            usize::MAX,
          )
          .await
          .unwrap(),
      )
      .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.transfer.amount, 1_000_000);
    },
  ),
);
