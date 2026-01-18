#![expect(missing_docs)]

use std::sync::LazyLock;
use tokio::sync::Mutex;

use monero_address::{Network, MoneroAddress};

use monero_simple_request_rpc::{prelude::*, *};

static SEQUENTIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

const ADDRESS: &str =
  "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey";

#[tokio::test]
async fn test_blockchain() {
  let _guard = SEQUENTIAL.lock().await;

  let rpc =
    SimpleRequestTransport::new("http://monero:oxide@127.0.0.1:18081".to_owned()).await.unwrap();

  let current_block_number = rpc.latest_block_number().await.unwrap();
  let latest_block = rpc.block_by_number(current_block_number).await.unwrap();
  assert_eq!(latest_block.number(), current_block_number);
  rpc.block_by_number(current_block_number + 1).await.unwrap_err();

  let (hashes, number) = rpc
    .generate_blocks(&MoneroAddress::from_str(Network::Mainnet, ADDRESS).unwrap(), 1)
    .await
    .unwrap();
  assert_eq!(hashes.len(), 1);
  assert_eq!(number, current_block_number + 1);
  let latest_block = rpc.block_by_number(number).await.unwrap();
  assert_eq!(latest_block.hash(), hashes[0]);
  assert_eq!(rpc.block(hashes[0]).await.unwrap(), latest_block);

  let contiguous_blocks = rpc.contiguous_blocks(number ..= number).await.unwrap();
  assert_eq!(contiguous_blocks.len(), 1);
  assert_eq!(contiguous_blocks[0], latest_block);

  let (hashes, new_number) = rpc
    .generate_blocks(&MoneroAddress::from_str(Network::Mainnet, ADDRESS).unwrap(), 2000)
    .await
    .unwrap();
  let contiguous_blocks = rpc.contiguous_blocks(number ..= new_number).await.unwrap();
  assert_eq!(contiguous_blocks[0], latest_block);
  assert_eq!(
    &{
      let mut blocks = vec![];
      for hash in &hashes {
        blocks.push(rpc.block(*hash).await.unwrap());
      }
      blocks
    },
    &contiguous_blocks[1 ..]
  );
  assert_eq!(contiguous_blocks.len(), new_number - number + 1);
  for ((block, hash), number) in contiguous_blocks
    .iter()
    .zip(core::iter::once(latest_block.hash()).chain(hashes))
    .zip(number ..= new_number)
  {
    assert_eq!(block.hash(), hash);
    assert_eq!(block.number(), number);
    assert_eq!(rpc.block_hash(number).await.unwrap(), hash);
  }
}

#[tokio::test]
async fn test_fee_rates() {
  let _guard = SEQUENTIAL.lock().await;

  let rpc =
    SimpleRequestTransport::new("http://monero:oxide@127.0.0.1:18081".to_owned()).await.unwrap();

  let fee_rate = rpc.fee_rate(FeePriority::Normal, u64::MAX).await.unwrap();
  rpc.fee_rate(FeePriority::Normal, fee_rate.per_weight()).await.unwrap();
  rpc.fee_rate(FeePriority::Normal, fee_rate.per_weight() - 1).await.unwrap_err();
}

#[tokio::test]
async fn test_decoys() {
  let _guard = SEQUENTIAL.lock().await;

  let rpc =
    SimpleRequestTransport::new("http://monero:oxide@127.0.0.1:18081".to_owned()).await.unwrap();

  // Ensure there's blocks on-chain
  rpc
    .generate_blocks(&MoneroAddress::from_str(Network::Mainnet, ADDRESS).unwrap(), 100)
    .await
    .unwrap();

  // Test `get_ringct_output_distribution`
  // Our documentation for our Rust fn defines it as taking two block numbers
  {
    let distribution_len = rpc.latest_block_number().await.unwrap() + 1;

    rpc.ringct_output_distribution(0 ..= distribution_len).await.unwrap_err();
    assert_eq!(
      rpc.ringct_output_distribution(0 .. distribution_len).await.unwrap().len(),
      distribution_len
    );
    assert_eq!(
      rpc.ringct_output_distribution(.. distribution_len).await.unwrap().len(),
      distribution_len
    );

    assert_eq!(
      rpc.ringct_output_distribution(.. (distribution_len - 1)).await.unwrap().len(),
      distribution_len - 1
    );
    assert_eq!(
      rpc.ringct_output_distribution(1 .. distribution_len).await.unwrap().len(),
      distribution_len - 1
    );

    assert_eq!(rpc.ringct_output_distribution(0 ..= 0).await.unwrap().len(), 1);
    assert_eq!(rpc.ringct_output_distribution(0 ..= 1).await.unwrap().len(), 2);
    assert_eq!(rpc.ringct_output_distribution(1 ..= 1).await.unwrap().len(), 1);

    rpc.ringct_output_distribution(0 .. 0).await.unwrap_err();
    #[expect(clippy::reversed_empty_ranges)]
    rpc.ringct_output_distribution(1 .. 0).await.unwrap_err();
  }

  {
    let latest_block_number = rpc.latest_block_number().await.unwrap();

    let lock_satisfied = latest_block_number - monero_oxide::COINBASE_LOCK_WINDOW;
    let lock_satisfied =
      rpc.ringct_output_distribution(lock_satisfied ..= lock_satisfied).await.unwrap();
    assert_eq!(lock_satisfied.len(), 1);

    {
      let res =
        rpc.unlocked_ringct_outputs(&[lock_satisfied[0]], EvaluateUnlocked::Normal).await.unwrap();
      assert_eq!(res.len(), 1);
      assert!(res[0].is_some());

      let res = rpc
        .unlocked_ringct_outputs(&[lock_satisfied[0] + 1], EvaluateUnlocked::Normal)
        .await
        .unwrap();
      assert_eq!(res.len(), 1);
      assert!(res[0].is_none());
    }
    {
      let res = rpc
        .unlocked_ringct_outputs(
          &[lock_satisfied[0]],
          EvaluateUnlocked::FingerprintableDeterministic { block_number: latest_block_number },
        )
        .await
        .unwrap();
      assert_eq!(res.len(), 1);
      assert!(res[0].is_some());

      let res = rpc
        .unlocked_ringct_outputs(
          &[lock_satisfied[0]],
          EvaluateUnlocked::FingerprintableDeterministic { block_number: latest_block_number - 1 },
        )
        .await
        .unwrap();
      assert_eq!(res.len(), 1);
      assert!(res[0].is_none());
    }
  }
}

#[tokio::test]
async fn test_block_hash_for_non_existent_block() {
  let _guard = SEQUENTIAL.lock().await;

  let rpc =
    SimpleRequestTransport::new("http://monero:oxide@127.0.0.1:18081".to_owned()).await.unwrap();
  let non_existent = rpc.latest_block_number().await.unwrap() + 1;
  rpc.block_hash(non_existent).await.unwrap_err();
}

/*
// This test passes yet requires a mainnet node, which we don't have reliable access to in CI.
#[tokio::test]
async fn test_output_indexes_with_transaction_with_no_outputs() {
  let _guard = SEQUENTIAL.lock().await;

  let rpc =
    SimpleRequestTransport::new("https://node.sethforprivacy.com".to_owned()).await.unwrap();

  assert_eq!(
    rpc
      .output_indexes(
        hex::decode("17ce4c8feeb82a6d6adaa8a89724b32bf4456f6909c7f84c8ce3ee9ebba19163")
          .unwrap()
          .try_into()
          .unwrap()
      )
      .await
      .unwrap(),
    Vec::<u64>::new()
  );
}
*/
