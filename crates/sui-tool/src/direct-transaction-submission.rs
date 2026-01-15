// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::ToFromBytes;
use std::fs;
use std::path::PathBuf;

use bytes::Bytes;
use sui_config::{SUI_CLIENT_CONFIG, sui_config_dir};
use sui_core::authority_client::{AuthorityAPI, NetworkAuthorityClient};
use sui_json_rpc_types::{
    SuiObjectData, SuiObjectDataFilter, SuiObjectDataOptions, SuiObjectResponse,
    SuiObjectResponseQuery, SuiProtocolConfigValue, SuiTransactionBlockResponseOptions,
};
use sui_network::tonic::IntoRequest;
use sui_sdk::wallet_context::WalletContext;
use sui_sdk::{SuiClient, SuiClientBuilder};
use sui_types::base_types::SuiAddress;
use sui_types::crypto::NetworkPublicKey;
use sui_types::gas_coin::GasCoin;
use sui_types::messages_grpc::{
    RawSubmitTxRequest, RawSubmitTxResponse, SubmitTxRequest, SubmitTxType,
};
use sui_types::multiaddr::Multiaddr;
use sui_types::transaction::{Transaction, TransactionData};

const DEFAULT_VALIDATOR_ADDR: &str = "/dns/mainnet-sui.stakingfacilities.com/tcp/10080/http";
const DEFAULT_VALIDATOR_PUBKEY_B64: &str = "lmFPxxSliX5uh2bygMxVQy559cV3+S8VvKb/Ft4iADc=";
const FALLBACK_GAS_BUDGET: u64 = 5_000_000;
const MIN_GAS_BUDGET: u64 = 5_000_000;

#[derive(Parser, Debug)]
#[command(name = "direct-transaction-submission")]
struct Args {
    /// Validator network address (Multiaddr)
    #[arg(long, default_value = DEFAULT_VALIDATOR_ADDR)]
    validator_address: String,

    /// Validator network public key bytes (base64)
    #[arg(long, default_value = DEFAULT_VALIDATOR_PUBKEY_B64)]
    validator_pubkey_b64: String,

    /// Path to Sui client config (client.yaml)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Optional RPC URL to query coins and protocol config
    #[arg(long)]
    rpc: Option<String>,

    /// Amount (in MIST) to send to self in each tx
    #[arg(long, default_value_t = 1)]
    amount: u64,

    /// Override gas budget (in MIST). If not set, uses minimum from protocol config.
    #[arg(long)]
    gas_budget: Option<u64>,

    /// Where to submit transactions
    #[arg(long, value_enum, default_value_t = SubmitTarget::Validator)]
    submit_target: SubmitTarget,

    /// Output path for signed transaction bytes (used with submit-target=file)
    #[arg(long, default_value = "signed_tx.bcs")]
    output_path: String,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SubmitTarget {
    Validator,
    Rpc,
    SoftBundle,
    File,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config_path = match args.config {
        Some(path) => path,
        None => sui_config_dir()?.join(SUI_CLIENT_CONFIG),
    };

    let mut wallet = WalletContext::new(&config_path)?;
    let sender = wallet.active_address()?;

    let client = match args.rpc.as_deref() {
        Some(rpc) => SuiClientBuilder::default().build(rpc).await?,
        None => wallet.get_client().await?,
    };

    let gas_price = client.read_api().get_reference_gas_price().await?;
    let gas_budget = match args.gas_budget {
        Some(budget) => budget,
        None => min_gas_budget(&client, gas_price).await?,
    };

    let mut gas_coins = fetch_gas_objects(&client, sender).await?;
    gas_coins.sort_by(|a, b| b.0.cmp(&a.0));
    let usable_coins = gas_coins
        .into_iter()
        .filter(|(value, _)| *value > args.amount + gas_budget)
        .collect::<Vec<_>>();

    let required_coins = match args.submit_target {
        SubmitTarget::File => 1,
        _ => 2,
    };
    if usable_coins.len() < required_coins {
        bail!(
            "Need at least {required_coins} gas coin(s) with balance > amount + gas_budget. Found {}",
            usable_coins.len()
        );
    }

    let tx1 = build_pay_sui_transaction(
        &wallet,
        sender,
        &usable_coins[0].1,
        args.amount,
        gas_budget,
        gas_price,
    )
    .await?;
    let tx2 = if required_coins > 1 {
        Some(
            build_pay_sui_transaction(
                &wallet,
                sender,
                &usable_coins[1].1,
                args.amount,
                gas_budget,
                gas_price,
            )
            .await?,
        )
    } else {
        None
    };

    let validator_address: Multiaddr = args.validator_address.parse()?;
    let pubkey_bytes = Base64::decode(&args.validator_pubkey_b64)
        .map_err(|e| anyhow!("invalid validator pubkey base64: {e}"))?;
    let validator_pubkey = NetworkPublicKey::from_bytes(&pubkey_bytes)?;
    let validator_client = if matches!(
        args.submit_target,
        SubmitTarget::Validator | SubmitTarget::SoftBundle
    ) {
        Some(NetworkAuthorityClient::connect(&validator_address, validator_pubkey).await?)
    } else {
        None
    };

    match args.submit_target {
        SubmitTarget::Validator => {
            let validator_client =
                validator_client.expect("validator client should be initialized");
            tokio::try_join!(
                submit_validator(validator_client.clone(), tx1, 1),
                submit_validator(validator_client, tx2.expect("tx2 should be built"), 2),
            )?;
        }
        SubmitTarget::Rpc => {
            tokio::try_join!(
                submit_rpc(client.clone(), tx1, 1),
                submit_rpc(client, tx2.expect("tx2 should be built"), 2),
            )?;
        }
        SubmitTarget::SoftBundle => {
            let validator_client =
                validator_client.expect("validator client should be initialized");
            submit_soft_bundle(
                validator_client,
                vec![tx1, tx2.expect("tx2 should be built")],
            )
            .await?;
        }
        SubmitTarget::File => {
            let tx_bytes = bcs::to_bytes(&tx1)?;
            fs::write(&args.output_path, tx_bytes)?;
            println!("wrote signed transaction to {}", args.output_path);
        }
    }

    Ok(())
}

async fn min_gas_budget(client: &SuiClient, gas_price: u64) -> Result<u64> {
    let config = client.read_api().get_protocol_config(None).await?;
    let base = config
        .attributes
        .get("base_tx_cost_fixed")
        .and_then(|v| v.as_ref())
        .and_then(|v| match v {
            SuiProtocolConfigValue::U64(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(FALLBACK_GAS_BUDGET);
    let budget = base.saturating_mul(gas_price);
    Ok(budget.max(MIN_GAS_BUDGET))
}

async fn build_pay_sui_transaction(
    wallet: &WalletContext,
    sender: SuiAddress,
    gas_coin: &SuiObjectData,
    amount: u64,
    gas_budget: u64,
    gas_price: u64,
) -> Result<Transaction> {
    let gas_payment = gas_coin.object_ref();
    let tx_data = TransactionData::new_pay_sui(
        sender,
        vec![],
        vec![sender],
        vec![amount],
        gas_payment,
        gas_budget,
        gas_price,
    )?;

    Ok(wallet.sign_transaction(&tx_data).await)
}

async fn fetch_gas_objects(
    client: &SuiClient,
    address: SuiAddress,
) -> Result<Vec<(u64, SuiObjectData)>> {
    let mut objects: Vec<SuiObjectResponse> = Vec::new();
    let mut cursor = None;
    loop {
        let response = client
            .read_api()
            .get_owned_objects(
                address,
                Some(SuiObjectResponseQuery::new(
                    Some(SuiObjectDataFilter::StructType(GasCoin::type_())),
                    Some(SuiObjectDataOptions::full_content()),
                )),
                cursor,
                None,
            )
            .await?;

        objects.extend(response.data);

        if response.has_next_page {
            cursor = response.next_cursor;
        } else {
            break;
        }
    }

    let mut values_objects = Vec::new();
    for object in objects {
        let Some(o) = object.data else {
            continue;
        };
        let gas_coin = GasCoin::try_from(&o)?;
        values_objects.push((gas_coin.value(), o));
    }

    Ok(values_objects)
}

async fn submit_validator(
    client: NetworkAuthorityClient,
    tx: Transaction,
    index: usize,
) -> Result<()> {
    let response = client
        .submit_transaction(SubmitTxRequest::new_transaction(tx), None)
        .await?;
    println!("validator tx{index}: {response:?}");
    Ok(())
}

async fn submit_rpc(client: SuiClient, tx: Transaction, index: usize) -> Result<()> {
    let response = client
        .quorum_driver_api()
        .execute_transaction_block(tx, SuiTransactionBlockResponseOptions::new(), None)
        .await?;
    println!("rpc tx{index}: {response:?}");
    Ok(())
}

async fn submit_soft_bundle(client: NetworkAuthorityClient, txs: Vec<Transaction>) -> Result<()> {
    let transactions = txs
        .into_iter()
        .map(|tx| bcs::to_bytes(&tx).map(Bytes::from))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let raw_request = RawSubmitTxRequest {
        transactions,
        submit_type: SubmitTxType::SoftBundle.into(),
    };
    let request = raw_request.into_request();
    let response: RawSubmitTxResponse = client
        .get_client_for_testing()?
        .submit_transaction(request)
        .await?
        .into_inner();
    println!("softbundle: {} results", response.results.len());
    println!("softbundle raw: {response:?}");
    Ok(())
}
