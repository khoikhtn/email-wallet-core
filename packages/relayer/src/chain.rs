use std::str::FromStr;

use ethers::abi::RawLog;
use ethers::middleware::Middleware;
use ethers::prelude::*;
use ethers::signers::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use shared::SHARED_MUTEX;

use crate::shared;
use crate::*;

const CONFIRMATIONS: usize = 1;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AccountCreationInput {
    pub(crate) email_addr_pointer: U256,
    pub(crate) account_key_commit: U256,
    pub(crate) wallet_salt: U256,
    pub(crate) psi_point: [U256; 2],
    pub(crate) proof: ProofJson,
}

#[derive(Default, Debug)]
pub struct AccountInitInput {
    pub(crate) email_addr_pointer: [u8; 32],
    pub(crate) email_domain: String,
    pub(crate) email_timestamp: U256,
    pub(crate) email_nullifier: [u8; 32],
    pub(crate) dkim_public_key_hash: [u8; 32],
    pub(crate) proof: Bytes,
}

#[derive(Default, Debug)]
pub struct AccountTransportInput {
    pub(crate) old_account_key_commit: [u8; 32],
    pub(crate) new_email_addr_pointer: [u8; 32],
    pub(crate) new_account_key_commit: [u8; 32],
    pub(crate) new_psi_point: Bytes,
    pub(crate) transport_email_proof: EmailProof,
    pub(crate) account_creation_proof: Bytes,
}

#[derive(Default, Debug)]
pub struct RegisterUnclaimedFundInput {
    pub(crate) email_addr_commit: [u8; 32],
    pub(crate) token_addr: Address,
    pub(crate) amount: U256,
    pub(crate) expiry_time: U256,
    pub(crate) announce_commit_randomness: U256,
    pub(crate) announce_email_addr: String,
}

#[derive(Default, Debug)]
pub struct ClaimInput {
    pub(crate) id: U256,
    pub(crate) email_addr_pointer: [u8; 32],
    pub(crate) is_fund: bool,
    pub(crate) proof: Bytes,
}

type SignerM = SignerMiddleware<Provider<Http>, LocalWallet>;

#[derive(Clone)]
pub struct ChainClient {
    // pub client: Arc<SignerM>,
    // pub(crate) core: EmailWalletCore<SignerM>,
    // pub(crate) token_registry: TokenRegistry<SignerM>,
    // pub(crate) account_handler: AccountHandler<SignerM>,
    // pub(crate) extension_handler: ExtensionHandler<SignerM>,
    // pub(crate) relayer_handler: RelayerHandler<SignerM>,
    // pub(crate) unclaims_handler: UnclaimsHandler<SignerM>,
    // pub(crate) ecdsa_owned_dkim_registry: ECDSAOwnedDKIMRegistry<SignerM>,
    // pub(crate) test_erc20: TestERC20<SignerM>,
    pub(crate) chain_sdk_client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
pub struct AccountCreationResponse {
    user_addr: String,
    account_creation_tx_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct GetWalletRes {
    pub address: String,
}

impl ChainClient {
    pub async fn setup() -> Result<Self> {
        // let wallet: LocalWallet = PRIVATE_KEY.get().unwrap().parse()?;
        // let provider = Provider::<Http>::try_from(CHAIN_RPC_PROVIDER.get().unwrap())?;
        // let client = Arc::new(SignerMiddleware::new(
        //     provider,
        //     wallet.with_chain_id(*CHAIN_ID.get().unwrap()),
        // ));
        // let core = EmailWalletCore::new(
        //     CORE_CONTRACT_ADDRESS.get().unwrap().parse::<Address>()?,
        //     client.clone(),
        // );
        // let token_registry_addr = core.token_registry().call().await.unwrap();
        // let token_registry = TokenRegistry::new(token_registry_addr, client.clone());
        // let account_handler_addr = core.account_handler().call().await.unwrap();
        // let account_handler = AccountHandler::new(account_handler_addr, client.clone());
        // let extension_handler =
        //     ExtensionHandler::new(core.extension_handler().call().await.unwrap(), client.clone());
        // let relayer_handler =
        //     RelayerHandler::new(core.relayer_handler().call().await.unwrap(), client.clone());
        // let unclaims_handler =
        //     UnclaimsHandler::new(core.unclaims_handler().call().await.unwrap(), client.clone());
        // let ecdsa_owned_dkim_registry = ECDSAOwnedDKIMRegistry::new(
        //     account_handler.default_dkim_registry().await.unwrap(),
        //     client.clone(),
        // );
        // let test_erc20 = TestERC20::new(
        //     token_registry.get_token_address("TEST".to_string()).await.unwrap(),
        //     client.clone(),
        // );
        Ok(Self {
            // client,
            // core,
            // token_registry,
            // account_handler,
            // extension_handler,
            // relayer_handler,
            // unclaims_handler,
            // ecdsa_owned_dkim_registry,
            // test_erc20,
            chain_sdk_client: reqwest::Client::new(),
        })
    }

    pub fn self_eth_addr(&self) -> Address {
        unimplemented!()
        // self.client.address()
    }

    pub async fn send_asset(
        &self,
        wallet_salt: &WalletSalt,
        asset: SendCommandAsset,
    ) -> Result<String> {
        let wallet_salt = fr_to_bytes32(&wallet_salt.0)?;
        match asset {
            SendCommandAsset::NativeToken {
                to_address,
                denom,
                amount,
            } => {
                let tx_hash = self
                    .chain_sdk_client
                    .post(format!(
                        "{}/transfer-token",
                        CHAIN_SDK_PROXY_SERVER.get().unwrap()
                    ))
                    .json(&json!({
                        "wallet_salt": wallet_salt,
                        "toAddress": to_address,
                        "denom": denom,
                        "amount": amount
                    }))
                    .send()
                    .await?
                    .json::<Value>()
                    .await?
                    .get("txHash")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                Ok(tx_hash)
            }
            SendCommandAsset::CW20 { to_address, contract_address, amount } => {
                let tx_hash = self
                    .chain_sdk_client
                    .post(format!(
                        "{}/transfer-cw20",
                        CHAIN_SDK_PROXY_SERVER.get().unwrap()
                    ))
                    .json(&json!({
                        "wallet_salt": wallet_salt,
                        "toAddress": to_address,
                        "amount": amount.to_string(),
                        "contract": contract_address
                    }))
                    .send()
                    .await?
                    .json::<Value>()
                    .await?
                    .get("txHash")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                Ok(tx_hash)
            }
            SendCommandAsset::NFT { to_address, contract_address, token_id } => {
                let tx_hash = self
                    .chain_sdk_client
                    .post(format!(
                        "{}/transfer-nft",
                        CHAIN_SDK_PROXY_SERVER.get().unwrap()
                    ))
                    .json(&json!({
                        "wallet_salt": wallet_salt,
                        "toAddress": to_address,
                        "contract": contract_address,
                        "tokenId": token_id
                    }))
                    .send()
                    .await?
                    .json::<Value>()
                    .await?
                    .get("txHash")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                Ok(tx_hash)
            }
        }
    }

    pub async fn register_relayer(
        &self,
        rand_hash: Fr,
        email_addr: String,
        hostname: String,
    ) -> Result<String> {
        // Mutex is used to prevent nonce conflicts.
        let mut mutex = SHARED_MUTEX.lock().await;
        *mutex += 1;
        println!("{}", field2string(&rand_hash));

        let call = self
            .chain_sdk_client
            .post(format!(
                "{}/register-relayer",
                CHAIN_SDK_PROXY_SERVER.get().unwrap()
            ))
            .json(&json!({
                "rand_hash": field2string(&rand_hash),
                "email_addr": email_addr,
                "hostname": hostname,
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await?;
        Ok(call.get("tx_hash").unwrap().as_str().unwrap().to_string())
    }

    pub async fn create_account(&self, data: AccountCreationInput) -> Result<String> {
        // Mutex is used to prevent nonce conflicts.
        let mut mutex = SHARED_MUTEX.lock().await;
        *mutex += 1;
        let psi_point: Vec<String> = data.psi_point.iter().map(|x| x.to_string()).collect();
        // Todo
        let res = self
            .chain_sdk_client
            .post(format!(
                "{}/create-account",
                CHAIN_SDK_PROXY_SERVER.get().unwrap()
            ))
            .json(&json!({
                "wallet_salt_byte32": u256_to_bytes32(&data.wallet_salt),
                "proof": {
                    "email_addr_pointer": data.email_addr_pointer.to_string(),
                    "account_key_commit": data.account_key_commit.to_string(),
                    "wallet_salt": data.wallet_salt.to_string(),
                    "psi_point": psi_point,
                    "proof": data.proof
                }
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let res_json = res.json::<AccountCreationResponse>().await?;
        info!(LOG, "account creation response {:?}", { &res_json });
        Ok(res_json.account_creation_tx_hash)
    }

    pub async fn init_account(&self, data: AccountInitInput) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // let call = self.account_handler.initialize_account(
        //     data.email_addr_pointer,
        //     data.email_domain,
        //     data.email_timestamp,
        //     data.email_nullifier,
        //     data.dkim_public_key_hash,
        //     data.proof,
        // );
        // let tx = call.send().await?;
        // let receipt = tx
        //     .log()
        //     .confirmations(CONFIRMATIONS)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        // let tx_hash = receipt.transaction_hash;
        // let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        // Ok(tx_hash)
    }

    pub async fn transport_account(&self, data: AccountTransportInput) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // let call = self.account_handler.transport_account(
        //     data.old_account_key_commit,
        //     data.new_email_addr_pointer,
        //     data.new_account_key_commit,
        //     data.new_psi_point,
        //     data.transport_email_proof,
        //     data.account_creation_proof,
        // );
        // let tx = call.send().await?;
        // let receipt = tx
        //     .log()
        //     .confirmations(CONFIRMATIONS)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        // let tx_hash = receipt.transaction_hash;
        // let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        // Ok(tx_hash)
    }

    pub async fn claim(&self, data: ClaimInput) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // if data.is_fund {
        //     let call = self.unclaims_handler.claim_unclaimed_fund(
        //         data.id,
        //         data.email_addr_pointer,
        //         data.proof,
        //     );
        //     let tx = call.send().await?;
        //     let receipt = tx
        //         .log()
        //         .confirmations(CONFIRMATIONS)
        //         .await?
        //         .ok_or(anyhow!("No receipt"))?;
        //     let tx_hash = receipt.transaction_hash;
        //     let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        //     Ok(tx_hash)
        // } else {
        //     let call = self.unclaims_handler.claim_unclaimed_state(
        //         data.id,
        //         data.email_addr_pointer,
        //         data.proof,
        //     );
        //     let tx = call.send().await?;
        //     let receipt = tx
        //         .log()
        //         .confirmations(CONFIRMATIONS)
        //         .await?
        //         .ok_or(anyhow!("No receipt"))?;
        //     let tx_hash = receipt.transaction_hash;
        //     let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        //     Ok(tx_hash)
        // }
    }

    pub async fn void(&self, id: U256, is_fund: bool) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // if is_fund {
        //     let call = self.unclaims_handler.void_unclaimed_fund(id);
        //     let tx = call.send().await?;
        //     let receipt = tx
        //         .log()
        //         .confirmations(CONFIRMATIONS)
        //         .await?
        //         .ok_or(anyhow!("No receipt"))?;
        //     let tx_hash = receipt.transaction_hash;
        //     let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        //     Ok(tx_hash)
        // } else {
        //     let call = self.unclaims_handler.void_unclaimed_state(id);
        //     let tx = call.send().await?;
        //     let receipt = tx
        //         .log()
        //         .confirmations(CONFIRMATIONS)
        //         .await?
        //         .ok_or(anyhow!("No receipt"))?;
        //     let tx_hash = receipt.transaction_hash;
        //     let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        //     Ok(tx_hash)
        // }
    }

    #[named]
    pub async fn handle_email_op(&self, email_op: EmailOp) -> Result<(String, U256)> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // let value = if !email_op.has_email_recipient {
        //     U256::zero()
        // } else if email_op.command == SEND_COMMAND {
        //     let gas = self.unclaims_handler.unclaimed_fund_claim_gas().await?;
        //     let fee = self.unclaims_handler.max_fee_per_gas().await?;
        //     gas * fee
        // } else {
        //     let gas = self.unclaims_handler.unclaimed_state_claim_gas().await?;
        //     let fee = self.unclaims_handler.max_fee_per_gas().await?;
        //     gas * fee
        // };
        // let call = self.core.handle_email_op(email_op);
        // let call = call.value(value);
        // let tx = call.send().await?;
        // let receipt = tx
        //     .log()
        //     .confirmations(CONFIRMATIONS)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        // let tx_hash = receipt.transaction_hash;
        // let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        // for log in receipt.logs.into_iter() {
        //     if let Ok(decoded) = EmailWalletEventsEvents::decode_log(&RawLog::from(log)) {
        //         match decoded {
        //             EmailWalletEventsEvents::EmailOpHandledFilter(event) => {
        //                 info!(LOG, "event {:?}", event; "func" => function_name!());
        //                 return Ok((tx_hash, event.registered_unclaim_id));
        //             }
        //             _ => {
        //                 continue;
        //             }
        //         }
        //     }
        // }
        // Err(anyhow!("no EmailOpHandled event found in the receipt"))
    }

    pub async fn set_dkim_public_key_hash(
        &self,
        selector: String,
        domain_name: String,
        public_key_hash: [u8; 32],
        signature: Bytes,
    ) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // let call = self.ecdsa_owned_dkim_registry.set_dkim_public_key_hash(
        //     selector,
        //     domain_name,
        //     public_key_hash,
        //     signature,
        // );
        // let tx = match call.send().await {
        //     Ok(tx) => tx,
        //     Err(err) => {
        //         error!(LOG, "set_dkim_public_key_hash error {}", err);
        //         unimplemented!()
        //     }
        // };
        // let receipt = tx
        //     .log()
        //     .confirmations(CONFIRMATIONS)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        // let tx_hash = receipt.transaction_hash;
        // let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        // Ok(tx_hash)
    }

    pub async fn free_mint_test_erc20(&self, wallet_addr: Address, amount: U256) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // let call = self.test_erc20.free_mint_with_to(wallet_addr, amount);
        // let tx = call.send().await?;
        // let receipt = tx
        //     .log()
        //     .confirmations(CONFIRMATIONS)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        // let tx_hash = receipt.transaction_hash;
        // let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        // Ok(tx_hash)
    }

    pub(crate) async fn transfer_onboarding_tokens(&self, wallet_addr: H160) -> Result<String> {
        unimplemented!()
        // Mutex is used to prevent nonce conflicts.
        // let mut mutex = SHARED_MUTEX.lock().await;
        // *mutex += 1;
        //
        // let erc20 = ERC20::new(
        //     ONBOARDING_TOKEN_ADDR.get().unwrap().to_owned(),
        //     self.client.clone(),
        // );
        // let tx = erc20.transfer(
        //     wallet_addr,
        //     ONBOARDING_TOKEN_AMOUNT.get().unwrap().to_owned(),
        // );
        // let tx = tx.send().await?;
        //
        // let receipt = tx
        //     .log()
        //     .confirmations(CONFIRMATIONS)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        //
        // let tx_hash = receipt.transaction_hash;
        // let tx_hash = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        // Ok(tx_hash)
    }

    pub async fn query_account_key_commit(&self, pointer: &Fr) -> Result<Fr> {
        unimplemented!()
        // let account_key_commit = self
        //     .account_handler
        //     .account_key_commit_of_pointer(fr_to_bytes32(pointer)?)
        //     .await?;
        // bytes32_to_fr(&account_key_commit)
    }

    pub async fn query_account_info(&self, account_key_commit: &Fr) -> Result<AccountKeyInfo> {
        unimplemented!()
        // let info = self
        //     .account_handler
        //     .get_info_of_account_key_commit(fr_to_bytes32(account_key_commit)?)
        //     .await?;
        // Ok(info)
    }

    pub async fn query_user_erc20_balance(
        &self,
        wallet_salt: &WalletSalt,
        token_name: &str,
    ) -> Result<U256> {
        unimplemented!()
        // let token_addr = self
        //     .token_registry
        //     .get_token_address(token_name.to_string())
        //     .call()
        //     .await?;
        // let erc20 = ERC20::new(token_addr, self.client.clone());
        // let wallet_addr = self.get_wallet_addr_from_salt(&wallet_salt.0).await?;
        // let balance = erc20.balance_of(wallet_addr).call().await?;
        // Ok(balance)
    }

    pub async fn query_erc20_address(&self, token_name: &str) -> Result<Address> {
        unimplemented!()
        // let token_addr = self
        //     .token_registry
        //     .get_token_address(token_name.to_string())
        //     .call()
        //     .await?;
        // Ok(token_addr)
    }

    pub async fn query_decimals_of_erc20(&self, token_name: &str) -> Result<u8> {
        unimplemented!()
        // let token_addr = self
        //     .token_registry
        //     .get_token_address(token_name.to_string())
        //     .call()
        //     .await?;
        // self.query_decimals_of_erc20_address(token_addr).await
    }

    pub async fn query_decimals_of_erc20_address(&self, token_addr: Address) -> Result<u8> {
        unimplemented!()
        // let erc20 = ERC20::new(token_addr, self.client.clone());
        // let decimals = erc20.decimals().call().await?;
        // Ok(decimals)
    }

    pub async fn query_token_name(&self, token_addr: Address) -> Result<String> {
        unimplemented!()
        // let name = self
        //     .token_registry
        //     .get_token_name_of_address(token_addr)
        //     .call()
        //     .await?;
        // Ok(name)
    }

    pub async fn query_relayer_rand_hash(&self, relayer: Address) -> Result<Fr> {
        unimplemented!()
        // let rand_hash = self.relayer_handler.get_rand_hash(relayer).call().await?;
        // bytes32_to_fr(&rand_hash)
    }

    pub async fn query_user_extension_for_command(
        &self,
        wallet_salt: &WalletSalt,
        command: &str,
    ) -> Result<Address> {
        unimplemented!()
        // let wallet_addr = self.get_wallet_addr_from_salt(&wallet_salt.0).await?;
        // let extension_addr = self
        //     .extension_handler
        //     .get_extension_for_command(wallet_addr, command.to_string())
        //     .call()
        //     .await?;
        // Ok(extension_addr)
    }

    pub async fn query_subject_templates_of_extension(
        &self,
        extension_addr: Address,
    ) -> Result<Vec<Vec<String>>> {
        unimplemented!()
        // let templates = self
        //     .extension_handler
        //     .get_subject_templates_of_extension(extension_addr)
        //     .call()
        //     .await?;
        // Ok(templates)
    }

    pub async fn get_wallet_addr_from_salt(&self, wallet_salt: &Fr) -> Result<String> {
        // let wallet_addr = self
        //     .account_handler
        //     .get_wallet_of_salt(fr_to_bytes32(wallet_salt)?)
        //     .call()
        //     .await?;
        // Ok(wallet_addr)
        let client = reqwest::Client::new();
        let salt_32 = fr_to_bytes32(wallet_salt).unwrap();
        info!(LOG, "salt_32 ");
        // Todo
        let res = client
            .post(format!(
                "{}/get-wallet-address",
                CHAIN_SDK_PROXY_SERVER.get().unwrap()
            ))
            .json(&json!({
                "wallet_salt": salt_32
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let addr = res.json::<GetWalletRes>().await;
        println!("get wallet address response raw {:?}", addr);
        Ok(addr.unwrap().address)
    }

    pub async fn query_rand_hash_of_relayer(&self, relayer: Address) -> Result<Fr> {
        unimplemented!()
        // let rand_hash = self.relayer_handler.get_rand_hash(relayer).call().await?;
        // bytes32_to_fr(&rand_hash)
    }

    // pub async fn query_ak_commit_and_relayer_of_wallet_salt(
    //     &self,
    //     wallet_salt: &WalletSalt,
    // ) -> Result<(Vec<Fr>, Vec<Address>)> {
    //     let events: Vec<(email_wallet_events::AccountCreatedFilter, LogMeta)> = self
    //         .account_handler
    //         .event_for_name::<email_wallet_events::AccountCreatedFilter>("AccountCreated")?
    //         .from_block(0)
    //         .topic2(H256::from(fr_to_bytes32(&wallet_salt.0)?))
    //         .query_with_meta()
    //         .await?;
    //     let mut account_key_commits = vec![];
    //     let mut relayers = vec![];
    //     for (created, log_meta) in events {
    //         let account_key_commit = bytes32_to_fr(&created.account_key_commit)?;
    //         account_key_commits.push(account_key_commit);
    //         let tx_hash = log_meta.transaction_hash;
    //         let tx = self.client.get_transaction(tx_hash).await?;
    //         if let Some(tx) = tx {
    //             let relayer = tx.from;
    //             relayers.push(relayer);
    //         }
    //     }
    //     Ok((account_key_commits, relayers))
    // }

    pub async fn query_unclaimed_fund(&self, id: U256) -> Result<UnclaimedFund> {
        unimplemented!()
        // let unclaimed_fund = self.unclaims_handler.get_unclaimed_fund(id).await?;
        // Ok(unclaimed_fund)
    }

    pub async fn query_unclaimed_state(&self, id: U256) -> Result<UnclaimedState> {
        unimplemented!()
        // let unclaimed_state = self.unclaims_handler.get_unclaimed_state(id).await?;
        // Ok(unclaimed_state)
    }

    #[named]
    pub async fn get_unclaim_id_from_tx_hash(&self, tx_hash: &str, is_fund: bool) -> Result<U256> {
        unimplemented!()
        // let receipt: TransactionReceipt = self
        //     .client
        //     .get_transaction_receipt(H256::from_str(tx_hash)?)
        //     .await?
        //     .ok_or(anyhow!("No receipt"))?;
        // info!(LOG, "receipt {:?}", receipt; "func" => function_name!());
        //
        // for log in receipt.logs.into_iter() {
        //     info!(LOG, "log {:?}", log; "func" => function_name!());
        //     if let Ok(decoded) = EmailWalletEventsEvents::decode_log(&RawLog::from(log)) {
        //         info!(LOG, "decoded {:?}", decoded; "func" => function_name!());
        //         match decoded {
        //             EmailWalletEventsEvents::UnclaimedFundRegisteredFilter(event) => {
        //                 if !is_fund {
        //                     return Err(anyhow!(
        //                         "the transaction does not register an unclaimed fund"
        //                     ));
        //                 }
        //                 return Ok(event.id);
        //             }
        //             EmailWalletEventsEvents::UnclaimedStateRegisteredFilter(event) => {
        //                 if is_fund {
        //                     return Err(anyhow!(
        //                         "the transaction does not register an unclaimed state"
        //                     ));
        //                 }
        //                 return Ok(event.id);
        //             }
        //             _ => {
        //                 continue;
        //             }
        //         }
        //     }
        // }
        // Err(anyhow!(
        //     "the transaction registers neither an unclaim fund nor state"
        // ))
    }

    pub async fn validate_email_op(&self, email_op: EmailOp) -> Result<()> {
        unimplemented!()
        // let call = self.core.validate_email_op(email_op);
        // call.call().await?;
        // Ok(())
    }

    pub async fn stream_unclaim_fund_registration<
        F: FnMut(email_wallet_events::UnclaimedFundRegisteredFilter, LogMeta) -> Result<()>,
    >(
        &self,
        from_block: U64,
        mut f: F,
    ) -> Result<U64> {
        unimplemented!()
        // let ev = self
        //     .unclaims_handler
        //     .event_for_name::<email_wallet_events::UnclaimedFundRegisteredFilter>(
        //         "UnclaimedFundRegistered",
        //     )?
        //     .from_block(from_block);
        // let mut stream = ev.stream_with_meta().await?;
        // let mut last_block = from_block;
        // while let Some(Ok((event, meta))) = stream.next().await {
        //     last_block = meta.block_number;
        //     f(event, meta)?;
        // }
        // Ok(last_block)
    }

    pub async fn stream_unclaim_state_registration<
        F: FnMut(email_wallet_events::UnclaimedStateRegisteredFilter, LogMeta) -> Result<()>,
    >(
        &self,
        from_block: U64,
        mut f: F,
    ) -> Result<U64> {
        unimplemented!()
        // let ev = self
        //     .unclaims_handler
        //     .event_for_name::<email_wallet_events::UnclaimedStateRegisteredFilter>(
        //         "UnclaimedStateRegistered",
        //     )?
        //     .from_block(from_block);
        // let mut stream = ev.stream_with_meta().await?;
        // let mut last_block = from_block;
        // while let Some(Ok((event, meta))) = stream.next().await {
        //     last_block = meta.block_number;
        //     f(event, meta)?;
        // }
        // Ok(last_block)
    }

    pub(crate) async fn check_if_point_registered(&self, point: Point) -> Result<bool> {
        unimplemented!()
        // let Point { x, y } = point;
        // let x = hex2field(&x)?;
        // let y = hex2field(&y)?;
        // let x = U256::from_little_endian(&x.to_bytes());
        // let y = U256::from_little_endian(&y.to_bytes());
        // let res = self
        //     .account_handler
        //     .pointer_of_psi_point(get_psi_point_bytes(x, y))
        //     .call()
        //     .await?;
        // let res = U256::from_little_endian(&res);
        // Ok(res == U256::zero())
    }

    pub(crate) async fn check_if_account_initialized_by_account_key(
        &self,
        email_addr: &str,
        account_key: &str,
    ) -> Result<bool> {
        unimplemented!()
        // let account_key = AccountKey(hex2field(account_key)?);
        // let padded_email_addr = PaddedEmailAddr::from_email_addr(email_addr);
        // let relayer_rand = RelayerRand(hex2field(RELAYER_RAND.get().unwrap())?);
        // let account_key_commitment =
        //     account_key.to_commitment(&padded_email_addr, &relayer_rand.hash()?)?;
        //
        // let account_key_info = self
        //     .account_handler
        //     .info_of_account_key_commit(Fr::to_bytes(&account_key_commitment))
        //     .call()
        //     .await?;
        //
        // Ok(account_key_info.1)
    }

    pub(crate) async fn check_if_account_initialized_by_point(&self, point: Point) -> Result<bool> {
        unimplemented!()
        // let Point { x, y } = point;
        // let x = hex2field(&x)?;
        // let y = hex2field(&y)?;
        // let x = U256::from_little_endian(&x.to_bytes());
        // let y = U256::from_little_endian(&y.to_bytes());
        // let pointer = self
        //     .account_handler
        //     .pointer_of_psi_point(get_psi_point_bytes(x, y))
        //     .call()
        //     .await?;
        // let account_key_commitment = self
        //     .account_handler
        //     .account_key_commit_of_pointer(pointer)
        //     .call()
        //     .await?;
        // let account_key_info = self
        //     .account_handler
        //     .info_of_account_key_commit(account_key_commitment)
        //     .call()
        //     .await?;
        //
        // Ok(account_key_info.1)
    }

    #[named]
    pub(crate) async fn check_if_dkim_public_key_hash_valid(
        &self,
        domain_name: ::std::string::String,
        public_key_hash: [u8; 32],
    ) -> Result<bool> {
        unimplemented!()
        // let is_valid = self
        //     .ecdsa_owned_dkim_registry
        //     .is_dkim_public_key_hash_valid(domain_name.clone(), public_key_hash)
        //     .call()
        //     .await?;
        // info!(
        //     LOG,
        //     "{:?} for {} is already registered: {}", public_key_hash, domain_name, is_valid; "func" => function_name!()
        // );
        // Ok(is_valid)
    }
}

#[cfg(test)]
mod test {
    use dotenv::dotenv;
    use email_wallet_utils::converters::field2hex;
    use serde_json::json;
    use std::env;

    use crate::chain::AccountCreationInput;
    use crate::core::{derive_relayer_rand, generate_account_creation_input, generate_proof};
    use crate::{
        u256_to_bytes32, AccountCreationResponse, CHAIN_SDK_PROXY_SERVER, CIRCUITS_DIR_PATH,
        INPUT_FILES_DIR,
    };

    #[tokio::test]
    async fn create_account() {
        dotenv().ok();
        INPUT_FILES_DIR
            .set(env::var("INPUT_FILES_DIR_PATH").unwrap())
            .unwrap();
        CIRCUITS_DIR_PATH
            .set(env::var("CIRCUITS_DIR_PATH").unwrap().into())
            .unwrap();
        let relayer_rand = derive_relayer_rand(env::var("PRIVATE_KEY").unwrap().as_str()).unwrap();
        let input = generate_account_creation_input(
            CIRCUITS_DIR_PATH.get().unwrap(),
            "hduoc2003@gmail.com",
            field2hex(&relayer_rand.0).as_str(),
            "0x2413b1824352a7febd833a75fc54a2eb910d9aeb71fd653e6bc703bab01d857e",
        )
        .await
        .unwrap();

        let (proof, pub_signals) =
            generate_proof(&input, "account_creation", "http://10.20.21.121:8080")
                .await
                .unwrap();

        let data = AccountCreationInput {
            email_addr_pointer: pub_signals[1],
            account_key_commit: pub_signals[2],
            wallet_salt: pub_signals[3],
            psi_point: [pub_signals[4], pub_signals[5]],
            proof,
        };
        let client = reqwest::Client::new();
        let psi_point: Vec<String> = data.psi_point.iter().map(|x| x.to_string()).collect();
        let res = client
            .post(format!(
                "{}/create-account",
                CHAIN_SDK_PROXY_SERVER.get().unwrap()
            ))
            .json(&json!({
                "wallet_salt_byte32": u256_to_bytes32(&data.wallet_salt),
                "proof": {
                    "relayer_hash": pub_signals[0].to_string(),
                "email_addr_pointer": data.email_addr_pointer.to_string(),
                "account_key_commit": data.account_key_commit.to_string(),
                "wallet_salt": data.wallet_salt.to_string(),
                "psi_point": psi_point,
                "proof": data.proof
                }
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let res_json = res.json::<AccountCreationResponse>().await.unwrap();
        print!("{:?}", res_json);
    }
}
