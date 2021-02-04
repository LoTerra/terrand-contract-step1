use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, HandleResponse, InitResponse, MessageInfo, Order, HumanAddr, WasmQuery, CosmosMsg};

use crate::error::ContractError;
use crate::msg::{ConfigResponse, GetRandomResponse, HandleMsg, InitMsg, LatestRandomResponse, QueryMsg, VerifyResponse};
use crate::state::{
    beacons_storage, beacons_storage_read, config, config_read, BeaconInfoState, State,
};
use paired::bls12_381::{G2Affine, G1Affine, G1Compressed, G2};
use groupy::{EncodedPoint, CurveProjective, GroupDecodingError, CurveAffine};
use sha2::{Sha256, Digest};
use paired::{HashToCurve, ExpandMsgXmd};
use std::fmt;
use schemars::_serde_json::Value;


use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
//use schemars::_serde_json::value::Serializer;

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// use drand_verify::{derive_randomness, g1_from_variable, verify};

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
pub fn init(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InitMsg,
) -> Result<InitResponse, ContractError> {
    let state = State {
        drand_public_key: vec![
            134, 143, 0, 94, 184, 230, 228, 202, 10, 71, 200, 167, 124, 234, 165, 48, 154, 71, 151,
            138, 124, 113, 188, 92, 206, 150, 54, 107, 93, 122, 86, 153, 55, 197, 41, 238, 218,
            102, 199, 41, 55, 132, 169, 64, 40, 1, 175, 49,
        ]
        .into(),
        drand_step2_contract_address: msg.drand_step2_contract_address
    };
    config(deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: HandleMsg,
) -> Result<HandleResponse, ContractError> {
    match msg {
        HandleMsg::Drand {
            round,
            previous_signature,
            signature,
        } => add_random(deps, info, round, previous_signature, signature),
    }
}

#[derive(Debug)]
pub enum InvalidPoint {
    InvalidLength { expected: usize, actual: usize },
    DecodingError { msg: String },
}
impl From<GroupDecodingError> for InvalidPoint {
    fn from(source: GroupDecodingError) -> Self {
        InvalidPoint::DecodingError {
            msg: format!("{:?}", source),
        }
    }
}

fn g1_from_fixed(data: [u8; 48]) -> Result<G1Affine, InvalidPoint> {
    // Workaround for https://github.com/filecoin-project/paired/pull/23
    let mut compressed = G1Compressed::empty();
    compressed.as_mut().copy_from_slice(&data);
    Ok(compressed.into_affine()?)
}

fn g1_from_variable(data: &[u8]) -> Result<G1Affine, InvalidPoint> {
    if data.len() != G1Compressed::size() {
        return Err(InvalidPoint::InvalidLength {
            expected: G1Compressed::size(),
            actual: data.len(),
        });
    }

    let mut buf = [0u8; 48];
    buf[..].clone_from_slice(&data[..]);
    g1_from_fixed(buf)
}

fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}

fn message(current_round: u64, prev_sig: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(prev_sig);
    hasher.update(round_to_bytes(current_round));
    hasher.finalize().to_vec()
}
fn msg_to_curve(msg: &[u8]) -> G2Affine {
    let g = <G2 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DOMAIN);
    g.into_affine()
}
fn verify_step1(round: u64, previous_signature: &[u8]) -> G2Affine {
    let msg = message(round, previous_signature);
    msg_to_curve(&msg)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
struct Verify {
    signature: Binary,
    msg_g2: Binary
}
pub fn add_random(
    deps: DepsMut,
    info: MessageInfo,
    round: u64,
    previous_signature: Binary,
    signature: Binary,
) -> Result<HandleResponse, ContractError> {
    let state = config(deps.storage).load()?;

    // Handle sender is not sending funds
    if !info.sent_funds.is_empty() {
        return Err(ContractError::DoNotSendFunds("add_random".to_string()));
    }
    // Handle sender are not adding existing rounds
    let already_added = beacons_storage(deps.storage)
        .may_load(&round.to_be_bytes())
        .unwrap();
    if already_added.is_some() {
        return Err(ContractError::DrandRoundAlreadyAdded(round.to_string()));
    }

    // verify random with drand-verify
    //let pk = g1_from_variable(&state.drand_public_key).unwrap();
    let verify_step1 = verify_step1(round, &previous_signature);
    //println!("{:?}", pk.into_compressed());
    //let x = verify_step1.into_compressed();

    let contractAddress = deps.api.human_address(&state.drand_step2_contract_address)?;


    let msg = query_verify(deps.as_ref(), signature, Binary::from(verify_step1.into_compressed().as_ref()))?;

    println!("{:?}", to_binary(&msg)?);
    /*let msg: CosmosMsg = Verify{
        signature,
        msg_g2: Binary::from(verify_step1.into_compressed().as_ref())
    }.into();*/
    println!("{:?}", msg);
    let msg = to_binary(&msg).unwrap();
    let x:WasmQuery = deps.querier.query_wasm_smart(contractAddress, &msg).unwrap();
    //let f =  Verify::serialize( &msg, Verify);
    //let f = Serializer::serialize_struct(msg, "msg", 0);


    //let contractAddress = deps.api.human_address(&state.drand_step2_contract_address)?;
    //let res = deps.querier.query_wasm_smart(contractAddress, &msg)?;
    //let res = deps.querier.query_wasm_smart(contractAddress, &msg)?;

   //let valid = verify(&pk, round, &previous_signature, &signature).unwrap_or(false);

    //save beacon for oracle usage
    /*beacons_storage(deps.storage).save(
        &round.to_be_bytes(),
        &BeaconInfoState {
            round,
            randomness: randomness.into(),
            worker: deps.api.canonical_address(&info.sender).unwrap(),
        },
    )?;*/

    Ok(HandleResponse::default())
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let response = match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
        QueryMsg::GetRandomness { round } => to_binary(&query_get(deps, round)?)?,
        QueryMsg::LatestDrand {} => to_binary(&query_latest(deps)?)?,
        QueryMsg::Verify {signature, msg_g2} => to_binary(&query_verify(deps, signature, msg_g2)?)?
    };
    Ok(response)
}
fn query_verify(deps: Deps, signature: Binary, msg_g2: Binary) -> Result<VerifyResponse, ContractError>{
    Ok(VerifyResponse{
        signature,
        msg_g2
    }.into())
}

fn query_config(deps: Deps) -> Result<ConfigResponse, ContractError> {
    let state = config_read(deps.storage).load()?;
    Ok(state)
}
// Query beacon by round
fn query_get(deps: Deps, round: u64) -> Result<GetRandomResponse, ContractError> {
    let beacons = beacons_storage_read(deps.storage);
    let beacon = beacons.load(&round.to_be_bytes()).unwrap();

    Ok(GetRandomResponse {
        randomness: beacon.randomness,
        worker: beacon.worker,
    })
}
// Query latest beacon
fn query_latest(deps: Deps) -> Result<LatestRandomResponse, ContractError> {
    let store = beacons_storage_read(deps.storage);
    let mut iter = store.range(None, None, Order::Descending);
    let (key, value) = iter.next().ok_or(ContractError::NoBeacon {})??;

    Ok(LatestRandomResponse {
        round: u64::from_be_bytes(Binary(key).to_array()?),
        randomness: value.randomness,
        worker: value.worker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, Api, HumanAddr, CanonicalAddr};
    use hex;



    #[test]
    fn add_random_test() {
        let mut deps = mock_dependencies(&[]);

        let contract_address = deps.api.canonical_address(&HumanAddr::from("terra1wct6".to_string())).unwrap();
        let info = mock_info(HumanAddr::from("creator"), &[]);
        let init_msg = InitMsg { drand_step2_contract_address: contract_address };
        init(deps.as_mut(), mock_env(), info, init_msg).unwrap();


        let prev_sign = hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into();
        let sign = hex::decode("a75c1b05446c28e9babb078b5e4887761a416b52a2f484bcb388be085236edacc72c69347cb533da81e01fe26f1be34708855b48171280c6660e2eb736abe214740ce696042879f01ba5613808a041b54a80a43dadb5a6be8ed580be7e3f546e").unwrap().into();
        let round = 545216;
        let msg = HandleMsg::Drand {
            round,
            previous_signature: prev_sign,
            signature: sign,
        };

        // Test do not send funds with add_random
        let info = mock_info("worker", &coins(1000, "earth"));
        let res = handle(deps.as_mut(), mock_env(), info, msg.clone());
        match res {
            Err(ContractError::DoNotSendFunds(msg)) => {
                assert_eq!("add_random", msg);
            }
            _ => panic!("Unexpected error"),
        }

        // Test success
        let info = mock_info("worker", &[]);
        let res = handle(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();
        assert_eq!(0, res.messages.len());
        // Test if random added success
        let (_key, beacon) = beacons_storage_read(deps.as_ref().storage)
            .range(None, None, Order::Descending)
            .next()
            .ok_or(ContractError::NoBeacon {})
            .unwrap()
            .unwrap();
        assert_eq!(
            "14e7d833da2adf2dddd9ccfc2b002d397fe0f18d09c32626935184b858dafe66",
            hex::encode(beacon.randomness.to_vec())
        );
        assert_eq!(545216, beacon.round);
        assert_eq!(
            deps.api
                .canonical_address(&HumanAddr("worker".to_string()))
                .unwrap(),
            beacon.worker
        );

        // Test query by round
        let round = query_get(deps.as_ref(), 545216).unwrap();
        assert_eq!(
            deps.api
                .canonical_address(&HumanAddr("worker".to_string()))
                .unwrap(),
            round.worker
        );
        assert_eq!(
            "14e7d833da2adf2dddd9ccfc2b002d397fe0f18d09c32626935184b858dafe66",
            hex::encode(round.randomness.to_vec())
        );

        // Test adding round already added
        let info = mock_info("worker", &[]);
        let res = handle(deps.as_mut(), mock_env(), info, msg);
        match res {
            Err(ContractError::DrandRoundAlreadyAdded(msg)) => {
                assert_eq!("545216", msg)
            }
            _ => panic!("Unexpected error"),
        }

        // add new round
        let prev_sign = hex::decode("ae5787851eb270eb0d167d5cb7c7a1494b640c4e01f7aed0aa556cd9f92f0e4f6bf7cedcb6cb36ae96de380fc04945bd19928f57a6e1d878b862c7a8d9e6bd3f3def0b3ff337eeeae18263fee2c6165c7674af864dd48a78485f831015088f20").unwrap().into();
        let sign = hex::decode("8fd46b28c04a574be0845b8ddd2c86fc12a4203896668e0479f71f73ffa5504a69bd0240730b6c61df2ca240406d41300f723f934a5908a19334312ae6695d0adf014ad4b6b990507b16220f19f3b9246a092a24f571baecd15519db0906877c").unwrap().into();
        let round = 550625;
        let msg = HandleMsg::Drand {
            round,
            previous_signature: prev_sign,
            signature: sign,
        };
        let info = mock_info("worker1", &[]);
        let _res = handle(deps.as_mut(), mock_env(), info, msg);
        // Test query latest randomness
        let latest_round = query_latest(deps.as_ref()).unwrap();
        assert_eq!(
            deps.api
                .canonical_address(&HumanAddr("worker1".to_string()))
                .unwrap(),
            latest_round.worker
        );
        assert_eq!(
            "85c3054b7bef980fbcbce58fb55315f249ba3ca370f392d185afd58a4605c4a4",
            hex::encode(latest_round.randomness.to_vec())
        );
        assert_eq!(550625, latest_round.round);

        // Test adding new round but with invalid signature
        let prev_sign = hex::decode("aeed0265092cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into();
        let sign = hex::decode("a75c1b05446c28e9babb078b5e4887761a416b52a2f484bcb388be085236edacc72c69347cb533da81e01fe26f1be34708855b48171280c6660e2eb736abe214740ce696042879f01ba5613808a041b54a80a43dadb5a6be8ed580be7e3f546e").unwrap().into();
        let round = 545226;
        let msg = HandleMsg::Drand {
            round,
            previous_signature: prev_sign,
            signature: sign,
        };
        let info = mock_info("worker", &[]);
        let res = handle(deps.as_mut(), mock_env(), info, msg.clone());
        match res {
            Err(ContractError::InvalidSignature {}) => {}
            _ => panic!("Unexpected error"),
        }
    }
}
