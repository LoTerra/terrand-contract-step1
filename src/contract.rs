use cosmwasm_std::{to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Order, Querier, StdResult, Storage, StdError, WasmMsg, HumanAddr, WasmQuery, LogAttribute, CosmosMsg};

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, GetRandomResponse, HandleMsg, InitMsg, LatestRandomResponse, QueryMsg
};
use crate::state::{
    beacons_storage, beacons_storage_read, config, config_read, State,
};
use groupy::{CurveAffine, CurveProjective, GroupDecodingError};
use paired::bls12_381::{G1Affine, G1Compressed, G2Affine, G2};
use paired::{ExpandMsgXmd, HashToCurve};
use sha2::{Digest, Sha256};


use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// use drand_verify::{derive_randomness, g1_from_variable, verify};

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        drand_public_key: vec![
            134, 143, 0, 94, 184, 230, 228, 202, 10, 71, 200, 167, 124, 234, 165, 48, 154, 71, 151,
            138, 124, 113, 188, 92, 206, 150, 54, 107, 93, 122, 86, 153, 55, 197, 41, 238, 218,
            102, 199, 41, 55, 132, 169, 64, 40, 1, 175, 49,
        ]
        .into(),
        drand_step2_contract_address: msg.drand_step2_contract_address,
    };
    config(&mut deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) ->  StdResult<HandleResponse> {
    match msg {
        HandleMsg::Drand {
            round,
            previous_signature,
            signature,
        } => add_random(deps, env, round, previous_signature, signature),
    }
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

fn encode_msg(msg: QueryMsg) -> StdResult<CosmosMsg> {
    Ok(WasmMsg::Execute {
        contract_addr: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6"),
        msg: to_binary(&msg)?,
        send: vec![]
    }.into())
}

pub fn add_random<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    round: u64,
    previous_signature: Binary,
    signature: Binary,
) -> StdResult<HandleResponse>  {
    let state = config(&mut deps.storage).load()?;

    // Handle sender is not sending funds

    if !env.message.sent_funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with add_random"));
    }
    // Handle sender are not adding existing rounds
    let already_added = beacons_storage(&mut deps.storage)
        .may_load(&round.to_be_bytes())
        .unwrap();
    if already_added.is_some() {
        return Err(StdError::generic_err("Round already added"));
    }

    // verify random with drand-verify
    //let pk = g1_from_variable(&state.drand_public_key).unwrap();
    let verify_step1 = verify_step1(round, &previous_signature.as_slice());
    println!("{:?}", Binary::from(verify_step1.into_compressed().as_ref()));
    /*let e = hex::encode(verify_step1.into_compressed());
    let decode = hex::decode(e.clone()).unwrap();
    println!("{:?}",e);
    println!("{:?}", verify_step1.into_compressed());
    //let x = verify_step1.into_compressed();
    println!("{:?}", Binary::from(verify_step1.into_compressed().as_ref()));
    println!("{:?}", Binary::from(decode));*/
    //deps.api.

    /*let contract_address = deps
        .api.human_address(&state.drand_step2_contract_address)?;*/
    let msg = QueryMsg::Verify { signature, msg_g2: Binary::from(verify_step1.into_compressed().as_ref()) };
    println!("{:?}", msg);
    println!("{:?}", verify_step1.into_compressed().as_ref());
    let res = encode_msg(msg)?;

   /* let msg = query_verify(
        deps,
        signature,
        Binary::from(verify_step1.into_compressed().as_ref()),
    )?;*/

    /*let msg: CosmosMsg = Verify{
        signature,
        msg_g2: Binary::from(verify_step1.into_compressed().as_ref())
    }.into();*/


    //println!("{:?}", msg);
    //let msg: Binary = to_binary(&msg).unwrap();



    //WasmQuery::Smart { contract_addr: HumanAddr("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6".to_string()), msg};
    /*WasmMsg::Execute {
        contract_addr: HumanAddr("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6".to_string()),
        msg,
        send: vec![]
    };*/


    //WasmQuery::Smart { contract_addr: Default::default(), msg }
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
    let data_msg = format!("data: {:?}",res).into_bytes();
    Ok(HandleResponse {
        messages: vec![res.into()],
        data: Some(data_msg.into()),
        log: vec![LogAttribute {
            key: "status".to_string(),
            value: "ok".to_string(),
        }],
    })

}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
        QueryMsg::GetRandomness { round } => to_binary(&query_get(deps, round)?)?,
        QueryMsg::LatestDrand {} => to_binary(&query_latest(deps)?)?,
        QueryMsg::Verify { signature, msg_g2 } => {
           to_binary(&query_verify(deps, signature, msg_g2)?)?
        }
    };
    Ok(response)
}
fn query_verify<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    signature: Binary,
    msg_g2: Binary,
) -> StdResult<ConfigResponse> {
    let state = config_read(&deps.storage).load()?;
    Ok(state)
}

fn query_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<ConfigResponse> {
    let state = config_read(&deps.storage).load()?;
    Ok(state)
}
// Query beacon by round
fn query_get<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    round: u64,
) -> StdResult<GetRandomResponse> {
    let beacons = beacons_storage_read(&deps.storage);
    let beacon = beacons.load(&round.to_be_bytes()).unwrap();

    Ok(GetRandomResponse {
        randomness: beacon.randomness,
        worker: beacon.worker,
    })
}
// Query latest beacon
fn query_latest<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<LatestRandomResponse> {
    let store = beacons_storage_read(&deps.storage);
    let mut iter = store.range(None, None, Order::Descending);
    let (_, value) = iter.next().ok_or(ContractError::NoBeacon {}).unwrap().unwrap();

    Ok(LatestRandomResponse {
        round: value.round,
        randomness: value.randomness,
        worker: value.worker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{ Api, HumanAddr};
    use hex;

    #[test]
    fn add_random_test() {
        let mut deps = mock_dependencies(44, &[]);

        //let x = deps.api.canonical_address();


        let contract_address = deps
            .api
            .canonical_address(&HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6"))
            .unwrap();
        //println!("{}", HumanAddr("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6".to_string()));
        let init_msg = InitMsg {
            drand_step2_contract_address: contract_address,
        };
        init(&mut deps, mock_env("terra", &[]),  init_msg).unwrap();

        //let prev_sign = hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into();
        //let sign = hex::decode("a75c1b05446c28e9babb078b5e4887761a416b52a2f484bcb388be085236edacc72c69347cb533da81e01fe26f1be34708855b48171280c6660e2eb736abe214740ce696042879f01ba5613808a041b54a80a43dadb5a6be8ed580be7e3f546e").unwrap().into();
        let round = 545216;
        let prev_sign = Binary::from_base64("gIO9RFHWCjKIq9lQrERpO1hEjdbroVuFuKRtWJuuPf+1HIYBHJkTIJCAwjf+ycA5BA0pHjnYsgSfqD5nsMpxvhPOArAknwuAYXFQOx+NZxoxzXOr+cdndFOl953+sXii").unwrap();
        let sign = Binary::from_base64("imgTaZQ/2cjJn+SG+i8FlqBIgQ8kuA1Izbg5BVh0pn/rbKAaysP5GSN8cjupq6kMC6JXBSpo61MDITzSNjqrEcJ1BPf4Qer2Hh2uOcR9+LHL/SFn6w9L/6Bv3PR4mMAE").unwrap();
        let msg = HandleMsg::Drand {
            round,
            previous_signature: prev_sign,
            signature: sign,
        };
        let res = handle(&mut deps, mock_env("address", &[]),  msg.clone());
        println!("{:?}", res);
/*
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

 */
    }
}
