use cosmwasm_std::{
    to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr, InitResponse,
    LogAttribute, Order, Querier, StdError, StdResult, Storage, WasmMsg,
};

use crate::msg::{
    ConfigResponse, GetRandomResponse, HandleMsg, InitMsg, LatestRandomResponse, QueryMsg,
};
use crate::state::{
    beacons_storage, beacons_storage_read, config, config_read, BeaconInfoState, State,
};
use groupy::{CurveAffine, CurveProjective};
use paired::bls12_381::{G2Affine, G2};
use paired::{ExpandMsgXmd, HashToCurve};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        drand_step2_contract_address: msg.drand_step2_contract_address,
    };
    config(&mut deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::Drand {
            round,
            previous_signature,
            signature,
        } => add_random(deps, env, round, previous_signature, signature),
        HandleMsg::VerifyCallBack {
            round,
            randomness,
            valid,
            worker,
        } => verify_call_back(deps, env, round, randomness, valid, worker),
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

fn encode_msg(msg: QueryMsg, address: HumanAddr) -> StdResult<CosmosMsg> {
    Ok(WasmMsg::Execute {
        contract_addr: address,
        msg: to_binary(&msg)?,
        send: vec![],
    }
    .into())
}

pub fn add_random<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    round: u64,
    previous_signature: Binary,
    signature: Binary,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;
    let contract_address = state.drand_step2_contract_address;
    // Handle sender is not sending funds
    if !env.message.sent_funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with add_random"));
    }

    let verify_step1 = verify_step1(round, &previous_signature.as_slice());
    let msg = QueryMsg::Verify {
        signature,
        msg_g2: Binary::from(verify_step1.into_compressed().as_ref()),
        worker: env.message.sender,
        round,
    };

    let res = encode_msg(msg, contract_address)?;

    Ok(HandleResponse {
        messages: vec![res.into()],
        data: None,
        log: vec![],
    })
}

pub fn verify_call_back<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    round: u64,
    randomness: Binary,
    valid: bool,
    worker: HumanAddr,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;
    let canonical_address = deps.api.canonical_address(&worker)?;
    //env.message.sender
    if env.message.sender != state.drand_step2_contract_address {
        return Err(StdError::Unauthorized { backtrace: None });
    }
    if !valid {
        return Err(StdError::generic_err("The randomness is not valid"));
    }
    // Handle sender are not adding existing rounds
    let already_added = beacons_storage(&mut deps.storage)
        .may_load(&round.to_be_bytes())
        .unwrap();
    if already_added.is_some() {
        return Err(StdError::generic_err("Randomness already added"));
    }
    //save beacon for oracle usage
    beacons_storage(&mut deps.storage).save(
        &round.to_be_bytes(),
        &BeaconInfoState {
            round,
            randomness: randomness.into(),
            worker: canonical_address,
        },
    )?;
    Ok(HandleResponse {
        messages: vec![],
        data: None,
        log: vec![LogAttribute {
            key: "isValidRandomness".to_string(),
            value: "true".to_string(),
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
        QueryMsg::Verify {
            signature: _,
            msg_g2: _,
            worker: _,
            round: _,
        } => to_binary(&query_verify(deps)?)?,
    };
    Ok(response)
}
fn query_verify<S: Storage, A: Api, Q: Querier>(_deps: &Extern<S, A, Q>) -> StdResult<StdError> {
    Err(StdError::Unauthorized { backtrace: None })
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
        worker: deps.api.human_address(&beacon.worker)?,
    })
}
// Query latest beacon
fn query_latest<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<LatestRandomResponse> {
    let store = beacons_storage_read(&deps.storage);
    let mut iter = store.range(None, None, Order::Descending);
    let (_, value) = iter
        .next()
        .ok_or(StdError::NotFound {
            kind: "No beacon".to_string(),
            backtrace: None,
        })
        .unwrap()
        .unwrap();

    Ok(LatestRandomResponse {
        round: value.round,
        randomness: value.randomness,
        worker: deps.api.human_address(&value.worker)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::HumanAddr;
    use hex;

    mod verify_call_back {
        use super::*;
        use cosmwasm_std::StdError::GenericErr;
        use cosmwasm_std::StdError::Unauthorized;

        #[test]
        fn success() {
            let mut deps = mock_dependencies(44, &[]);
            let contract_address = HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6");
            let init_msg = InitMsg {
                drand_step2_contract_address: contract_address.clone(),
            };
            init(&mut deps, mock_env("terra", &[]), init_msg).unwrap();

            let msg = HandleMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l12345")
            };

            let res = handle(
                &mut deps,
                mock_env("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6", &[]),
                msg.clone(),
            )
            .unwrap();
            let log_res: bool = res.log[0].value.parse().unwrap();
            assert!(log_res);

            // Add other one
            let msg = HandleMsg::VerifyCallBack {
                round: 2234230,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l09876")
            };

            let _res = handle(
                &mut deps,
                mock_env("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6", &[]),
                msg.clone(),
            );

            // get latest round
            let state = query_latest(&mut deps).unwrap();
            assert_eq!(
                HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l12345"),
                state.worker
            );

            // get custom round
            let state = query_get(&mut deps, 2234230).unwrap();
            assert_eq!(
                HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l09876"),
                state.worker
            );
        }

        #[test]
        fn not_valid_randomness() {
            let mut deps = mock_dependencies(44, &[]);
            let contract_address = HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6");
            let init_msg = InitMsg {
                drand_step2_contract_address: contract_address,
            };
            init(&mut deps, mock_env("terra", &[]), init_msg).unwrap();

            let msg = HandleMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: false,
                worker: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6")
            };

            let res = handle(
                &mut deps,
                mock_env("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6", &[]),
                msg.clone(),
            );

            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!("The randomness is not valid", msg)
                }
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn sender_is_not_authorized() {
            let mut deps = mock_dependencies(44, &[]);
            let contract_address = HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6");
            let unauthorized_sender =
                HumanAddr::from("terra1x46rqay4d3cssq8gxxvqz8xt6nwlz4td20k38v");
            let init_msg = InitMsg {
                drand_step2_contract_address: contract_address,
            };
            init(&mut deps, mock_env("terra", &[]), init_msg).unwrap();

            let msg = HandleMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6")
            };

            let res = handle(&mut deps, mock_env(unauthorized_sender, &[]), msg.clone());

            match res {
                Err(Unauthorized { backtrace: None }) => {}
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn handle_adding_randomness_multiple_times_error() {
            let mut deps = mock_dependencies(44, &[]);
            let contract_address = HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6");
            let init_msg = InitMsg {
                drand_step2_contract_address: contract_address,
            };
            init(&mut deps, mock_env("terra", &[]), init_msg).unwrap();

            let msg = HandleMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6")
            };

            let _res = handle(
                &mut deps,
                mock_env("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6", &[]),
                msg.clone(),
            )
            .unwrap();

            let msg = HandleMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6")
            };

            let res = handle(
                &mut deps,
                mock_env("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6", &[]),
                msg.clone(),
            );

            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!("Randomness already added", msg)
                }
                _ => panic!("Unexpected error"),
            }
        }
    }

    #[test]
    fn add_random_test() {
        let mut deps = mock_dependencies(44, &[]);
        let contract_address = HumanAddr::from("terra1wct66yr5dzg8zh8amhzztzpnut5zx3m5l8qmc6");
        let init_msg = InitMsg {
            drand_step2_contract_address: contract_address,
        };
        init(&mut deps, mock_env("terra", &[]), init_msg).unwrap();
        let round = 545216;
        let prev_sign = Binary::from_base64("gIO9RFHWCjKIq9lQrERpO1hEjdbroVuFuKRtWJuuPf+1HIYBHJkTIJCAwjf+ycA5BA0pHjnYsgSfqD5nsMpxvhPOArAknwuAYXFQOx+NZxoxzXOr+cdndFOl953+sXii").unwrap();
        let sign = Binary::from_base64("imgTaZQ/2cjJn+SG+i8FlqBIgQ8kuA1Izbg5BVh0pn/rbKAaysP5GSN8cjupq6kMC6JXBSpo61MDITzSNjqrEcJ1BPf4Qer2Hh2uOcR9+LHL/SFn6w9L/6Bv3PR4mMAE").unwrap();
        let msg = HandleMsg::Drand {
            round,
            previous_signature: prev_sign,
            signature: sign,
        };
        let res = handle(&mut deps, mock_env("address", &[]), msg.clone()).unwrap();
        assert_eq!(1, res.messages.len());
    }
}
