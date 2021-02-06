use crate::state::State;
use cosmwasm_std::{Binary, CanonicalAddr, HumanAddr};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub drand_step2_contract_address: CanonicalAddr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Get the config state
    Config {},
    /// Get the last randomness
    LatestDrand {},
    /// Get a specific randomnesvs
    GetRandomness { round: u64 },
    /// Not used to be call directly
    Verify {
        signature: Binary,
        msg_g2: Binary,
        worker: CanonicalAddr,
        round: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// Add random from this
    Drand {
        round: u64,
        previous_signature: Binary,
        signature: Binary,
    },
    /// Not used to be call directly
    VerifyCallBack {
        round: u64,
        randomness: Binary,
        valid: bool,
        worker: CanonicalAddr,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct GetRandomResponse {
    pub randomness: Binary,
    pub worker: CanonicalAddr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LatestRandomResponse {
    pub round: u64,
    pub randomness: Binary,
    pub worker: CanonicalAddr,
}

// We define a custom struct for each query response
pub type ConfigResponse = State;
