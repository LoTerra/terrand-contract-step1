use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, CanonicalAddr, Storage};
use cosmwasm_storage::{
    bucket, bucket_read, singleton, singleton_read, Bucket, ReadonlyBucket, ReadonlySingleton,
    Singleton,
};

pub static CONFIG_KEY: &[u8] = b"config";
const BEACONS_KEY: &[u8] = b"beacons";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub drand_public_key: Binary,
    pub drand_step2_contract_address: CanonicalAddr,
    pub x: bool,
}

pub fn config<S: Storage>(storage: &mut S) -> Singleton<S, State> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, State> {
    singleton_read(storage, CONFIG_KEY)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BeaconInfoState {
    pub round: u64,
    pub randomness: Binary,
    pub worker: CanonicalAddr,
}

pub fn beacons_storage<T: Storage>(storage: &mut T) -> Bucket<T, BeaconInfoState> {
    bucket(BEACONS_KEY, storage)
}
pub fn beacons_storage_read<T: Storage>(storage: &T) -> ReadonlyBucket<T, BeaconInfoState> {
    bucket_read(BEACONS_KEY, storage)
}
