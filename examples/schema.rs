use std::env::current_dir;
use std::fs::create_dir_all;

use cosmwasm_schema::{export_schema, export_schema_with_title, remove_schemas, schema_for};

use drand_lottery::msg::{
    ConfigResponse, GetRandomResponse, HandleMsg, InitMsg, LatestRandomResponse, VerifyResponse
};
use drand_lottery::state::State;

fn main() {
    let mut out_dir = current_dir().unwrap();
    out_dir.push("schema");
    create_dir_all(&out_dir).unwrap();
    remove_schemas(&out_dir).unwrap();
    export_schema(&schema_for!(InitMsg), &out_dir);
    export_schema(&schema_for!(HandleMsg), &out_dir);
    export_schema(&schema_for!(State), &out_dir);
    export_schema_with_title(&mut schema_for!(ConfigResponse), &out_dir, "ConfigResponse");
    export_schema_with_title(
        &mut schema_for!(GetRandomResponse),
        &out_dir,
        "GetRandomResponse",
    );
    export_schema_with_title(
        &mut schema_for!(LatestRandomResponse),
        &out_dir,
        "LatestRandomResponse",
    );
    export_schema_with_title(
        &mut schema_for!(VerifyResponse),
        &out_dir,
        "VerifyResponse",
    );
}
