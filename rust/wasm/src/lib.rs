use libsignal_core::ServiceId;
use wasm_bindgen::prelude::*;
use zkgroup::groups::{GroupMasterKey, GroupSecretParams};

#[wasm_bindgen]
pub fn group_secret_params_derive_from_master_key(key_bytes: &mut [u8]) -> JsValue {
    let master_key = GroupMasterKey::new(
        key_bytes
            .try_into()
            .expect("key bytes must be 32 bytes long"),
    );
    let params = GroupSecretParams::derive_from_master_key(master_key);

    return serde_wasm_bindgen::to_value(&params).unwrap();
}

#[wasm_bindgen]
pub fn group_secret_params_encrypt_service_id(val: JsValue, service_string: String) -> JsValue {
    let params: GroupSecretParams = serde_wasm_bindgen::from_value(val).unwrap();
    let service_id = ServiceId::parse_from_service_id_string(&service_string).unwrap();

    let public = params.encrypt_service_id(service_id);

    return serde_wasm_bindgen::to_value(&public).unwrap();
}

// #[wasm_bindgen]
// pub fn generate_key() -> JsValue {}
