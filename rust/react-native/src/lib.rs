#![allow(non_snake_case)]
#![feature(fmt_internals)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]

use futures::executor;
use std::borrow::Borrow;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::thread::sleep_ms;
use std::{any, fmt};
use storage::JSISenderKeyStore;

use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
use aes_gcm_siv::aead::AeadMutInPlace;
use aes_gcm_siv::{AeadCore, KeyInit};
use jsi::de::JsiDeserializeError;
use jsi::ser::JsiSerializeError;
use jsi::{
    host_object, AsyncUserHostObject, CallInvoker, FromObject, FromValue, IntoValue,
    JsiArrayBuffer, JsiFn, JsiString, JsiValue, PropName, RuntimeDisplay, RuntimeHandle,
};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress};
use libsignal_protocol::kem::{Key as KemKey, KeyPair as KyberKeyPair, KeyType, Public};
use libsignal_protocol::{
    extract_decryption_error_message_from_serialized_content, group_decrypt, CiphertextMessageType,
    DecryptionErrorMessage, PrivateKey as CurvePrivateKey, PublicKey as CurvePublicKey,
    SenderCertificate, SenderKeyStore, ServerCertificate, Timestamp,
};
use promise::{clone_runtime_handle, make_async, CallbackType, SendableRuntimeHandle};
use serde::de::Error;
use zkgroup::auth::{
    AnyAuthCredentialPresentation, AuthCredentialWithPni, AuthCredentialWithPniResponse,
};
use zkgroup::backups::{
    BackupAuthCredential, BackupAuthCredentialPresentation, BackupAuthCredentialRequest,
    BackupAuthCredentialRequestContext, BackupAuthCredentialResponse, BackupLevel,
};
use zkgroup::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use zkgroup::groups::GroupSecretParams;
use zkgroup::profiles::{ExpiringProfileKeyCredential, ProfileKey};
use zkgroup::receipts::ReceiptCredential;
use zkgroup::{NotarySignatureBytes, ReceiptSerialBytes, ServerPublicParams, ServerSecretParams};

pub const RANDOMNESS_LEN: usize = 32;

mod promise;
mod storage;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "ios")]
mod ios;

pub fn console_log(message: &str, rt: &mut RuntimeHandle) -> anyhow::Result<()> {
    let console = PropName::new("console", rt);
    let console = rt.global().get(console, rt);
    let console = jsi::JsiObject::from_value(&console, rt)
        .ok_or(JsiDeserializeError::custom("Expected an object"))?;

    let console_log = console.get(PropName::new("log", rt), rt);
    let console_log = jsi::JsiObject::from_value(&console_log, rt)
        .ok_or(JsiDeserializeError::custom("Expected an object"))?;
    let console_log = jsi::JsiFn::from_object(&console_log, rt)
        .ok_or(JsiDeserializeError::custom("Expected a function"))?;
    console_log.call([jsi::JsiString::new(message, rt).into_value(rt)], rt)?;

    Ok(())
}

pub fn init(rt: *mut jsi::sys::Runtime, call_invoker: cxx::SharedPtr<jsi::sys::CallInvoker>) {
    let (mut rt, call_invoker) = jsi::init(rt, call_invoker);

    let host_object = LibsignalAPI {
        callInvoker: call_invoker,
    };
    let host_object = host_object.into_value(&mut rt);

    rt.global()
        .set(PropName::new("Libsignal", &mut rt), &host_object, &mut rt);

    console_log("Hello from Rust!", &mut rt).ok();

    // let global_str = JsiString::new("hallo", &mut rt);
    // let global_str = global_str.into_value(&mut rt);
    // rt.global().set(
    //     PropName::new("ExampleGlobal2", &mut rt),
    //     &global_str,
    //     &mut rt,
    // );

    // let global_num = JsiValue::new_number(3.200);
    // rt.global().set(
    //     PropName::new("ExampleGlobal3", &mut rt),
    //     &global_num,
    //     &mut rt,
    // );
}

fn serialize_bytes<'rt>(
    rt: &mut RuntimeHandle<'rt>,
    v: &[u8],
) -> Result<JsiValue<'rt>, JsiSerializeError> {
    let array_buffer_ctor = rt.global().get(PropName::new("ArrayBuffer", rt), rt);
    let array_buffer_ctor: JsiFn = array_buffer_ctor
        .try_into_js(rt)
        .expect("ArrayBuffer constructor is not a function");
    let array_buffer = array_buffer_ctor
        .call_as_constructor(vec![JsiValue::new_number(v.len() as f64)], rt)
        .expect("ArrayBuffer constructor threw an exception");
    let array_buffer: JsiArrayBuffer = array_buffer
        .try_into_js(rt)
        .expect("ArrayBuffer constructor did not return an ArrayBuffer");

    array_buffer.data(rt).copy_from_slice(v);

    Ok(array_buffer.into_value(rt))
}

fn get_buffer<'rt>(value: JsiValue<'rt>, rt: &mut RuntimeHandle<'rt>) -> anyhow::Result<Vec<u8>> {
    let value = JsiArrayBuffer::from_value(&value, rt)
        .ok_or(JsiDeserializeError::custom("Expected an ArrayBuffer"))?;

    Ok(value.data(rt).to_vec())
}

fn get_number<'rt>(value: JsiValue<'rt>, rt: &mut RuntimeHandle<'rt>) -> anyhow::Result<f64> {
    Ok(f64::from_value(&value, rt).ok_or(JsiDeserializeError::custom("Expected a number"))?)
}

fn get_string<'rt>(value: JsiValue<'rt>, rt: &mut RuntimeHandle<'rt>) -> anyhow::Result<String> {
    let value = JsiString::from_value(&value, rt)
        .ok_or(JsiDeserializeError::custom("Expected a string"))?;

    let mut output = String::new();
    let mut formatter = fmt::Formatter::new(&mut output);
    value.fmt(&mut formatter, rt)?;

    Ok(output)
}

fn get_reference<'rt, T>(
    pointer_value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<&'rt T> {
    let pointer = get_number(pointer_value, rt)? as i64;

    let reference = unsafe { &*(pointer as *const T) };

    Ok(reference)
}

fn get_reference_mut<'rt, T>(
    pointer_value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<&'rt mut T> {
    let pointer = get_number(pointer_value, rt)? as i64;

    let reference = unsafe { &mut *(pointer as *mut T) };

    Ok(reference)
}

struct LibsignalAPI {
    callInvoker: CallInvoker<'static>,
}

#[host_object()]
impl LibsignalAPI {
    #[host_object(method as KyberKeyPair_Generate)]
    pub fn KyberKeyPair_Generate(&self, _rt: &mut RuntimeHandle) -> anyhow::Result<i64> {
        let keyPair = KyberKeyPair::generate(KeyType::Kyber1024);
        let keyPairPointer = Box::into_raw(Box::new(keyPair)) as i64;

        Ok(keyPairPointer)
    }

    #[host_object(method as KyberKeyPair_GetPublicKey)]
    pub fn KyberKeyPair_GetPublicKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let keyPair: &KyberKeyPair = get_reference(pointer, rt)?;
        let publicKeyPointer = Box::into_raw(Box::new(keyPair.public_key.clone())) as i64;
        Ok(publicKeyPointer)
    }

    #[host_object(method as KyberPreKeyRecord_Serialize)]
    pub fn KyberPreKeyRecord_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let publicKey: &KemKey<Public> = get_reference(pointer, rt)?;

        let serialized = publicKey.serialize();
        let serialized = serialized.as_ref();

        Ok(serialize_bytes(rt, serialized)?)
    }

    #[host_object(method as ProtocolAddress_New)]
    pub fn ProtocolAddress_New<'rt>(
        &self,
        _rt: &mut RuntimeHandle<'rt>,
        name: String,
        deviceId: f64,
    ) -> anyhow::Result<i64> {
        let deviceId = DeviceId::from(deviceId as u32);

        let address = ProtocolAddress::new(name, deviceId);
        let pointer = Box::into_raw(Box::new(address)) as i64;

        Ok(pointer)
    }

    #[host_object(method as ProtocolAddress_Name)]
    pub fn ProtocolAddress_Name<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<String> {
        let address: &ProtocolAddress = get_reference(pointer, rt)?;

        Ok(address.name().to_string())
    }

    #[host_object(method as ProtocolAddress_DeviceId)]
    pub fn ProtocolAddress_DeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let address: &ProtocolAddress = get_reference(pointer, rt)?;

        Ok(u32::from(address.device_id()) as i64)
    }

    #[host_object(method as SenderCertificate_New)]
    pub fn SenderCertificate_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        sender_uuid: JsiValue<'rt>,
        sender_e164: JsiValue<'rt>,
        sender_device_id: JsiValue<'rt>,
        sender_key: JsiValue<'rt>,
        expiration: JsiValue<'rt>,
        signer_cert: JsiValue<'rt>,
        signer_key: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let sender_uuid = get_string(sender_uuid, rt)?;
        let sender_e164 = get_string(sender_e164, rt).ok();
        let sender_device_id = get_number(sender_device_id, rt)? as u32;
        let sender_key = CurvePublicKey::from_djb_public_key_bytes(&get_buffer(sender_key, rt)?)?;
        let expiration = Timestamp::from_epoch_millis(get_number(expiration, rt)? as u64);
        let signer_cert = ServerCertificate::deserialize(&get_buffer(signer_cert, rt)?)?;
        let signer_key = CurvePrivateKey::deserialize(&get_buffer(signer_key, rt)?)?;

        let mut rng = rand::rngs::OsRng;

        let cert = SenderCertificate::new(
            sender_uuid,
            sender_e164,
            sender_key,
            sender_device_id.into(),
            expiration,
            signer_cert,
            &signer_key,
            &mut rng,
        );

        let certPointer = Box::into_raw(Box::new(cert)) as i64;

        Ok(certPointer)
    }

    #[host_object(method as SenderCertificate_Deserialize)]
    pub fn SenderCertificate_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        serialized: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let cert = SenderCertificate::deserialize(&get_buffer(serialized, rt)?)?;

        let certPointer = Box::into_raw(Box::new(cert)) as i64;

        Ok(certPointer)
    }

    #[host_object(method as SenderCertificate_GetCertificate)]
    pub fn SenderCertificate_GetCertificate<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        let serialized_cert = cert.certificate()?;

        Ok(serialize_bytes(rt, serialized_cert)?)
    }

    #[host_object(method as SenderCertificate_GetDeviceId)]
    pub fn SenderCertificate_GetDeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        Ok(u32::from(cert.sender_device_id()?))
    }

    #[host_object(method as SenderCertificate_GetExpiration)]
    pub fn SenderCertificate_GetExpiration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        Ok(cert.expiration()?.epoch_millis() as u64)
    }

    #[host_object(method as SenderCertificate_GetKey)]
    pub fn SenderCertificate_GetKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        let public_key = Box::into_raw(Box::from(cert.key()?)) as i64;

        Ok(public_key)
    }

    #[host_object(method as SenderCertificate_GetSenderE164)]
    pub fn SenderCertificate_GetSenderE164<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        match cert.sender_e164()? {
            Some(e164) => Ok(JsiString::new(e164, rt).into_value(rt)),
            None => Ok(JsiValue::new_null()),
        }
    }

    #[host_object(method as SenderCertificate_GetSenderUuid)]
    pub fn SenderCertificate_GetSenderUuid<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<String> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        Ok(cert.sender_uuid()?.to_string())
    }

    #[host_object(method as SenderCertificate_GetSerialized)]
    pub fn SenderCertificate_GetSerialized<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        let serialized_cert = cert.serialized()?;

        Ok(serialize_bytes(rt, serialized_cert)?)
    }

    #[host_object(method as SenderCertificate_GetServerCertificate)]
    pub fn SenderCertificate_GetServerCertificate<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        let server_cert = cert.signer()?;

        let cert_pointer = Box::into_raw(Box::new(server_cert)) as i64;
        Ok(cert_pointer)
    }

    #[host_object(method as SenderCertificate_GetSignature)]
    pub fn SenderCertificate_GetSignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cert: &SenderCertificate = get_reference(pointer, rt)?;

        let signature = cert.signature()?;
        Ok(serialize_bytes(rt, signature)?)
    }

    #[host_object(method as SenderCertificate_Validate)]
    pub fn SenderCertificate_Validate<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        cert_pointer: JsiValue<'rt>,
        key_pointer: JsiValue<'rt>,
        time: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let cert: &SenderCertificate = get_reference(cert_pointer, rt)?;
        let key: &CurvePublicKey = get_reference(key_pointer, rt)?;
        let time = Timestamp::from_epoch_millis(get_number(time, rt)? as u64);

        Ok(cert.validate(key, time).is_ok())
    }

    #[host_object(method as ServerCertificate_Deserialize)]
    pub fn ServerCertificate_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let server_certificate = ServerCertificate::deserialize(&data)?;

        let server_cert_ptr = Box::into_raw(Box::new(server_certificate)) as i64;
        Ok(server_cert_ptr)
    }

    #[host_object(method as ServerCertificate_GetCertificate)]
    pub fn ServerCertificate_GetCertificate<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference(pointer, rt)?;

        let cert_data = server_cert.certificate()?;
        Ok(serialize_bytes(rt, cert_data)?)
    }

    #[host_object(method as ServerCertificate_GetKey)]
    pub fn ServerCertificate_GetKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference(pointer, rt)?;

        let public_key = server_cert.public_key()?.serialize();
        Ok(serialize_bytes(rt, public_key.as_ref())?)
    }

    #[host_object(method as ServerCertificate_GetKeyId)]
    pub fn ServerCertificate_GetKeyId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let server_cert: &ServerCertificate = get_reference(pointer, rt)?;

        Ok(server_cert.key_id()? as i64)
    }

    #[host_object(method as ServerCertificate_GetSerialized)]
    pub fn ServerCertificate_GetSerialized<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference(pointer, rt)?;

        let serialized_data = server_cert.serialized()?;
        Ok(serialize_bytes(rt, serialized_data)?)
    }

    #[host_object(method as ServerCertificate_GetSignature)]
    pub fn ServerCertificate_GetSignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference(pointer, rt)?;

        let signature_data = server_cert.signature()?;
        Ok(serialize_bytes(rt, signature_data)?)
    }

    #[host_object(method as ServerCertificate_New)]
    pub fn ServerCertificate_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        key_id: JsiValue<'rt>,
        server_key: JsiValue<'rt>,
        trust_root: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let key_id = f64::from_value(&key_id, rt).expect("Expected a number") as u32;

        let server_key = CurvePublicKey::from_djb_public_key_bytes(&get_buffer(server_key, rt)?)?;
        let trust_root = CurvePrivateKey::deserialize(&get_buffer(trust_root, rt)?)?;

        let mut rng = rand::rngs::OsRng;

        let server_cert = ServerCertificate::new(key_id, server_key, &trust_root, &mut rng)?;
        let server_cert_ptr = Box::into_raw(Box::new(server_cert)) as i64;

        Ok(server_cert_ptr)
    }

    #[host_object(method as ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic)]
    pub fn ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        group_secret_params: JsiValue<'rt>,
        auth_credential_with_pni_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let group_secret_params_vec = get_buffer(group_secret_params, rt)?;
        let group_secret_params: GroupSecretParams =
            zkgroup::deserialize(&group_secret_params_vec)?;

        let auth_credential_with_pni_vec = get_buffer(auth_credential_with_pni_bytes, rt)?;
        let auth_credential_with_pni_bytes: &[u8] = auth_credential_with_pni_vec.as_slice();

        let auth_credential = AuthCredentialWithPni::new(auth_credential_with_pni_bytes)?;
        let result = server_public_params.create_auth_credential_with_pni_presentation(
            *randomness,
            group_secret_params,
            auth_credential,
        );

        let serialized_result = zkgroup::serialize(&result);

        Ok(serialize_bytes(rt, &serialized_result)?)
    }

    #[host_object(method as ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic)]
    pub fn ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        group_secret_params: JsiValue<'rt>,
        profile_key_credential: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let group_secret_params_vec = get_buffer(group_secret_params, rt)?;
        let group_secret_params: GroupSecretParams =
            zkgroup::deserialize(&group_secret_params_vec)?;

        let profile_key_credential_vec = get_buffer(profile_key_credential, rt)?;
        let profile_key_credential: ExpiringProfileKeyCredential =
            zkgroup::deserialize(&profile_key_credential_vec)?;

        let presentation = server_public_params
            .create_expiring_profile_key_credential_presentation(
                *randomness,
                group_secret_params,
                profile_key_credential,
            );

        let serialized_presentation = zkgroup::serialize(&presentation);
        Ok(serialize_bytes(rt, &serialized_presentation)?)
    }

    #[host_object(method as ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic)]
    pub fn ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        user_id: JsiValue<'rt>,
        profile_key: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let user_id: [u8; 16] = get_buffer(user_id, rt)?.as_slice().try_into()?;
        let user_id = Aci::from_uuid_bytes(user_id);
        let profile_key: ProfileKey = zkgroup::deserialize(&get_buffer(profile_key, rt)?)?;

        let request_context = server_public_params.create_profile_key_credential_request_context(
            *randomness,
            user_id,
            profile_key,
        );

        let serialized_context = zkgroup::serialize(&request_context);
        Ok(serialize_bytes(rt, &serialized_context)?)
    }

    #[host_object(method as ServerPublicParams_CreateReceiptCredentialPresentationDeterministic)]
    pub fn ServerPublicParams_CreateReceiptCredentialPresentationDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        receipt_credential: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let receipt_credential_vec = get_buffer(receipt_credential, rt)?;
        let receipt_credential: ReceiptCredential = zkgroup::deserialize(&receipt_credential_vec)?;

        let presentation = server_public_params
            .create_receipt_credential_presentation(*randomness, &receipt_credential);

        let serialized_presentation = zkgroup::serialize(&presentation);
        Ok(serialize_bytes(rt, &serialized_presentation)?)
    }

    #[host_object(method as ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic)]
    pub fn ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        receipt_serial: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let randomness = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness.as_slice().try_into()?;

        let receipt_serial = get_buffer(receipt_serial, rt)?;
        let receipt_serial: ReceiptSerialBytes = receipt_serial.as_slice().try_into()?;

        let context = server_public_params
            .create_receipt_credential_request_context(*randomness, receipt_serial);

        let serialized_context = zkgroup::serialize(&context);
        Ok(serialize_bytes(rt, &serialized_context)?)
    }

    #[host_object(method as ServerPublicParams_Deserialize)]
    pub fn ServerPublicParams_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer_vec = get_buffer(buffer, rt)?;
        let server_public_params: ServerPublicParams = zkgroup::deserialize(&buffer_vec)?;

        let server_public_params_ptr = Box::into_raw(Box::new(server_public_params)) as i64;
        Ok(server_public_params_ptr)
    }

    #[host_object(method as ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId)]
    pub fn ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        aci: JsiValue<'rt>,
        pni: JsiValue<'rt>,
        redemption_time: JsiValue<'rt>,
        auth_credential_with_pni_response_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let aci: [u8; 16] = get_buffer(aci, rt)?.as_slice().try_into()?;
        let aci = Aci::from_uuid_bytes(aci);

        let pni: [u8; 16] = get_buffer(pni, rt)?.as_slice().try_into()?;
        let pni = Pni::from_uuid_bytes(pni);

        let redemption_time = get_number(redemption_time, rt)? as u64;
        let auth_credential_with_pni_response = AuthCredentialWithPniResponse::new(&get_buffer(
            auth_credential_with_pni_response_bytes,
            rt,
        )?)?;

        let auth_credential_with_pni = server_public_params
            .receive_auth_credential_with_pni_as_service_id(
                aci,
                pni,
                zkgroup::common::simple_types::Timestamp::from_epoch_seconds(redemption_time),
                auth_credential_with_pni_response,
            )?;

        let serialized_credential = zkgroup::serialize(&auth_credential_with_pni);
        Ok(serialize_bytes(rt, &serialized_credential)?)
    }

    #[host_object(method as ServerPublicParams_ReceiveExpiringProfileKeyCredential)]
    pub fn ServerPublicParams_ReceiveExpiringProfileKeyCredential<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        request_context: JsiValue<'rt>,
        response: JsiValue<'rt>,
        current_time_in_seconds: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let request_context_vec = get_buffer(request_context, rt)?;
        let response_vec = get_buffer(response, rt)?;
        let current_time_in_seconds = get_number(current_time_in_seconds, rt)? as u64;

        let expiring_profile_key_credential = server_public_params
            .receive_expiring_profile_key_credential(
                &zkgroup::deserialize(&request_context_vec)?,
                &zkgroup::deserialize(&response_vec)?,
                zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
                    current_time_in_seconds,
                ),
            )?;

        let serialized_credential = zkgroup::serialize(&expiring_profile_key_credential);
        Ok(serialize_bytes(rt, &serialized_credential)?)
    }

    #[host_object(method as ServerPublicParams_ReceiveReceiptCredential)]
    pub fn ServerPublicParams_ReceiveReceiptCredential<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        request_context: JsiValue<'rt>,
        response: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let request_context_vec = get_buffer(request_context, rt)?;
        let response_vec = get_buffer(response, rt)?;

        let receipt_credential = server_public_params.receive_receipt_credential(
            &zkgroup::deserialize(&request_context_vec)?,
            &zkgroup::deserialize(&response_vec)?,
        )?;

        let serialized_credential = zkgroup::serialize(&receipt_credential);
        Ok(serialize_bytes(rt, &serialized_credential)?)
    }

    #[host_object(method as ServerPublicParams_Serialize)]
    pub fn ServerPublicParams_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let serialized_params = zkgroup::serialize(server_public_params);
        Ok(serialize_bytes(rt, &serialized_params)?)
    }

    #[host_object(method as ServerPublicParams_VerifySignature)]
    pub fn ServerPublicParams_VerifySignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_public_params: JsiValue<'rt>,
        message: JsiValue<'rt>,
        notary_signature: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let server_public_params: &ServerPublicParams = get_reference(server_public_params, rt)?;

        let message_vec = get_buffer(message, rt)?;
        let notary_signature_vec = get_buffer(notary_signature, rt)?;
        let notary_signature: NotarySignatureBytes = notary_signature_vec
            .try_into()
            .map_err(|_| JsiDeserializeError::custom("Invalid NotarySignatureBytes"))?;

        server_public_params.verify_signature(&message_vec, notary_signature)?;

        Ok(())
    }

    #[host_object(method as ServerSecretParams_Deserialize)]
    pub fn ServerSecretParams_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer_vec = get_buffer(buffer, rt)?;
        let server_secret_params: ServerSecretParams = zkgroup::deserialize(&buffer_vec)?;

        let server_secret_params_ptr = Box::into_raw(Box::new(server_secret_params)) as i64;
        Ok(server_secret_params_ptr)
    }

    #[host_object(method as ServerSecretParams_GenerateDeterministic)]
    pub fn ServerSecretParams_GenerateDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        randomness: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness_bytes: [u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;
        let server_secret_params = ServerSecretParams::generate(randomness_bytes);

        let server_secret_params_ptr = Box::into_raw(Box::new(server_secret_params)) as i64;
        Ok(server_secret_params_ptr)
    }

    #[host_object(method as ServerSecretParams_GetPublicParams)]
    pub fn ServerSecretParams_GetPublicParams<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let server_secret_params: &ServerSecretParams = get_reference(params, rt)?;
        let public_params = server_secret_params.get_public_params();

        let public_params_ptr = Box::into_raw(Box::new(public_params)) as i64;
        Ok(public_params_ptr)
    }

    #[host_object(method as ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic)]
    pub fn ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_secret_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        aci: JsiValue<'rt>,
        pni: JsiValue<'rt>,
        redemption_time: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_secret_params: &ServerSecretParams = get_reference(server_secret_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let aci_vec = get_buffer(aci, rt)?;
        let aci: [u8; 16] = aci_vec.as_slice().try_into()?;
        let aci = Aci::from_uuid_bytes(aci);

        let pni_vec = get_buffer(pni, rt)?;
        let pni: [u8; 16] = pni_vec.as_slice().try_into()?;
        let pni = Pni::from_uuid_bytes(pni);

        let redemption_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(redemption_time, rt)? as u64,
        );

        let response = server_secret_params.issue_auth_credential_with_pni_as_service_id(
            *randomness,
            aci,
            pni,
            redemption_time,
        );

        let serialized_response = zkgroup::serialize(&response);
        Ok(serialize_bytes(rt, &serialized_response)?)
    }

    #[host_object(method as ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic)]
    pub fn ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_secret_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        request: JsiValue<'rt>,
        user_id: JsiValue<'rt>,
        commitment: JsiValue<'rt>,
        expiration_in_seconds: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_secret_params: &ServerSecretParams = get_reference(server_secret_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let request = zkgroup::deserialize(&get_buffer(request, rt)?)?;
        let commitment = zkgroup::deserialize(&get_buffer(commitment, rt)?)?;
        let user_id: [u8; 16] = get_buffer(user_id, rt)?.as_slice().try_into()?;

        let expiration_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(expiration_in_seconds, rt)? as u64,
        );

        let response = server_secret_params.issue_expiring_profile_key_credential(
            *randomness,
            &request,
            Aci::from_uuid_bytes(user_id),
            commitment,
            expiration_time,
        )?;

        let serialized_response = zkgroup::serialize(&response);
        Ok(serialize_bytes(rt, &serialized_response)?)
    }

    #[host_object(method as ServerSecretParams_IssueReceiptCredentialDeterministic)]
    pub fn ServerSecretParams_IssueReceiptCredentialDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_secret_params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        request: JsiValue<'rt>,
        receipt_expiration_time: JsiValue<'rt>,
        receipt_level: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_secret_params: &ServerSecretParams = get_reference(server_secret_params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let request = zkgroup::deserialize(&get_buffer(request, rt)?)?;
        let receipt_expiration_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(receipt_expiration_time, rt)? as u64,
        );
        let receipt_level = get_number(receipt_level, rt)? as u64;

        let response = server_secret_params.issue_receipt_credential(
            *randomness,
            &request,
            receipt_expiration_time,
            receipt_level,
        );

        let serialized_response = zkgroup::serialize(&response);
        Ok(serialize_bytes(rt, &serialized_response)?)
    }

    #[host_object(method as ServerSecretParams_Serialize)]
    pub fn ServerSecretParams_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        handle: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_secret_params: &ServerSecretParams = get_reference(handle, rt)?;

        let serialized_data = zkgroup::serialize(server_secret_params);

        Ok(serialize_bytes(rt, &serialized_data)?)
    }

    #[host_object(method as ServerSecretParams_SignDeterministic)]
    pub fn ServerSecretParams_SignDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        message: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_secret_params: &ServerSecretParams = get_reference(params, rt)?;

        let randomness_vec = get_buffer(randomness, rt)?;
        let randomness: &[u8; RANDOMNESS_LEN] = randomness_vec.as_slice().try_into()?;

        let message = get_buffer(message, rt)?;

        let signature = server_secret_params.sign(*randomness, &message);

        Ok(serialize_bytes(rt, signature.as_ref())?)
    }

    #[host_object(method as ServerSecretParams_VerifyAuthCredentialPresentation)]
    pub fn ServerSecretParams_VerifyAuthCredentialPresentation<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_secret_params: JsiValue<'rt>,
        group_public_params: JsiValue<'rt>,
        presentation_bytes: JsiValue<'rt>,
        current_time_in_seconds: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let server_secret_params: &ServerSecretParams = get_reference(server_secret_params, rt)?;

        let group_public_params = zkgroup::deserialize(&get_buffer(group_public_params, rt)?)?;
        let presentation = zkgroup::api::auth::AnyAuthCredentialPresentation::new(&get_buffer(
            presentation_bytes,
            rt,
        )?)?;

        let current_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(current_time_in_seconds, rt)? as u64,
        );

        server_secret_params.verify_auth_credential_presentation(
            group_public_params,
            &presentation,
            current_time,
        )?;

        Ok(())
    }

    #[host_object(method as ServerSecretParams_VerifyProfileKeyCredentialPresentation)]
    pub fn ServerSecretParams_VerifyProfileKeyCredentialPresentation<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_secret_params: JsiValue<'rt>,
        group_public_params: JsiValue<'rt>,
        presentation_bytes: JsiValue<'rt>,
        current_time_in_seconds: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let server_secret_params: &ServerSecretParams = get_reference(server_secret_params, rt)?;

        let group_public_params = zkgroup::deserialize(&get_buffer(group_public_params, rt)?)?;
        let presentation = zkgroup::api::profiles::AnyProfileKeyCredentialPresentation::new(
            &get_buffer(presentation_bytes, rt)?,
        )?;
        let current_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(current_time_in_seconds, rt)? as u64,
        );

        server_secret_params.verify_profile_key_credential_presentation(
            group_public_params,
            &presentation,
            current_time,
        )?;

        Ok(())
    }

    #[host_object(method as ServerSecretParams_VerifyReceiptCredentialPresentation)]
    pub fn ServerSecretParams_VerifyReceiptCredentialPresentation<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        server_secret_params: JsiValue<'rt>,
        presentation: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let server_secret_params: &ServerSecretParams = get_reference(server_secret_params, rt)?;

        let presentation: zkgroup::api::receipts::ReceiptCredentialPresentation =
            zkgroup::deserialize(&get_buffer(presentation, rt)?)?;

        server_secret_params.verify_receipt_credential_presentation(&presentation)?;

        Ok(())
    }

    #[host_object(method as Aes256GcmSiv_New)]
    pub fn Aes256GcmSiv_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        key: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let key = &get_buffer(key, rt)?;
        let cipher = aes_gcm_siv::Aes256GcmSiv::new_from_slice(key);

        let cipher_ptr = Box::into_raw(Box::new(cipher)) as i64;
        Ok(cipher_ptr)
    }

    #[host_object(method as Aes256GcmSiv_Decrypt)]
    pub fn Aes256GcmSiv_Decrypt<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        cipher: JsiValue<'rt>,
        ciphertext: JsiValue<'rt>,
        nonce: JsiValue<'rt>,
        associated_data: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cipher: &mut aes_gcm_siv::Aes256GcmSiv = get_reference_mut(cipher, rt)?;

        let nonce = get_buffer(nonce, rt)?;
        let nonce: &aes_gcm_siv::Nonce = nonce.as_slice().try_into()?;
        let mut buffer = get_buffer(ciphertext, rt)?;
        let associated_data = get_buffer(associated_data, rt)?;

        cipher
            .decrypt_in_place(&nonce, &associated_data, &mut buffer)
            .map_err(|e| {
                JsiDeserializeError::custom(format!("Failed to decrypt ciphertext: {:?}", e))
            })?;

        Ok(serialize_bytes(rt, &buffer)?)
    }

    #[host_object(method as Aes256GcmSiv_Encrypt)]
    pub fn Aes256GcmSiv_Encrypt<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        cipher: JsiValue<'rt>,
        plaintext: JsiValue<'rt>,
        nonce: JsiValue<'rt>,
        associated_data: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cipher: &mut aes_gcm_siv::Aes256GcmSiv = get_reference_mut(cipher, rt)?;

        let nonce = get_buffer(nonce, rt)?;
        let nonce: &aes_gcm_siv::Nonce = nonce.as_slice().try_into()?;
        let plaintext = get_buffer(plaintext, rt)?;
        let plaintext = plaintext.as_slice();
        let associated_data = get_buffer(associated_data, rt)?;

        let mut buf = Vec::with_capacity(
            plaintext.len() + <aes_gcm_siv::Aes256GcmSiv as AeadCore>::TagSize::USIZE,
        );
        buf.extend_from_slice(plaintext);

        cipher
            .encrypt_in_place(&nonce, &associated_data, &mut buf)
            .map_err(|e| {
                JsiDeserializeError::custom(format!("Failed to encrypt plaintext: {:?}", e))
            })?;

        Ok(serialize_bytes(rt, &buf)?)
    }

    #[host_object(method as AuthCredentialPresentation_CheckValidContents)]
    pub fn AuthCredentialPresentation_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let presentation = get_buffer(presentation_bytes, rt)?;
        AnyAuthCredentialPresentation::new(&presentation)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid presentation: {:?}", e)))?;
        Ok(())
    }

    #[host_object(method as AuthCredentialPresentation_GetPniCiphertext)]
    pub fn AuthCredentialPresentation_GetPniCiphertext<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let presentation = get_buffer(presentation_bytes, rt)?;
        let presentation = AnyAuthCredentialPresentation::new(&presentation)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid presentation: {:?}", e)))?;

        if let Some(ciphertext) = presentation.get_pni_ciphertext() {
            let ciphertext = zkgroup::serialize(&ciphertext);
            return Ok(serialize_bytes(rt, &ciphertext)?);
        }

        Ok(JsiValue::new_null())
    }

    #[host_object(method as AuthCredentialPresentation_GetRedemptionTime)]
    pub fn AuthCredentialPresentation_GetRedemptionTime<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let presentation = get_buffer(presentation_bytes, rt)?;
        let presentation = AnyAuthCredentialPresentation::new(&presentation)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid presentation: {:?}", e)))?;
        Ok(presentation.get_redemption_time().epoch_seconds())
    }

    #[host_object(method as AuthCredentialPresentation_GetUuidCiphertext)]
    pub fn AuthCredentialPresentation_GetUuidCiphertext<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let presentation = get_buffer(presentation_bytes, rt)?;
        let presentation = AnyAuthCredentialPresentation::new(&presentation)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid presentation: {:?}", e)))?;
        let ciphertext = presentation.get_uuid_ciphertext();
        let ciphertext = zkgroup::serialize(&ciphertext);
        Ok(serialize_bytes(rt, &ciphertext)?)
    }

    #[host_object(method as AuthCredentialWithPniResponse_CheckValidContents)]
    pub fn AuthCredentialWithPniResponse_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        response_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let response = get_buffer(response_bytes, rt)?;
        AuthCredentialWithPniResponse::new(&response)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid response: {:?}", e)))?;
        Ok(())
    }

    #[host_object(method as AuthCredentialWithPni_CheckValidContents)]
    pub fn AuthCredentialWithPni_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let credential = get_buffer(bytes, rt)?;
        AuthCredentialWithPni::new(&credential)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid credential: {:?}", e)))?;

        Ok(())
    }

    #[host_object(method as BackupAuthCredentialPresentation_CheckValidContents)]
    pub fn BackupAuthCredentialPresentation_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let presentation = get_buffer(presentation_bytes, rt)?;
        let _: BackupAuthCredentialPresentation = zkgroup::deserialize(&presentation)?;

        Ok(())
    }

    #[host_object(method as BackupAuthCredentialPresentation_Verify)]
    pub fn BackupAuthCredentialPresentation_Verify<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
        now: JsiValue<'rt>,
        server_params_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let presentation = get_buffer(presentation_bytes, rt)?;
        let current_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(now, rt)? as u64,
        );
        let server_params: GenericServerSecretParams =
            zkgroup::deserialize(&get_buffer(server_params_bytes, rt)?)?;

        let presentation: BackupAuthCredentialPresentation = zkgroup::deserialize(&presentation)?;

        presentation
            .verify(current_time, &server_params)
            .map_err(|e| {
                JsiDeserializeError::custom(format!("Failed to verify presentation: {:?}", e))
            })?;

        Ok(())
    }

    #[host_object(method as BackupAuthCredentialRequestContext_CheckValidContents)]
    pub fn BackupAuthCredentialRequestContext_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        context_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let context = get_buffer(context_bytes, rt)?;
        let _: BackupAuthCredentialRequestContext = zkgroup::deserialize(&context)?;
        Ok(())
    }

    #[host_object(method as BackupAuthCredentialRequestContext_GetRequest)]
    pub fn BackupAuthCredentialRequestContext_GetRequest<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        context_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let context = get_buffer(context_bytes, rt)?;
        let request_context: BackupAuthCredentialRequestContext = zkgroup::deserialize(&context)?;
        let request = request_context.get_request();
        Ok(serialize_bytes(rt, &zkgroup::serialize(&request))?)
    }

    #[host_object(method as BackupAuthCredentialRequestContext_New)]
    pub fn BackupAuthCredentialRequestContext_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        backup_key: JsiValue<'rt>,
        uuid: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let backup_key = get_buffer(backup_key, rt)?;
        let backup_key = backup_key.as_slice().try_into()?;
        let uuid_str = get_string(uuid, rt)?;
        let uuid = uuid::Uuid::parse_str(&uuid_str)
            .map_err(|e| JsiDeserializeError::custom(format!("Invalid UUID: {:?}", e)))?;

        let context = BackupAuthCredentialRequestContext::new(&backup_key, &uuid);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&context))?)
    }

    #[host_object(method as BackupAuthCredentialRequestContext_ReceiveResponse)]
    pub fn BackupAuthCredentialRequestContext_ReceiveResponse<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        context_bytes: JsiValue<'rt>,
        response_bytes: JsiValue<'rt>,
        expected_redemption_time: JsiValue<'rt>,
        params_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let context = get_buffer(context_bytes, rt)?;
        let response = get_buffer(response_bytes, rt)?;
        let response: BackupAuthCredentialResponse = zkgroup::deserialize(&response)?;
        let expected_redemption_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(expected_redemption_time, rt)? as u64,
        );
        let params: GenericServerPublicParams =
            zkgroup::deserialize(&get_buffer(params_bytes, rt)?)?;

        let request_context: BackupAuthCredentialRequestContext = zkgroup::deserialize(&context)?;
        let credential = request_context
            .receive(response, &params, expected_redemption_time)
            .map_err(|e| {
                JsiDeserializeError::custom(format!("Failed to receive response: {:?}", e))
            })?;

        Ok(serialize_bytes(rt, &zkgroup::serialize(&credential))?)
    }

    #[host_object(method as BackupAuthCredentialRequest_CheckValidContents)]
    pub fn BackupAuthCredentialRequest_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        request_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let request = get_buffer(request_bytes, rt)?;
        let _: BackupAuthCredentialRequest = zkgroup::deserialize(&request)?;
        Ok(())
    }

    #[host_object(method as BackupAuthCredentialRequest_IssueDeterministic)]
    pub fn BackupAuthCredentialRequest_IssueDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        request_bytes: JsiValue<'rt>,
        redemption_time: JsiValue<'rt>,
        backup_level: JsiValue<'rt>,
        params_bytes: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let request = get_buffer(request_bytes, rt)?;
        let redemption_time = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(redemption_time, rt)? as u64,
        );
        let backup_level = get_number(backup_level, rt)? as u64;
        let backup_level = BackupLevel::try_from(backup_level)
            .map_err(|_| JsiDeserializeError::custom("Invalid backup level"))?;
        let params: GenericServerSecretParams =
            zkgroup::deserialize(&get_buffer(params_bytes, rt)?)?;
        let randomness = get_buffer(randomness, rt)?;
        let randomness = randomness.as_slice().try_into()?;

        let request: BackupAuthCredentialRequest = zkgroup::deserialize(&request)?;

        let response = request.issue(redemption_time, backup_level, &params, randomness);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&response))?)
    }

    #[host_object(method as BackupAuthCredentialResponse_CheckValidContents)]
    pub fn BackupAuthCredentialResponse_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        response_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let response = get_buffer(response_bytes, rt)?;
        let _: BackupAuthCredentialResponse = zkgroup::deserialize(&response)?;
        Ok(())
    }

    #[host_object(method as BackupAuthCredential_CheckValidContents)]
    pub fn BackupAuthCredential_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        credential_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let credential = get_buffer(credential_bytes, rt)?;
        let _: BackupAuthCredential = zkgroup::deserialize(&credential)?;
        Ok(())
    }

    #[host_object(method as BackupAuthCredential_GetBackupId)]
    pub fn BackupAuthCredential_GetBackupId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        credential_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let credential = get_buffer(credential_bytes, rt)?;
        let credential: BackupAuthCredential = zkgroup::deserialize(&credential)?;
        Ok(serialize_bytes(rt, &credential.backup_id())?)
    }

    #[host_object(method as BackupAuthCredential_GetBackupLevel)]
    pub fn BackupAuthCredential_GetBackupLevel<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        credential_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let credential = get_buffer(credential_bytes, rt)?;
        let credential: BackupAuthCredential = zkgroup::deserialize(&credential)?;
        Ok(credential.backup_level() as u64)
    }

    #[host_object(method as BackupAuthCredential_PresentDeterministic)]
    pub fn BackupAuthCredential_PresentDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        credential_bytes: JsiValue<'rt>,
        server_params_bytes: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let credential = get_buffer(credential_bytes, rt)?;
        let server_params: GenericServerPublicParams =
            zkgroup::deserialize(&get_buffer(server_params_bytes, rt)?)?;
        let randomness = get_buffer(randomness, rt)?;
        let randomness = randomness.as_slice().try_into()?;

        let credential: BackupAuthCredential = zkgroup::deserialize(&credential)?;

        let presentation = credential.present(&server_params, randomness);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&presentation))?)
    }

    #[host_object(method as DecryptionErrorMessage_Deserialize)]
    pub fn DecryptionErrorMessage_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(data, rt)?;
        let message = DecryptionErrorMessage::try_from(buffer.as_slice())?;
        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        Ok(message_ptr)
    }

    #[host_object(method as DecryptionErrorMessage_ExtractFromSerializedContent)]
    pub fn DecryptionErrorMessage_ExtractFromSerializedContent<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(bytes, rt)?;
        let message = extract_decryption_error_message_from_serialized_content(&buffer);
        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        Ok(message_ptr)
    }

    #[host_object(method as DecryptionErrorMessage_ForOriginalMessage)]
    pub fn DecryptionErrorMessage_ForOriginalMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        original_bytes: JsiValue<'rt>,
        original_type: JsiValue<'rt>,
        original_timestamp: JsiValue<'rt>,
        original_sender_device_id: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let original_bytes = get_buffer(original_bytes, rt)?;
        let original_type = get_number(original_type, rt)? as u8;
        let original_type = CiphertextMessageType::try_from(original_type)?;
        let original_timestamp =
            Timestamp::from_epoch_millis(get_number(original_timestamp, rt)? as u64);
        let original_sender_device_id = get_number(original_sender_device_id, rt)? as u32;

        let message = DecryptionErrorMessage::for_original(
            &original_bytes,
            original_type,
            original_timestamp,
            original_sender_device_id,
        )?;

        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        Ok(message_ptr)
    }

    #[host_object(method as DecryptionErrorMessage_GetDeviceId)]
    pub fn DecryptionErrorMessage_GetDeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let message: &DecryptionErrorMessage = get_reference(obj, rt)?;
        Ok(message.device_id())
    }

    #[host_object(method as DecryptionErrorMessage_GetRatchetKey)]
    pub fn DecryptionErrorMessage_GetRatchetKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &DecryptionErrorMessage = get_reference(obj, rt)?;
        if let Some(key) = message.ratchet_key() {
            let key_ptr = Box::into_raw(Box::new(key.clone())) as i64;
            Ok(JsiValue::new_number(key_ptr as f64))
        } else {
            Ok(JsiValue::new_null())
        }
    }

    #[host_object(method as DecryptionErrorMessage_GetTimestamp)]
    pub fn DecryptionErrorMessage_GetTimestamp<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let message: &DecryptionErrorMessage = get_reference(obj, rt)?;
        Ok(message.timestamp().epoch_millis() as u64)
    }

    #[host_object(method as DecryptionErrorMessage_Serialize)]
    pub fn DecryptionErrorMessage_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &DecryptionErrorMessage = get_reference(obj, rt)?;
        Ok(serialize_bytes(rt, message.serialized())?)
    }

    #[host_object(method as GroupCipher_DecryptMessage)]
    pub fn GroupCipher_DecryptMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'static>,
        sender: JsiValue<'static>,
        message: JsiValue<'static>,
        store: JsiValue<'static>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let rt_ptr = Box::into_raw(Box::new(clone_runtime_handle(rt))) as i64;
        let sender_ptr = Box::into_raw(Box::new(sender)) as i64;
        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        let store_ptr = Box::into_raw(Box::new(store)) as i64;

        let callback: CallbackType<'static> = Arc::new(move || {
            Box::pin(async move {
                let mut rt = *unsafe { Box::from_raw(rt_ptr as *mut RuntimeHandle<'static>) };
                let sender = *unsafe { Box::from_raw(sender_ptr as *mut JsiValue<'static>) };
                let message = *unsafe { Box::from_raw(message_ptr as *mut JsiValue<'static>) };
                let store = *unsafe { Box::from_raw(store_ptr as *mut JsiValue<'static>) };
                let message_bytes = get_buffer(message, &mut rt)?;
                let protocol_address: &ProtocolAddress = get_reference(sender, &mut rt)?;

                let mut store = JSISenderKeyStore::new(store, clone_runtime_handle(&mut rt))?;

                let result = group_decrypt(&message_bytes, &mut store, protocol_address).await;

                Ok(JsiValue::new_number(64.0))
            })
        });

        make_async(rt, callback, self.callInvoker.clone())
    }
}
