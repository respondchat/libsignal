#![allow(non_snake_case)]
#![allow(internal_features)]
#![allow(dead_code)]
#![feature(fmt_internals)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]

use aes_gcm_siv::aead::AeadMutInPlace;
use anyhow::anyhow;
use futures::executor;
use sequences::ServiceIdSequence;
use storage::{
    JSIIdentityKeyStore, JSIKyberPreKeyStore, JSIPreKeyStore, JSISenderKeyStore, JSISessionStore,
    JSISignedPreKeyStore,
};
use util::*;

use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
use aes_gcm_siv::{AeadCore, KeyInit};
use jsi::de::JsiDeserializeError;
use jsi::{host_object, CallInvoker, IntoValue, JsiString, JsiValue, PropName, RuntimeHandle};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::kem::{self, Key as KemKey, KeyPair as KyberKeyPair, KeyType, Public};
use libsignal_protocol::{
    create_sender_key_distribution_message,
    extract_decryption_error_message_from_serialized_content, group_decrypt, group_encrypt,
    message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    process_sender_key_distribution_message, sealed_sender_decrypt, sealed_sender_decrypt_to_usmc,
    sealed_sender_encrypt_from_usmc, sealed_sender_multi_recipient_encrypt, CiphertextMessage,
    CiphertextMessageType, ContentHint, DecryptionErrorMessage, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, KeyPair as CurveKeyPair, KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PrivateKey as CurvePrivateKey,
    PublicKey as CurvePublicKey, SealedSenderDecryptionResult, SealedSenderV2SentMessage,
    SenderCertificate, SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord,
    ServerCertificate, SessionRecord, SignalMessage, SignedPreKeyId, SignedPreKeyRecord, Timestamp,
    UnidentifiedSenderMessageContent,
};
use promise::clone_runtime_handle;
use serde::de::Error;
use zkgroup::auth::{
    AnyAuthCredentialPresentation, AuthCredentialWithPni, AuthCredentialWithPniResponse,
};
use zkgroup::backups::{
    BackupAuthCredential, BackupAuthCredentialPresentation, BackupAuthCredentialRequest,
    BackupAuthCredentialRequestContext, BackupAuthCredentialResponse, BackupLevel,
};
use zkgroup::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use zkgroup::groups::{
    GroupMasterKey, GroupPublicParams, GroupSecretParams, GroupSendDerivedKeyPair,
    GroupSendEndorsement, GroupSendEndorsementsResponse, GroupSendFullToken, GroupSendToken,
    ProfileKeyCiphertext, UuidCiphertext,
};
use zkgroup::profiles::{
    AnyProfileKeyCredentialPresentation, ExpiringProfileKeyCredential, ProfileKey,
    ProfileKeyCredentialRequest, ProfileKeyCredentialRequestContext,
};
use zkgroup::receipts::ReceiptCredential;
use zkgroup::{
    NotarySignatureBytes, ReceiptSerialBytes, ServerPublicParams, ServerSecretParams,
    UUID_CIPHERTEXT_LEN,
};

pub const RANDOMNESS_LEN: usize = 32;

mod promise;
mod sequences;
mod storage;
mod util;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "ios")]
mod ios;

pub fn init(rt: *mut jsi::sys::Runtime, call_invoker: cxx::SharedPtr<jsi::sys::CallInvoker>) {
    let (mut rt, call_invoker) = jsi::init(rt, call_invoker);

    let host_object = LibsignalAPI {
        _callInvoker: call_invoker,
    };
    let host_object = host_object.into_value(&mut rt);

    rt.global()
        .set(PropName::new("Libsignal", &mut rt), &host_object, &mut rt);

    console_log("Hello from Rust!", &mut rt).ok();
}

struct LibsignalAPI {
    _callInvoker: CallInvoker<'static>,
}

#[host_object()]
impl LibsignalAPI {
    #[host_object(method as KyberKeyPair_Generate)]
    pub fn KyberKeyPair_Generate(&self, _rt: &mut RuntimeHandle) -> anyhow::Result<i64> {
        let keyPair = KyberKeyPair::generate(KeyType::Kyber1024);
        let pointer = Box::into_raw(Box::new(keyPair)) as i64;

        Ok(pointer)
    }

    #[host_object(method as KyberKeyPair_GetPublicKey)]
    pub fn KyberKeyPair_GetPublicKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let keyPair: &KyberKeyPair = get_reference_handle(pointer, rt)?;
        let pointer = Box::into_raw(Box::new(keyPair.public_key.clone())) as i64;
        Ok(pointer)
    }

    #[host_object(method as KyberKeyPair_GetSecretKey)]
    pub fn KyberKeyPair_GetSecretKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let keyPair: &KyberKeyPair = get_reference_handle(pointer, rt)?;
        let pointer = Box::into_raw(Box::new(keyPair.secret_key.clone())) as i64;
        Ok(pointer)
    }

    #[host_object(method as KyberPreKeyRecord_Serialize)]
    pub fn KyberPreKeyRecord_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let publicKey: &KemKey<Public> = get_reference_handle(pointer, rt)?;

        let serialized = publicKey.serialize();
        let serialized = serialized.as_ref();

        Ok(serialize_bytes(rt, serialized)?)
    }

    #[host_object(method as KyberPreKeyRecord_Deserialize)]
    pub fn KyberPreKeyRecord_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let record = KyberPreKeyRecord::deserialize(&data)?;
        let record_ptr = Box::into_raw(Box::new(record)) as i64;
        Ok(record_ptr)
    }

    #[host_object(method as KyberPreKeyRecord_GetId)]
    pub fn KyberPreKeyRecord_GetId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let record: &KyberPreKeyRecord = get_reference_handle(obj, rt)?;
        let id: KyberPreKeyId = record.id()?;
        Ok(id.into())
    }

    #[host_object(method as KyberPreKeyRecord_GetKeyPair)]
    pub fn KyberPreKeyRecord_GetKeyPair<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let record: &KyberPreKeyRecord = get_reference_handle(obj, rt)?;
        let key_pair = record.key_pair()?;
        let key_pair_ptr = Box::into_raw(Box::new(key_pair)) as i64;
        Ok(key_pair_ptr)
    }

    #[host_object(method as KyberPreKeyRecord_GetPublicKey)]
    pub fn KyberPreKeyRecord_GetPublicKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let record: &KyberPreKeyRecord = get_reference_handle(obj, rt)?;
        let public_key = record.public_key()?;
        let public_key_ptr = Box::into_raw(Box::new(public_key)) as i64;
        Ok(public_key_ptr)
    }

    #[host_object(method as KyberPreKeyRecord_GetSecretKey)]
    pub fn KyberPreKeyRecord_GetSecretKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let record: &KyberPreKeyRecord = get_reference_handle(obj, rt)?;
        let secret_key = record.secret_key()?;
        let secret_key_ptr = Box::into_raw(Box::new(secret_key)) as i64;
        Ok(secret_key_ptr)
    }

    #[host_object(method as KyberPreKeyRecord_GetSignature)]
    pub fn KyberPreKeyRecord_GetSignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let record: &KyberPreKeyRecord = get_reference_handle(obj, rt)?;
        let signature = record.signature()?;
        Ok(serialize_bytes(rt, &signature)?)
    }

    #[host_object(method as KyberPreKeyRecord_GetTimestamp)]
    pub fn KyberPreKeyRecord_GetTimestamp<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let record: &KyberPreKeyRecord = get_reference_handle(obj, rt)?;
        let timestamp = record.timestamp()?;
        Ok(timestamp.epoch_millis() as u64)
    }

    #[host_object(method as KyberPreKeyRecord_New)]
    pub fn KyberPreKeyRecord_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        id: JsiValue<'rt>,
        timestamp: JsiValue<'rt>,
        key_pair: JsiValue<'rt>,
        signature: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let id = KyberPreKeyId::from(get_number(id, rt)? as u32);
        let timestamp = Timestamp::from_epoch_millis(get_number(timestamp, rt)? as u64);
        let key_pair: &kem::KeyPair = get_reference_handle(key_pair, rt)?;
        let signature = get_buffer(signature, rt)?;

        let record = KyberPreKeyRecord::new(id, timestamp, key_pair, &signature);
        let record_ptr = Box::into_raw(Box::new(record)) as i64;
        Ok(record_ptr)
    }

    #[host_object(method as KyberPublicKey_Deserialize)]
    pub fn KyberPublicKey_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let public_key = kem::PublicKey::deserialize(&data)?;
        let public_key_ptr = Box::into_raw(Box::new(public_key)) as i64;
        Ok(public_key_ptr)
    }

    #[host_object(method as KyberPublicKey_Equals)]
    pub fn KyberPublicKey_Equals<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        lhs: JsiValue<'rt>,
        rhs: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let lhs: &kem::PublicKey = get_reference_handle(lhs, rt)?;
        let rhs: &kem::PublicKey = get_reference_handle(rhs, rt)?;
        Ok(lhs == rhs)
    }

    #[host_object(method as KyberPublicKey_Serialize)]
    pub fn KyberPublicKey_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let public_key: &kem::PublicKey = get_reference_handle(obj, rt)?;
        let serialized = public_key.serialize();
        Ok(serialize_bytes(rt, &serialized)?)
    }

    #[host_object(method as KyberSecretKey_Deserialize)]
    pub fn KyberSecretKey_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let secret_key = kem::SecretKey::deserialize(&data)?;
        let secret_key_ptr = Box::into_raw(Box::new(secret_key)) as i64;
        Ok(secret_key_ptr)
    }

    #[host_object(method as KyberSecretKey_Serialize)]
    pub fn KyberSecretKey_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let secret_key: &kem::SecretKey = get_reference_handle(obj, rt)?;
        let serialized = secret_key.serialize();
        Ok(serialize_bytes(rt, &serialized)?)
    }

    #[host_object(method as PrivateKey_Agree)]
    pub fn PrivateKey_Agree<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        privateKey: JsiValue<'rt>,
        publicKey: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let privateKey: &CurvePrivateKey = get_reference_handle(privateKey, rt)?;
        let publicKey: &CurvePublicKey = get_reference_handle(publicKey, rt)?;

        let sharedSecret = privateKey.calculate_agreement(publicKey)?;

        Ok(serialize_bytes(rt, &sharedSecret)?)
    }

    #[host_object(method as PrivateKey_Sign)]
    pub fn PrivateKey_Sign<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        privateKey: JsiValue<'rt>,
        message: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let privateKey: &CurvePrivateKey = get_reference_handle(privateKey, rt)?;
        let message = get_buffer(message, rt)?;
        let mut rng = rand::rngs::OsRng;
        let signature = privateKey.calculate_signature(&message, &mut rng)?;

        Ok(serialize_bytes(rt, &signature)?)
    }

    #[host_object(method as PrivateKey_Deserialize)]
    pub fn PrivateKey_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let privateKey = CurvePrivateKey::deserialize(&data)?;

        let privateKeyPointer = Box::into_raw(Box::new(privateKey)) as i64;

        Ok(privateKeyPointer)
    }

    #[host_object(method as PrivateKey_Generate)]
    pub fn PrivateKey_Generate(&self, _rt: &mut RuntimeHandle) -> anyhow::Result<i64> {
        let mut rng = rand::rngs::OsRng;
        let keypair = CurveKeyPair::generate(&mut rng);
        let keyPairPointer = Box::into_raw(Box::new(keypair.private_key)) as i64;

        Ok(keyPairPointer)
    }

    #[host_object(method as PrivateKey_GetPublicKey)]
    pub fn PrivateKey_GetPublicKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let privateKey: &CurvePrivateKey = get_reference_handle(pointer, rt)?;
        let publicKeyPointer = Box::into_raw(Box::new(privateKey.public_key()?)) as i64;
        Ok(publicKeyPointer)
    }

    #[host_object(method as PrivateKey_Serialize)]
    pub fn PrivateKey_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let privateKey: &CurvePrivateKey = get_reference_handle(pointer, rt)?;

        Ok(serialize_bytes(rt, &privateKey.serialize())?)
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
        let address: &ProtocolAddress = get_reference_handle(pointer, rt)?;

        Ok(address.name().to_string())
    }

    #[host_object(method as ProtocolAddress_DeviceId)]
    pub fn ProtocolAddress_DeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let address: &ProtocolAddress = get_reference_handle(pointer, rt)?;

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
        )?;

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
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

        let serialized_cert = cert.certificate()?;

        Ok(serialize_bytes(rt, serialized_cert)?)
    }

    #[host_object(method as SenderCertificate_GetDeviceId)]
    pub fn SenderCertificate_GetDeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

        Ok(u32::from(cert.sender_device_id()?))
    }

    #[host_object(method as SenderCertificate_GetExpiration)]
    pub fn SenderCertificate_GetExpiration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

        Ok(cert.expiration()?.epoch_millis() as u64)
    }

    #[host_object(method as SenderCertificate_GetKey)]
    pub fn SenderCertificate_GetKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

        let public_key = Box::into_raw(Box::from(cert.key()?)) as i64;

        Ok(public_key)
    }

    #[host_object(method as SenderCertificate_GetSenderE164)]
    pub fn SenderCertificate_GetSenderE164<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

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
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

        Ok(cert.sender_uuid()?.to_string())
    }

    #[host_object(method as SenderCertificate_GetSerialized)]
    pub fn SenderCertificate_GetSerialized<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

        let serialized_cert = cert.serialized()?;

        Ok(serialize_bytes(rt, serialized_cert)?)
    }

    #[host_object(method as SenderCertificate_GetServerCertificate)]
    pub fn SenderCertificate_GetServerCertificate<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

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
        let cert: &SenderCertificate = get_reference_handle(pointer, rt)?;

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
        let cert: &SenderCertificate = get_reference_handle(cert_pointer, rt)?;
        let key: &CurvePublicKey = get_reference_handle(key_pointer, rt)?;
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
        let server_cert: &ServerCertificate = get_reference_handle(pointer, rt)?;

        let cert_data = server_cert.certificate()?;
        Ok(serialize_bytes(rt, cert_data)?)
    }

    #[host_object(method as ServerCertificate_GetKey)]
    pub fn ServerCertificate_GetKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference_handle(pointer, rt)?;

        let public_key = server_cert.public_key()?.serialize();
        Ok(serialize_bytes(rt, public_key.as_ref())?)
    }

    #[host_object(method as ServerCertificate_GetKeyId)]
    pub fn ServerCertificate_GetKeyId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let server_cert: &ServerCertificate = get_reference_handle(pointer, rt)?;

        Ok(server_cert.key_id()? as i64)
    }

    #[host_object(method as ServerCertificate_GetSerialized)]
    pub fn ServerCertificate_GetSerialized<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference_handle(pointer, rt)?;

        let serialized_data = server_cert.serialized()?;
        Ok(serialize_bytes(rt, serialized_data)?)
    }

    #[host_object(method as ServerCertificate_GetSignature)]
    pub fn ServerCertificate_GetSignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let server_cert: &ServerCertificate = get_reference_handle(pointer, rt)?;

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
        let key_id = get_number(key_id, rt)? as u32;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_public_params: &ServerPublicParams =
            get_reference_handle(server_public_params, rt)?;

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
        let server_secret_params: &ServerSecretParams = get_reference_handle(params, rt)?;
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
        let server_secret_params: &ServerSecretParams =
            get_reference_handle(server_secret_params, rt)?;

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
        let server_secret_params: &ServerSecretParams =
            get_reference_handle(server_secret_params, rt)?;

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
        let server_secret_params: &ServerSecretParams =
            get_reference_handle(server_secret_params, rt)?;

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
        let server_secret_params: &ServerSecretParams = get_reference_handle(handle, rt)?;

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
        let server_secret_params: &ServerSecretParams = get_reference_handle(params, rt)?;

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
        let server_secret_params: &ServerSecretParams =
            get_reference_handle(server_secret_params, rt)?;

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
        let server_secret_params: &ServerSecretParams =
            get_reference_handle(server_secret_params, rt)?;

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
        let server_secret_params: &ServerSecretParams =
            get_reference_handle(server_secret_params, rt)?;

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
        let cipher = aes_gcm_siv::Aes256GcmSiv::new_from_slice(key)?;

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
        let cipher: &mut aes_gcm_siv::Aes256GcmSiv = get_reference_handle_mut(cipher, rt)?;

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
        let cipher: &mut aes_gcm_siv::Aes256GcmSiv = get_reference_handle_mut(cipher, rt)?;

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
        let message = extract_decryption_error_message_from_serialized_content(&buffer)?;
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
        let message: &DecryptionErrorMessage = get_reference_handle(obj, rt)?;
        Ok(message.device_id())
    }

    #[host_object(method as DecryptionErrorMessage_GetRatchetKey)]
    pub fn DecryptionErrorMessage_GetRatchetKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &DecryptionErrorMessage = get_reference_handle(obj, rt)?;
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
        let message: &DecryptionErrorMessage = get_reference_handle(obj, rt)?;
        Ok(message.timestamp().epoch_millis() as u64)
    }

    #[host_object(method as DecryptionErrorMessage_Serialize)]
    pub fn DecryptionErrorMessage_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &DecryptionErrorMessage = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, message.serialized())?)
    }

    #[host_object(method as SenderKeyDistributionMessage_Create)]
    pub fn SenderKeyDistributionMessage_Create<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        sender: JsiValue<'rt>,
        distribution_id: JsiValue<'rt>,
        store: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let distribution_id = get_buffer(distribution_id, rt)?;
        let distribution_id = uuid::Uuid::from_slice(distribution_id.as_slice())?;
        let sender: &ProtocolAddress = get_reference_handle(sender, rt)?;

        println!(
            "SenderKeyDistributionMessage_Create: sender: {:?}, distribution_id: {:?}, store: {:?}",
            sender, distribution_id, store
        );

        let mut store = JSISenderKeyStore::new(store, clone_runtime_handle(rt))?;
        let mut csprng = rand::rngs::OsRng;

        println!("SenderKeyDistributionMessage_Create: store");

        let result = create_sender_key_distribution_message(
            sender,
            distribution_id,
            &mut store,
            &mut csprng,
        );

        println!("SenderKeyDistributionMessage_Create: future");

        let result = executor::block_on(result)?;

        println!("SenderKeyDistributionMessage_Create: result: {:?}", result);

        let pointer = Box::into_raw(Box::new(result)) as i64;

        Ok(pointer)
    }

    #[host_object(method as SenderKeyDistributionMessage_Deserialize)]
    pub fn SenderKeyDistributionMessage_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(buffer, rt)?;
        let msg = SenderKeyDistributionMessage::try_from(&buffer[..])?;

        let pointer = Box::into_raw(Box::new(msg)) as i64;

        Ok(pointer)
    }

    #[host_object(method as SenderKeyDistributionMessage_Serialize)]
    pub fn SenderKeyDistributionMessage_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let msg: &SenderKeyDistributionMessage = get_reference_handle(pointer, rt)?;

        Ok(serialize_bytes(rt, msg.serialized())?)
    }

    #[host_object(method as SenderKeyDistributionMessage_GetChainKey)]
    pub fn SenderKeyDistributionMessage_GetChainKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let msg: &SenderKeyDistributionMessage = get_reference_handle(pointer, rt)?;

        Ok(serialize_bytes(rt, msg.chain_key()?)?)
    }

    #[host_object(method as SenderKeyDistributionMessage_GetDistributionId)]
    pub fn SenderKeyDistributionMessage_GetDistributionId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let msg: &SenderKeyDistributionMessage = get_reference_handle(pointer, rt)?;

        Ok(serialize_bytes(rt, msg.distribution_id()?.as_bytes())?)
    }

    #[host_object(method as SenderKeyDistributionMessage_GetChainId)]
    pub fn SenderKeyDistributionMessage_GetChainId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let msg: &SenderKeyDistributionMessage = get_reference_handle(pointer, rt)?;

        Ok(msg.chain_id()?)
    }

    #[host_object(method as SenderKeyDistributionMessage_GetIteration)]
    pub fn SenderKeyDistributionMessage_GetIteration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let msg: &SenderKeyDistributionMessage = get_reference_handle(pointer, rt)?;

        Ok(msg.iteration()?)
    }

    #[host_object(method as SenderKeyDistributionMessage_Process)]
    pub fn SenderKeyDistributionMessage_Process<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        sender: JsiValue<'rt>,
        message: JsiValue<'rt>,
        store: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let message: &SenderKeyDistributionMessage = get_reference_handle(message, rt)?;
        let sender: &ProtocolAddress = get_reference_handle(sender, rt)?;

        let mut store = JSISenderKeyStore::new(store, clone_runtime_handle(rt))?;

        executor::block_on(process_sender_key_distribution_message(
            sender, message, &mut store,
        ))?;

        Ok(())
    }

    #[host_object(method as GroupCipher_DecryptMessage)]
    pub fn GroupCipher_DecryptMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        sender: JsiValue<'rt>,
        message: JsiValue<'rt>,
        store: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let message_bytes = get_buffer(message, rt)?;
        let sender: &ProtocolAddress = get_reference_handle(sender, rt)?;

        let mut store = JSISenderKeyStore::new(store, clone_runtime_handle(rt))?;

        let result = executor::block_on(group_decrypt(&message_bytes, &mut store, sender))?;

        Ok(serialize_bytes(rt, &result)?)
    }

    #[host_object(method as GroupCipher_EncryptMessage)]
    pub fn GroupCipher_EncryptMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        sender: JsiValue<'rt>,
        distribution_id: JsiValue<'rt>,
        message: JsiValue<'rt>,
        store: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let distribution_id = get_buffer(distribution_id, rt)?;
        let distribution_id = uuid::Uuid::from_slice(distribution_id.as_slice())?;
        let message = get_buffer(message, rt)?;
        let sender: &ProtocolAddress = get_reference_handle(sender, rt)?;

        let mut store = JSISenderKeyStore::new(store, clone_runtime_handle(rt))?;
        let mut rng = rand::rngs::OsRng;

        let ctext = executor::block_on(group_encrypt(
            &mut store,
            sender,
            distribution_id,
            &message,
            &mut rng,
        ))?;
        let ctext = CiphertextMessage::SenderKeyMessage(ctext);

        let pointer = Box::into_raw(Box::new(ctext)) as i64;

        Ok(pointer)
    }

    #[host_object(method as PreKeyBundle_GetDeviceId)]
    pub fn PreKeyBundle_GetDeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        Ok(u32::from(bundle.device_id()?))
    }

    #[host_object(method as PreKeyBundle_GetIdentityKey)]
    pub fn PreKeyBundle_GetIdentityKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        Ok(Box::into_raw(Box::new(bundle.identity_key()?)) as i64)
    }

    #[host_object(method as PreKeyBundle_GetKyberPreKeyId)]
    pub fn PreKeyBundle_GetKyberPreKeyId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        match bundle.kyber_pre_key_id()? {
            Some(id) => Ok(JsiValue::new_number(u32::from(id) as f64)),
            None => Ok(JsiValue::new_null()),
        }
    }

    #[host_object(method as PreKeyBundle_GetKyberPreKeyPublic)]
    pub fn PreKeyBundle_GetKyberPreKeyPublic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        match bundle.kyber_pre_key_public()? {
            Some(public_key) => {
                let public_key_ptr = Box::into_raw(Box::new(public_key.clone())) as i64;
                Ok(JsiValue::new_number(public_key_ptr as f64))
            }
            None => Ok(JsiValue::new_null()),
        }
    }

    #[host_object(method as PreKeyBundle_GetKyberPreKeySignature)]
    pub fn PreKeyBundle_GetKyberPreKeySignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;
        let signature = bundle.kyber_pre_key_signature()?.unwrap_or(&[]).to_vec();
        Ok(serialize_bytes(rt, &signature)?)
    }

    #[host_object(method as PreKeyBundle_GetPreKeyId)]
    pub fn PreKeyBundle_GetPreKeyId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        match bundle.pre_key_id()? {
            Some(id) => Ok(JsiValue::new_number(u32::from(id) as f64)),
            None => Ok(JsiValue::new_null()),
        }
    }

    #[host_object(method as PreKeyBundle_GetPreKeyPublic)]
    pub fn PreKeyBundle_GetPreKeyPublic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        match bundle.pre_key_public()? {
            Some(public_key) => {
                let public_key_ptr = Box::into_raw(Box::new(public_key.clone())) as i64;
                Ok(JsiValue::new_number(public_key_ptr as f64))
            }
            None => Ok(JsiValue::new_null()),
        }
    }

    #[host_object(method as PreKeyBundle_GetRegistrationId)]
    pub fn PreKeyBundle_GetRegistrationId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;

        Ok(bundle.registration_id()?)
    }

    #[host_object(method as PreKeyBundle_GetSignedPreKeyId)]
    pub fn PreKeyBundle_GetSignedPreKeyId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;
        Ok(u32::from(bundle.signed_pre_key_id()?))
    }

    #[host_object(method as PreKeyBundle_GetSignedPreKeyPublic)]
    pub fn PreKeyBundle_GetSignedPreKeyPublic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;
        let public_key = bundle.signed_pre_key_public()?.clone();
        Ok(Box::into_raw(Box::new(public_key)) as i64)
    }

    #[host_object(method as PreKeyBundle_GetSignedPreKeySignature)]
    pub fn PreKeyBundle_GetSignedPreKeySignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<JsiValue<'rt>> {
        let bundle: &PreKeyBundle = get_reference_handle(obj, rt)?;
        let signature = bundle.signed_pre_key_signature()?.to_vec();
        Ok(serialize_bytes(rt, &signature)?)
    }

    #[host_object(method as PreKeyBundle_New)]
    pub fn PreKeyBundle_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        registration_id: f64,
        device_id: f64,
        prekey_id: JsiValue<'rt>, // null or f64
        prekey: JsiValue<'rt>,    // null or CurvePublicKey
        signed_prekey_id: f64,
        signed_prekey: JsiValue<'rt>,
        signed_prekey_signature: JsiValue<'rt>,
        identity_key: JsiValue<'rt>,
        kyber_prekey_id: JsiValue<'rt>,        // null or i64
        kyber_prekey: JsiValue<'rt>,           // null or KemKey<Public>
        kyber_prekey_signature: JsiValue<'rt>, // buffer
    ) -> anyhow::Result<i64> {
        let prekey = if prekey_id.is_null()
            || prekey_id.is_undefined()
            || prekey.is_null()
            || prekey.is_undefined()
        {
            None
        } else {
            let prekey_id = get_number(prekey_id, rt)? as u32;
            let prekey = get_reference_handle::<CurvePublicKey>(prekey, rt)?.clone();

            Some((PreKeyId::from(prekey_id), prekey))
        };

        let signed_prekey: CurvePublicKey = *get_reference_handle(signed_prekey, rt)?;
        let identity_key: CurvePublicKey = *get_reference_handle(identity_key, rt)?;
        let identity_key = IdentityKey::new(identity_key);
        let signed_prekey_signature = get_buffer(signed_prekey_signature, rt)?;

        let mut bundle = PreKeyBundle::new(
            registration_id as u32,
            DeviceId::from(device_id as u32),
            prekey,
            SignedPreKeyId::from(signed_prekey_id as u32),
            signed_prekey,
            signed_prekey_signature,
            identity_key,
        )?;

        if !kyber_prekey_id.is_null()
            && !kyber_prekey_id.is_undefined()
            && !kyber_prekey.is_null()
            && !kyber_prekey.is_undefined()
        {
            let kyber_prekey: &KemKey<Public> = get_reference_handle(kyber_prekey, rt)?;
            let kyber_signature = get_buffer(kyber_prekey_signature, rt)?;
            let kyber_prekey_id = get_number(kyber_prekey_id, rt)? as u32;
            bundle = bundle.with_kyber_pre_key(
                KyberPreKeyId::from(kyber_prekey_id),
                kyber_prekey.clone(),
                kyber_signature,
            );
        }

        let pointer = Box::into_raw(Box::new(bundle)) as i64;
        Ok(pointer)
    }

    #[host_object(method as PreKeyRecord_Deserialize)]
    pub fn PreKeyRecord_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(data, rt)?;
        let prekey_record = PreKeyRecord::deserialize(&buffer)?;

        let prekey_record_ptr = Box::into_raw(Box::new(prekey_record)) as i64;
        Ok(prekey_record_ptr)
    }

    #[host_object(method as PreKeyRecord_GetId)]
    pub fn PreKeyRecord_GetId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let prekey_record: &PreKeyRecord = get_reference_handle(obj, rt)?;
        Ok(prekey_record.id()?.into())
    }

    #[host_object(method as PreKeyRecord_GetPrivateKey)]
    pub fn PreKeyRecord_GetPrivateKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let prekey_record: &PreKeyRecord = get_reference_handle(obj, rt)?;
        let private_key = prekey_record.private_key()?;
        let private_key_ptr = Box::into_raw(Box::new(private_key)) as i64;

        Ok(private_key_ptr)
    }

    #[host_object(method as PreKeyRecord_GetPublicKey)]
    pub fn PreKeyRecord_GetPublicKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let prekey_record: &PreKeyRecord = get_reference_handle(obj, rt)?;
        let public_key = prekey_record.public_key()?;
        let public_key_ptr = Box::into_raw(Box::new(public_key)) as i64;

        Ok(public_key_ptr)
    }

    #[host_object(method as PreKeyRecord_New)]
    pub fn PreKeyRecord_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        id: JsiValue<'rt>,
        pub_key: JsiValue<'rt>,
        priv_key: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let id = PreKeyId::from(get_number(id, rt)? as u32);
        let public_key: &CurvePublicKey = get_reference_handle(pub_key, rt)?;
        let private_key: &CurvePrivateKey = get_reference_handle(priv_key, rt)?;

        let prekey_record = PreKeyRecord::new(
            id,
            &CurveKeyPair::new(public_key.clone(), private_key.clone()),
        );
        let prekey_record_ptr = Box::into_raw(Box::new(prekey_record)) as i64;

        Ok(prekey_record_ptr)
    }

    #[host_object(method as PreKeyRecord_Serialize)]
    pub fn PreKeyRecord_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let prekey_record: &PreKeyRecord = get_reference_handle(obj, rt)?;
        let serialized = prekey_record.serialize()?;

        Ok(serialize_bytes(rt, &serialized)?)
    }

    #[host_object(method as PublicKey_Compare)]
    pub fn PublicKey_Compare<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        key1: JsiValue<'rt>,
        key2: JsiValue<'rt>,
    ) -> anyhow::Result<i32> {
        let key1: &CurvePublicKey = get_reference_handle(key1, rt)?;
        let key2: &CurvePublicKey = get_reference_handle(key2, rt)?;

        Ok(key1.cmp(key2) as i32)
    }

    #[host_object(method as PublicKey_Deserialize)]
    pub fn PublicKey_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let public_key = CurvePublicKey::deserialize(&data)?;

        let public_key_ptr = Box::into_raw(Box::new(public_key)) as i64;
        Ok(public_key_ptr)
    }

    #[host_object(method as PublicKey_Equals)]
    pub fn PublicKey_Equals<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        lhs: JsiValue<'rt>,
        rhs: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let lhs: &CurvePublicKey = get_reference_handle(lhs, rt)?;
        let rhs: &CurvePublicKey = get_reference_handle(rhs, rt)?;

        Ok(lhs == rhs)
    }

    #[host_object(method as PublicKey_GetPublicKeyBytes)]
    pub fn PublicKey_GetPublicKeyBytes<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let public_key: &CurvePublicKey = get_reference_handle(obj, rt)?;

        Ok(serialize_bytes(rt, public_key.public_key_bytes()?)?)
    }

    #[host_object(method as PublicKey_Serialize)]
    pub fn PublicKey_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let public_key: &CurvePublicKey = get_reference_handle(obj, rt)?;

        Ok(serialize_bytes(rt, &public_key.serialize())?)
    }

    #[host_object(method as PublicKey_Verify)]
    pub fn PublicKey_Verify<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        key: JsiValue<'rt>,
        message: JsiValue<'rt>,
        signature: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let key: &CurvePublicKey = get_reference_handle(key, rt)?;
        let message = get_buffer(message, rt)?;
        let signature = get_buffer(signature, rt)?;

        Ok(key.verify_signature(&message, &signature)?)
    }

    #[host_object(method as SenderKeyMessage_Deserialize)]
    pub fn SenderKeyMessage_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(data, rt)?;
        let message = SenderKeyMessage::try_from(buffer.as_slice())?;
        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        Ok(message_ptr)
    }

    #[host_object(method as SenderKeyMessage_GetChainId)]
    pub fn SenderKeyMessage_GetChainId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let message: &SenderKeyMessage = get_reference_handle(obj, rt)?;
        Ok(message.chain_id())
    }

    #[host_object(method as SenderKeyMessage_GetCipherText)]
    pub fn SenderKeyMessage_GetCipherText<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &SenderKeyMessage = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, message.ciphertext())?)
    }

    #[host_object(method as SenderKeyMessage_GetDistributionId)]
    pub fn SenderKeyMessage_GetDistributionId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &SenderKeyMessage = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, message.distribution_id().as_bytes())?)
    }

    #[host_object(method as SenderKeyMessage_GetIteration)]
    pub fn SenderKeyMessage_GetIteration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let message: &SenderKeyMessage = get_reference_handle(obj, rt)?;
        Ok(message.iteration())
    }

    #[host_object(method as SenderKeyMessage_New)]
    pub fn SenderKeyMessage_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        message_version: JsiValue<'rt>,
        distribution_id: JsiValue<'rt>,
        chain_id: JsiValue<'rt>,
        iteration: JsiValue<'rt>,
        ciphertext: JsiValue<'rt>,
        private_key: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let message_version = get_number(message_version, rt)? as u8;
        let distribution_id = uuid::Uuid::from_slice(&get_buffer(distribution_id, rt)?)?;
        let chain_id = get_number(chain_id, rt)? as u32;
        let iteration = get_number(iteration, rt)? as u32;
        let ciphertext = get_buffer(ciphertext, rt)?.into_boxed_slice();
        let private_key: &CurvePrivateKey = get_reference_handle(private_key, rt)?;

        let mut rng = rand::rngs::OsRng;
        let message = SenderKeyMessage::new(
            message_version,
            distribution_id,
            chain_id,
            iteration,
            ciphertext,
            &mut rng,
            private_key,
        )?;

        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        Ok(message_ptr)
    }

    #[host_object(method as SenderKeyMessage_Serialize)]
    pub fn SenderKeyMessage_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &SenderKeyMessage = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, message.serialized())?)
    }

    #[host_object(method as SenderKeyMessage_VerifySignature)]
    pub fn SenderKeyMessage_VerifySignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        skm: JsiValue<'rt>,
        pubkey: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let message: &SenderKeyMessage = get_reference_handle(skm, rt)?;
        let pubkey: &CurvePublicKey = get_reference_handle(pubkey, rt)?;
        Ok(message.verify_signature(pubkey)?)
    }

    #[host_object(method as SenderKeyRecord_Deserialize)]
    pub fn SenderKeyRecord_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(data, rt)?;
        let record = SenderKeyRecord::deserialize(buffer.as_slice())?;
        let record_ptr = Box::into_raw(Box::new(record)) as i64;
        Ok(record_ptr)
    }

    #[host_object(method as SenderKeyRecord_Serialize)]
    pub fn SenderKeyRecord_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let record: &SenderKeyRecord = get_reference_handle(obj, rt)?;

        Ok(serialize_bytes(rt, &record.serialize()?)?)
    }

    #[host_object(method as SealedSenderDecryptionResult_GetDeviceId)]
    pub fn SealedSenderDecryptionResult_GetDeviceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let result: &SealedSenderDecryptionResult = get_reference_handle(obj, rt)?;
        Ok(result.device_id()?.into())
    }

    #[host_object(method as SealedSenderDecryptionResult_GetSenderE164)]
    pub fn SealedSenderDecryptionResult_GetSenderE164<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let result: &SealedSenderDecryptionResult = get_reference_handle(obj, rt)?;
        match result.sender_e164()? {
            Some(e164) => Ok(JsiString::new(e164, rt).into_value(rt)),
            None => Ok(JsiValue::new_null()),
        }
    }

    #[host_object(method as SealedSenderDecryptionResult_GetSenderUuid)]
    pub fn SealedSenderDecryptionResult_GetSenderUuid<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<String> {
        let result: &SealedSenderDecryptionResult = get_reference_handle(obj, rt)?;
        Ok(result.sender_uuid()?.to_string())
    }

    #[host_object(method as SealedSenderDecryptionResult_Message)]
    pub fn SealedSenderDecryptionResult_Message<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let result: &SealedSenderDecryptionResult = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, result.message()?)?)
    }

    #[host_object(method as SealedSenderMultiRecipientMessage_Parse)]
    pub fn SealedSenderMultiRecipientMessage_Parse<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let buffer = get_buffer(buffer, rt)?;
        let message = SealedSenderV2SentMessage::parse(buffer.as_slice())?;
        let message_ptr = Box::into_raw(Box::new(message)) as i64;
        Ok(message_ptr)
    }

    #[host_object(method as SealedSender_DecryptMessage)]
    pub fn SealedSender_DecryptMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        message: JsiValue<'rt>,
        trust_root: JsiValue<'rt>,
        timestamp: JsiValue<'rt>,
        local_e164: JsiValue<'rt>,
        local_uuid: JsiValue<'rt>,
        local_device_id: JsiValue<'rt>,
        session_store: JsiValue<'rt>,
        identity_store: JsiValue<'rt>,
        prekey_store: JsiValue<'rt>,
        signed_prekey_store: JsiValue<'rt>,
        kyber_prekey_store: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let message = get_buffer(message, rt)?;
        let trust_root: &CurvePublicKey = get_reference_handle(trust_root, rt)?;
        let timestamp = Timestamp::from_epoch_millis(get_number(timestamp, rt)? as u64);
        let local_e164 = get_string(local_e164, rt).ok();
        let local_uuid = get_string(local_uuid, rt)?;
        let local_device_id = DeviceId::from(get_number(local_device_id, rt)? as u32);
        let mut session_store = JSISessionStore::new(session_store, clone_runtime_handle(rt))?;
        let mut identity_store =
            JSIIdentityKeyStore::new(identity_store, clone_runtime_handle(rt))?;
        let mut prekey_store = JSIPreKeyStore::new(prekey_store, clone_runtime_handle(rt))?;
        let mut signed_prekey_store =
            JSISignedPreKeyStore::new(signed_prekey_store, clone_runtime_handle(rt))?;
        let mut kyber_prekey_store =
            JSIKyberPreKeyStore::new(kyber_prekey_store, clone_runtime_handle(rt))?;

        let result = sealed_sender_decrypt(
            &message,
            trust_root,
            timestamp,
            local_e164,
            local_uuid,
            local_device_id,
            &mut identity_store,
            &mut session_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut kyber_prekey_store,
        );
        let result = executor::block_on(result)?;

        let result_ptr = Box::into_raw(Box::new(result)) as i64;
        Ok(result_ptr)
    }

    #[host_object(method as SealedSender_DecryptToUsmc)]
    pub fn SealedSender_DecryptToUsmc<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        ctext: JsiValue<'rt>,
        identity_store: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let ctext = get_buffer(ctext, rt)?;
        let mut identity_store =
            JSIIdentityKeyStore::new(identity_store, clone_runtime_handle(rt))?;

        let result = sealed_sender_decrypt_to_usmc(&ctext, &mut identity_store);
        let result = executor::block_on(result)?;
        let result_ptr = Box::into_raw(Box::new(result)) as i64;
        Ok(result_ptr)
    }

    #[host_object(method as SealedSender_Encrypt)]
    pub fn SealedSender_Encrypt<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        destination: JsiValue<'rt>,
        content: JsiValue<'rt>,
        identity_key_store: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let destination: &ProtocolAddress = get_reference_handle(destination, rt)?;
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(content, rt)?;
        let mut identity_key_store =
            JSIIdentityKeyStore::new(identity_key_store, clone_runtime_handle(rt))?;
        let mut rng = rand::rngs::OsRng;

        let encrypted_message = sealed_sender_encrypt_from_usmc(
            destination,
            content,
            &mut identity_key_store,
            &mut rng,
        );
        let encrypted_message = executor::block_on(encrypted_message)?;

        Ok(serialize_bytes(rt, &encrypted_message)?)
    }

    #[host_object(method as SealedSender_MultiRecipientEncrypt)]
    pub fn SealedSender_MultiRecipientEncrypt<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        recipients: JsiValue<'rt>,
        recipient_sessions: JsiValue<'rt>,
        excluded_recipients: JsiValue<'rt>,
        content: JsiValue<'rt>,
        identity_key_store: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let recipients: Vec<&ProtocolAddress> = get_array_of_handles(recipients, rt)?;
        let recipient_sessions: Vec<&SessionRecord> = get_array_of_handles(recipient_sessions, rt)?;
        let excluded_recipients = get_buffer(excluded_recipients, rt)?;
        let excluded_recipients = ServiceIdSequence::parse(&excluded_recipients);
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(content, rt)?;
        let mut identity_key_store =
            JSIIdentityKeyStore::new(identity_key_store, clone_runtime_handle(rt))?;
        let mut rng = rand::rngs::OsRng;

        let encrypted_message = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &recipient_sessions,
            excluded_recipients,
            content,
            &mut identity_key_store,
            &mut rng,
        );
        let encrypted_message = executor::block_on(encrypted_message)?;

        Ok(serialize_bytes(rt, &encrypted_message)?)
    }

    #[host_object(method as SealedSender_MultiRecipientMessageForSingleRecipient)]
    pub fn SealedSender_MultiRecipientMessageForSingleRecipient<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        encoded_multi_recipient_message: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let encoded_message = get_buffer(encoded_multi_recipient_message, rt)?;

        let messages = SealedSenderV2SentMessage::parse(&encoded_message)?;
        if messages.recipients.len() != 1 {
            return Err(anyhow!("Expected exactly one recipient"));
        }
        let result = messages
            .received_message_parts_for_recipient(&messages.recipients[0])
            .as_ref()
            .concat();

        Ok(serialize_bytes(rt, &result)?)
    }

    #[host_object(method as ServiceId_ParseFromServiceIdBinary)]
    pub fn ServiceId_ParseFromServiceIdBinary<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        input: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let input_bytes = get_buffer(input, rt)?;
        let service_id = ServiceId::parse_from_service_id_binary(&input_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid binary format for ServiceId"))?;

        let service_id_bytes = service_id.service_id_binary();
        Ok(serialize_bytes(rt, &service_id_bytes)?)
    }

    #[host_object(method as ServiceId_ParseFromServiceIdString)]
    pub fn ServiceId_ParseFromServiceIdString<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        input: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let input_str = get_string(input, rt)?;
        let service_id = ServiceId::parse_from_service_id_string(&input_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid string format for ServiceId"))?;

        let service_id_bytes = service_id.service_id_binary();
        Ok(serialize_bytes(rt, &service_id_bytes)?)
    }

    #[host_object(method as ServiceId_ServiceIdBinary)]
    pub fn ServiceId_ServiceIdBinary<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        value: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let input_bytes = get_buffer(value, rt)?;
        let service_id = ServiceId::parse_from_service_id_binary(&input_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid binary format for ServiceId"))?;

        let service_id_bytes = service_id.service_id_binary();
        Ok(serialize_bytes(rt, &service_id_bytes)?)
    }

    #[host_object(method as ServiceId_ServiceIdLog)]
    pub fn ServiceId_ServiceIdLog<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        value: JsiValue<'rt>,
    ) -> anyhow::Result<String> {
        let input_bytes = get_buffer(value, rt)?;
        let service_id = ServiceId::parse_from_service_id_binary(&input_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid binary format for ServiceId"))?;

        Ok(format!("{:?}", service_id))
    }

    #[host_object(method as ServiceId_ServiceIdString)]
    pub fn ServiceId_ServiceIdString<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        value: JsiValue<'rt>,
    ) -> anyhow::Result<String> {
        let input_bytes = get_buffer(value, rt)?;
        let service_id = ServiceId::parse_from_service_id_binary(&input_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid binary format for ServiceId"))?;

        Ok(service_id.service_id_string())
    }

    #[host_object(method as SessionBuilder_ProcessPreKeyBundle)]
    pub fn SessionBuilder_ProcessPreKeyBundle<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bundle: JsiValue<'rt>,
        protocol_address: JsiValue<'rt>,
        session_store: JsiValue<'rt>,
        identity_key_store: JsiValue<'rt>,
        now: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let bundle: &PreKeyBundle = get_reference_handle(bundle, rt)?;
        let protocol_address: &ProtocolAddress = get_reference_handle(protocol_address, rt)?;
        let mut session_store = JSISessionStore::new(session_store, clone_runtime_handle(rt))?;
        let mut identity_key_store =
            JSIIdentityKeyStore::new(identity_key_store, clone_runtime_handle(rt))?;
        let now = Timestamp::from_epoch_millis(get_number(now, rt)? as u64);
        let mut rng = rand::rngs::OsRng;

        executor::block_on(process_prekey_bundle(
            protocol_address,
            &mut session_store,
            &mut identity_key_store,
            bundle,
            now.into(),
            &mut rng,
        ))?;

        Ok(())
    }

    #[host_object(method as SessionCipher_DecryptPreKeySignalMessage)]
    pub fn SessionCipher_DecryptPreKeySignalMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        message: JsiValue<'rt>,
        protocol_address: JsiValue<'rt>,
        session_store: JsiValue<'rt>,
        identity_key_store: JsiValue<'rt>,
        prekey_store: JsiValue<'rt>,
        signed_prekey_store: JsiValue<'rt>,
        kyber_prekey_store: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &PreKeySignalMessage = get_reference_handle(message, rt)?;
        let protocol_address: &ProtocolAddress = get_reference_handle(protocol_address, rt)?;
        let mut session_store = JSISessionStore::new(session_store, clone_runtime_handle(rt))?;
        let mut identity_key_store =
            JSIIdentityKeyStore::new(identity_key_store, clone_runtime_handle(rt))?;
        let mut prekey_store = JSIPreKeyStore::new(prekey_store, clone_runtime_handle(rt))?;
        let mut signed_prekey_store =
            JSISignedPreKeyStore::new(signed_prekey_store, clone_runtime_handle(rt))?;
        let mut kyber_prekey_store =
            JSIKyberPreKeyStore::new(kyber_prekey_store, clone_runtime_handle(rt))?;
        let mut rng = rand::rngs::OsRng;

        let decrypted = executor::block_on(message_decrypt_prekey(
            message,
            protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut kyber_prekey_store,
            &mut rng,
        ))?;

        Ok(serialize_bytes(rt, &decrypted)?)
    }

    #[host_object(method as SessionCipher_DecryptSignalMessage)]
    pub fn SessionCipher_DecryptSignalMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        message: JsiValue<'rt>,
        protocol_address: JsiValue<'rt>,
        session_store: JsiValue<'rt>,
        identity_key_store: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let message: &SignalMessage = get_reference_handle(message, rt)?;
        let protocol_address: &ProtocolAddress = get_reference_handle(protocol_address, rt)?;
        let mut session_store = JSISessionStore::new(session_store, clone_runtime_handle(rt))?;
        let mut identity_key_store =
            JSIIdentityKeyStore::new(identity_key_store, clone_runtime_handle(rt))?;
        let mut rng = rand::rngs::OsRng;

        let decrypted = executor::block_on(message_decrypt_signal(
            message,
            protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut rng,
        ))?;

        Ok(serialize_bytes(rt, &decrypted)?)
    }

    #[host_object(method as SessionCipher_EncryptMessage)]
    pub fn SessionCipher_EncryptMessage<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        ptext: JsiValue<'rt>,
        protocol_address: JsiValue<'rt>,
        session_store: JsiValue<'rt>,
        identity_key_store: JsiValue<'rt>,
        now: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let plaintext = get_buffer(ptext, rt)?;
        let protocol_address: &ProtocolAddress = get_reference_handle(protocol_address, rt)?;
        let mut session_store = JSISessionStore::new(session_store, clone_runtime_handle(rt))?;
        let mut identity_key_store =
            JSIIdentityKeyStore::new(identity_key_store, clone_runtime_handle(rt))?;
        let now = Timestamp::from_epoch_millis(get_number(now, rt)? as u64);

        let encrypted_message = executor::block_on(message_encrypt(
            &plaintext,
            protocol_address,
            &mut session_store,
            &mut identity_key_store,
            now.into(),
        ))?;

        let pointer = Box::into_raw(Box::new(encrypted_message)) as i64;

        Ok(pointer)
    }

    #[host_object(method as SessionRecord_ArchiveCurrentState)]
    pub fn SessionRecord_ArchiveCurrentState<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        session_record: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let session_record: &mut SessionRecord = get_reference_handle_mut(session_record, rt)?;
        session_record.archive_current_state()?;
        Ok(())
    }

    #[host_object(method as SessionRecord_CurrentRatchetKeyMatches)]
    pub fn SessionRecord_CurrentRatchetKeyMatches<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        session_record: JsiValue<'rt>,
        key: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let session_record: &SessionRecord = get_reference_handle(session_record, rt)?;
        let key: &CurvePublicKey = get_reference_handle(key, rt)?;
        Ok(session_record.current_ratchet_key_matches(key)?)
    }

    #[host_object(method as SessionRecord_Deserialize)]
    pub fn SessionRecord_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let session_record = SessionRecord::deserialize(&data)?;
        let session_record_ptr = Box::into_raw(Box::new(session_record)) as i64;
        Ok(session_record_ptr)
    }

    #[host_object(method as SessionRecord_GetLocalRegistrationId)]
    pub fn SessionRecord_GetLocalRegistrationId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let session_record: &SessionRecord = get_reference_handle(obj, rt)?;
        Ok(session_record.local_registration_id()?)
    }

    #[host_object(method as SessionRecord_GetRemoteRegistrationId)]
    pub fn SessionRecord_GetRemoteRegistrationId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let session_record: &SessionRecord = get_reference_handle(obj, rt)?;
        Ok(session_record.remote_registration_id()?)
    }

    #[host_object(method as SessionRecord_HasUsableSenderChain)]
    pub fn SessionRecord_HasUsableSenderChain<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        session_record: JsiValue<'rt>,
        now: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let session_record: &SessionRecord = get_reference_handle(session_record, rt)?;
        let now = Timestamp::from_epoch_millis(get_number(now, rt)? as u64).into();
        Ok(session_record.has_usable_sender_chain(now)?)
    }

    #[host_object(method as SessionRecord_Serialize)]
    pub fn SessionRecord_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let session_record: &SessionRecord = get_reference_handle(obj, rt)?;
        let serialized = session_record.serialize()?;
        Ok(serialize_bytes(rt, &serialized)?)
    }

    #[host_object(method as SignalMessage_Deserialize)]
    pub fn SignalMessage_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let signal_message = SignalMessage::try_from(data.as_slice())?;
        let signal_message_ptr = Box::into_raw(Box::new(signal_message)) as i64;
        Ok(signal_message_ptr)
    }

    #[host_object(method as SignalMessage_GetBody)]
    pub fn SignalMessage_GetBody<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let signal_message: &SignalMessage = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, signal_message.body())?)
    }

    #[host_object(method as SignalMessage_GetCounter)]
    pub fn SignalMessage_GetCounter<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let signal_message: &SignalMessage = get_reference_handle(obj, rt)?;
        Ok(signal_message.counter())
    }

    #[host_object(method as SignalMessage_GetMessageVersion)]
    pub fn SignalMessage_GetMessageVersion<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u8> {
        let signal_message: &SignalMessage = get_reference_handle(obj, rt)?;
        Ok(signal_message.message_version())
    }

    #[host_object(method as SignalMessage_GetSerialized)]
    pub fn SignalMessage_GetSerialized<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let signal_message: &SignalMessage = get_reference_handle(obj, rt)?;
        Ok(serialize_bytes(rt, signal_message.serialized())?)
    }

    #[host_object(method as SignalMessage_New)]
    pub fn SignalMessage_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        message_version: JsiValue<'rt>,
        mac_key: JsiValue<'rt>,
        sender_ratchet_key: JsiValue<'rt>,
        counter: JsiValue<'rt>,
        previous_counter: JsiValue<'rt>,
        ciphertext: JsiValue<'rt>,
        sender_identity_key: JsiValue<'rt>,
        receiver_identity_key: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let message_version = get_number(message_version, rt)? as u8;
        let mac_key = get_buffer(mac_key, rt)?;
        let sender_ratchet_key: &CurvePublicKey = get_reference_handle(sender_ratchet_key, rt)?;
        let counter = get_number(counter, rt)? as u32;
        let previous_counter = get_number(previous_counter, rt)? as u32;
        let ciphertext = get_buffer(ciphertext, rt)?;
        let sender_identity_key: &IdentityKey = get_reference_handle(sender_identity_key, rt)?;
        let receiver_identity_key: &IdentityKey = get_reference_handle(receiver_identity_key, rt)?;

        let signal_message = SignalMessage::new(
            message_version,
            &mac_key,
            sender_ratchet_key.clone(),
            counter,
            previous_counter,
            &ciphertext,
            sender_identity_key,
            receiver_identity_key,
        )?;

        let signal_message_ptr = Box::into_raw(Box::new(signal_message)) as i64;
        Ok(signal_message_ptr)
    }

    #[host_object(method as SignalMessage_VerifyMac)]
    pub fn SignalMessage_VerifyMac<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        msg: JsiValue<'rt>,
        sender_identity_key: JsiValue<'rt>,
        receiver_identity_key: JsiValue<'rt>,
        mac_key: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let signal_message: &SignalMessage = get_reference_handle(msg, rt)?;
        let sender_identity_key: &IdentityKey = get_reference_handle(sender_identity_key, rt)?;
        let receiver_identity_key: &IdentityKey = get_reference_handle(receiver_identity_key, rt)?;
        let mac_key = get_buffer(mac_key, rt)?;

        Ok(signal_message.verify_mac(sender_identity_key, receiver_identity_key, &mac_key)?)
    }

    #[host_object(method as SignedPreKeyRecord_Deserialize)]
    pub fn SignedPreKeyRecord_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;
        let signed_pre_key_record = SignedPreKeyRecord::deserialize(&data)?;
        let signed_pre_key_record_ptr = Box::into_raw(Box::new(signed_pre_key_record)) as i64;
        Ok(signed_pre_key_record_ptr)
    }

    #[host_object(method as SignedPreKeyRecord_GetId)]
    pub fn SignedPreKeyRecord_GetId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let signed_pre_key_record: &SignedPreKeyRecord = get_reference_handle(obj, rt)?;
        let id: SignedPreKeyId = signed_pre_key_record.id()?;
        Ok(id.into())
    }

    #[host_object(method as SignedPreKeyRecord_GetPrivateKey)]
    pub fn SignedPreKeyRecord_GetPrivateKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let signed_pre_key_record: &SignedPreKeyRecord = get_reference_handle(obj, rt)?;
        let private_key = signed_pre_key_record.private_key()?;
        let private_key_ptr = Box::into_raw(Box::new(private_key)) as i64;
        Ok(private_key_ptr)
    }

    #[host_object(method as SignedPreKeyRecord_GetPublicKey)]
    pub fn SignedPreKeyRecord_GetPublicKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let signed_pre_key_record: &SignedPreKeyRecord = get_reference_handle(obj, rt)?;
        let public_key = signed_pre_key_record.public_key()?;
        let public_key_ptr = Box::into_raw(Box::new(public_key)) as i64;
        Ok(public_key_ptr)
    }

    #[host_object(method as SignedPreKeyRecord_GetSignature)]
    pub fn SignedPreKeyRecord_GetSignature<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let signed_pre_key_record: &SignedPreKeyRecord = get_reference_handle(obj, rt)?;
        let signature = signed_pre_key_record.signature()?;
        Ok(serialize_bytes(rt, &signature)?)
    }

    #[host_object(method as SignedPreKeyRecord_GetTimestamp)]
    pub fn SignedPreKeyRecord_GetTimestamp<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let signed_pre_key_record: &SignedPreKeyRecord = get_reference_handle(obj, rt)?;
        let timestamp = signed_pre_key_record.timestamp()?;
        Ok(timestamp.epoch_millis() as u64)
    }

    #[host_object(method as SignedPreKeyRecord_New)]
    pub fn SignedPreKeyRecord_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        id: JsiValue<'rt>,
        timestamp: JsiValue<'rt>,
        pub_key: JsiValue<'rt>,
        priv_key: JsiValue<'rt>,
        signature: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let id = SignedPreKeyId::from(get_number(id, rt)? as u32);
        let timestamp = Timestamp::from_epoch_millis(get_number(timestamp, rt)? as u64);
        let pub_key: &CurvePublicKey = get_reference_handle(pub_key, rt)?;
        let priv_key: &CurvePrivateKey = get_reference_handle(priv_key, rt)?;
        let signature = get_buffer(signature, rt)?;

        let key_pair = CurveKeyPair::new(pub_key.clone(), priv_key.clone());
        let signed_pre_key_record = SignedPreKeyRecord::new(id, timestamp, &key_pair, &signature);

        let signed_pre_key_record_ptr = Box::into_raw(Box::new(signed_pre_key_record)) as i64;
        Ok(signed_pre_key_record_ptr)
    }

    #[host_object(method as SignedPreKeyRecord_Serialize)]
    pub fn SignedPreKeyRecord_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let signed_pre_key_record: &SignedPreKeyRecord = get_reference_handle(obj, rt)?;
        let serialized = signed_pre_key_record.serialize()?;

        Ok(serialize_bytes(rt, &serialized)?)
    }

    #[host_object(method as IdentityKeyPair_Deserialize)]
    pub fn IdentityKeyPair_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let data = get_buffer(buffer, rt)?;
        let identity_key_pair = IdentityKeyPair::try_from(data.as_slice())?;

        let public_key_ptr = Box::into_raw(Box::new(identity_key_pair.public_key().clone())) as i64;
        let private_key_ptr =
            Box::into_raw(Box::new(identity_key_pair.private_key().clone())) as i64;

        let mut result = jsi::JsiObject::new(rt);

        result.set(
            PropName::new("publicKey", rt),
            &JsiValue::new_number(public_key_ptr as f64),
            rt,
        );

        result.set(
            PropName::new("privateKey", rt),
            &JsiValue::new_number(private_key_ptr as f64),
            rt,
        );

        Ok(result.into_value(rt))
    }

    #[host_object(method as IdentityKeyPair_Serialize)]
    pub fn IdentityKeyPair_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        public_key: JsiValue<'rt>,
        private_key: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let public_key: &CurvePublicKey = get_reference_handle(public_key, rt)?;
        let private_key: &CurvePrivateKey = get_reference_handle(private_key, rt)?;

        let identity_key = IdentityKey::from(public_key.clone());
        let identity_key_pair = IdentityKeyPair::new(identity_key, private_key.clone());

        let serialized = identity_key_pair.serialize();
        Ok(serialize_bytes(rt, &serialized)?)
    }

    #[host_object(method as IdentityKeyPair_SignAlternateIdentity)]
    pub fn IdentityKeyPair_SignAlternateIdentity<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        public_key: JsiValue<'rt>,
        private_key: JsiValue<'rt>,
        other_identity: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let public_key: &CurvePublicKey = get_reference_handle(public_key, rt)?;
        let private_key: &CurvePrivateKey = get_reference_handle(private_key, rt)?;
        let other_identity: &CurvePublicKey = get_reference_handle(other_identity, rt)?;

        let identity_key = IdentityKey::from(public_key.clone());
        let identity_key_pair = IdentityKeyPair::new(identity_key, private_key.clone());

        let mut rng = rand::rngs::OsRng;
        let signature = identity_key_pair
            .sign_alternate_identity(&IdentityKey::from(other_identity.clone()), &mut rng)?;

        Ok(serialize_bytes(rt, &signature)?)
    }

    #[host_object(method as IdentityKey_VerifyAlternateIdentity)]
    pub fn IdentityKey_VerifyAlternateIdentity<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        public_key: JsiValue<'rt>,
        other_identity: JsiValue<'rt>,
        signature: JsiValue<'rt>,
    ) -> anyhow::Result<bool> {
        let public_key: &CurvePublicKey = get_reference_handle(public_key, rt)?;
        let other_identity: &CurvePublicKey = get_reference_handle(other_identity, rt)?;
        let signature = get_buffer(signature, rt)?;

        let identity_key = IdentityKey::from(public_key.clone());
        let other_identity_key = IdentityKey::from(other_identity.clone());

        Ok(identity_key.verify_alternate_identity(&other_identity_key, &signature)?)
    }

    #[host_object(method as GroupSendDerivedKeyPair_CheckValidContents)]
    pub fn GroupSendDerivedKeyPair_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let bytes = get_buffer(bytes, rt)?;
        zkgroup::deserialize::<GroupSendDerivedKeyPair>(&bytes)?;
        Ok(())
    }

    #[host_object(method as GroupSendDerivedKeyPair_ForExpiration)]
    pub fn GroupSendDerivedKeyPair_ForExpiration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        expiration: JsiValue<'rt>,
        server_params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let expiration = get_number(expiration, rt)? as u64;
        let expiration = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(expiration);
        let server_params: &ServerSecretParams = get_reference_handle(server_params, rt)?;
        let derived_key_pair = GroupSendDerivedKeyPair::for_expiration(expiration, server_params);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&derived_key_pair))?)
    }

    #[host_object(method as GroupSendEndorsement_CheckValidContents)]
    pub fn GroupSendEndorsement_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let bytes = get_buffer(bytes, rt)?;
        zkgroup::deserialize::<GroupSendEndorsement>(&bytes)?;
        Ok(())
    }

    #[host_object(method as GroupSendEndorsement_Combine)]
    pub fn GroupSendEndorsement_Combine<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        endorsements: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let endorsements = get_array(endorsements, rt)?
            .into_iter()
            .map(|e| get_buffer(e, rt))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let combined = GroupSendEndorsement::combine(
            endorsements
                .iter()
                .map(|e| zkgroup::deserialize::<GroupSendEndorsement>(e))
                .filter_map(Result::ok),
        );
        Ok(serialize_bytes(rt, &zkgroup::serialize(&combined))?)
    }

    #[host_object(method as GroupSendEndorsement_Remove)]
    pub fn GroupSendEndorsement_Remove<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        endorsement: JsiValue<'rt>,
        to_remove: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let endorsement =
            zkgroup::deserialize::<GroupSendEndorsement>(&get_buffer(endorsement, rt)?)?;
        let to_remove = zkgroup::deserialize::<GroupSendEndorsement>(&get_buffer(to_remove, rt)?)?;
        let result = endorsement.remove(&to_remove);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&result))?)
    }

    #[host_object(method as GroupSendEndorsement_ToToken)]
    pub fn GroupSendEndorsement_ToToken<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        endorsement: JsiValue<'rt>,
        group_params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let endorsement =
            zkgroup::deserialize::<GroupSendEndorsement>(&get_buffer(endorsement, rt)?)?;
        let group_params =
            zkgroup::deserialize::<GroupSecretParams>(&get_buffer(group_params, rt)?)?;

        let token = endorsement.to_token(&group_params);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&token))?)
    }

    #[host_object(method as GroupSendEndorsementsResponse_CheckValidContents)]
    pub fn GroupSendEndorsementsResponse_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let bytes = get_buffer(bytes, rt)?;
        zkgroup::deserialize::<GroupSendEndorsementsResponse>(&bytes)?;
        Ok(())
    }

    #[host_object(method as GroupSendEndorsementsResponse_GetExpiration)]
    pub fn GroupSendEndorsementsResponse_GetExpiration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        response_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let response = zkgroup::deserialize::<GroupSendEndorsementsResponse>(&get_buffer(
            response_bytes,
            rt,
        )?)?;
        Ok(response.expiration().epoch_seconds() as u64)
    }

    #[host_object(method as GroupSendEndorsementsResponse_IssueDeterministic)]
    pub fn GroupSendEndorsementsResponse_IssueDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        concatenated_ciphertexts: JsiValue<'rt>,
        key_pair: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let ciphertexts = get_buffer(concatenated_ciphertexts, rt)?;
        assert!(ciphertexts.len() % UUID_CIPHERTEXT_LEN == 0);

        let user_id_ciphertexts = ciphertexts
            .chunks_exact(UUID_CIPHERTEXT_LEN)
            .map(|chunk| zkgroup::deserialize::<UuidCiphertext>(chunk))
            .filter_map(Result::ok);

        let key_pair = zkgroup::deserialize::<GroupSendDerivedKeyPair>(&get_buffer(key_pair, rt)?)?;
        let randomness: [u8; RANDOMNESS_LEN] = get_buffer(randomness, rt)?
            .try_into()
            .map_err(|_| anyhow!("Randomness buffer has invalid length: {}", RANDOMNESS_LEN))?;

        let response =
            GroupSendEndorsementsResponse::issue(user_id_ciphertexts, &key_pair, randomness);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&response))?)
    }

    #[host_object(method as GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts)]
    pub fn GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        response_bytes: JsiValue<'rt>,
        concatenated_ciphertexts: JsiValue<'rt>,
        local_user_ciphertext: JsiValue<'rt>,
        now: JsiValue<'rt>,
        server_params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiArray<'rt>> {
        let response = zkgroup::deserialize::<GroupSendEndorsementsResponse>(&get_buffer(
            response_bytes,
            rt,
        )?)?;
        let concatenated_ciphertexts = get_buffer(concatenated_ciphertexts, rt)?;
        assert!(concatenated_ciphertexts.len() % UUID_CIPHERTEXT_LEN == 0);

        let local_user_ciphertext = get_buffer(local_user_ciphertext, rt)?;
        let local_user_index = concatenated_ciphertexts
            .chunks_exact(UUID_CIPHERTEXT_LEN)
            .position(|chunk| chunk == local_user_ciphertext)
            .ok_or(anyhow!("Local user not found in member list"))?;

        let user_id_ciphertexts = concatenated_ciphertexts
            .chunks_exact(UUID_CIPHERTEXT_LEN)
            .map(|chunk| zkgroup::deserialize::<UuidCiphertext>(chunk))
            .filter_map(Result::ok);

        let now = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(now, rt)? as u64,
        );
        let server_params: &ServerPublicParams = get_reference_handle(server_params, rt)?;

        let endorsements =
            response.receive_with_ciphertexts(user_id_ciphertexts, now, server_params)?;

        let combined_endorsement = GroupSendEndorsement::combine(
            endorsements[..local_user_index]
                .iter()
                .chain(&endorsements[local_user_index + 1..])
                .map(|e| e.decompressed),
        );

        let results: Box<[Vec<u8>]> = endorsements
            .iter()
            .map(|received| received.compressed)
            .chain([combined_endorsement.compress()])
            .map(|e| zkgroup::serialize(&e))
            .collect();

        let mut array = jsi::JsiArray::new(results.len() as usize, rt);

        for (i, result) in results.iter().enumerate() {
            array.set(i as usize, &serialize_bytes(rt, result)?, rt);
        }

        Ok(array)
    }

    #[host_object(method as GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds)]
    pub fn GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        response_bytes: JsiValue<'rt>,
        group_members: JsiValue<'rt>,
        local_user: JsiValue<'rt>,
        now: JsiValue<'rt>,
        group_params: JsiValue<'rt>,
        server_params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiArray<'rt>> {
        let response = zkgroup::deserialize::<GroupSendEndorsementsResponse>(&get_buffer(
            response_bytes,
            rt,
        )?)?;
        let group_members = get_buffer(group_members, rt)?;
        let group_members = ServiceIdSequence::parse(&group_members);
        let local_user = ServiceId::parse_from_service_id_binary(&get_buffer(local_user, rt)?)
            .ok_or(anyhow!("Invalid local user"))?;
        let now = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(now, rt)? as u64,
        );
        let group_params =
            zkgroup::deserialize::<GroupSecretParams>(&get_buffer(group_params, rt)?)?;
        let server_params = get_reference_handle::<ServerPublicParams>(server_params, rt)?;

        let endorsements =
            response.receive_with_service_ids(group_members, now, &group_params, server_params)?;

        let local_user_index = group_members
            .into_iter()
            .position(|next| next == local_user)
            .ok_or(anyhow!("Local user not found in member list"))?;

        let combined_endorsement = GroupSendEndorsement::combine(
            endorsements[..local_user_index]
                .iter()
                .chain(&endorsements[local_user_index + 1..])
                .map(|received| received.decompressed),
        );

        let results: Box<[Vec<u8>]> = endorsements
            .iter()
            .map(|received| received.compressed)
            .chain([combined_endorsement.compress()])
            .map(|e| zkgroup::serialize(&e))
            .collect();

        let mut array = jsi::JsiArray::new(results.len() as usize, rt);
        for (i, result) in results.iter().enumerate() {
            array.set(i as usize, &serialize_bytes(rt, result)?, rt);
        }

        Ok(array)
    }

    #[host_object(method as GroupSendFullToken_CheckValidContents)]
    pub fn GroupSendFullToken_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let bytes = get_buffer(bytes, rt)?;
        zkgroup::deserialize::<GroupSendFullToken>(&bytes)?;
        Ok(())
    }

    #[host_object(method as GroupSendFullToken_GetExpiration)]
    pub fn GroupSendFullToken_GetExpiration<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        token: JsiValue<'rt>,
    ) -> anyhow::Result<u64> {
        let token = zkgroup::deserialize::<GroupSendFullToken>(&get_buffer(token, rt)?)?;
        Ok(token.expiration().epoch_seconds() as u64)
    }

    #[host_object(method as GroupSendFullToken_Verify)]
    pub fn GroupSendFullToken_Verify<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        token: JsiValue<'rt>,
        user_ids: JsiValue<'rt>,
        now: JsiValue<'rt>,
        key_pair: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let token = zkgroup::deserialize::<GroupSendFullToken>(&get_buffer(token, rt)?)?;
        let user_ids = get_buffer(user_ids, rt)?;
        let user_ids = ServiceIdSequence::parse(&user_ids);
        let now = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(
            get_number(now, rt)? as u64,
        );
        let key_pair = zkgroup::deserialize::<GroupSendDerivedKeyPair>(&get_buffer(key_pair, rt)?)?;

        token.verify(user_ids, now, &key_pair)?;
        Ok(())
    }

    #[host_object(method as GroupSendToken_CheckValidContents)]
    pub fn GroupSendToken_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let bytes = get_buffer(bytes, rt)?;
        zkgroup::deserialize::<GroupSendToken>(&bytes)?;
        Ok(())
    }

    #[host_object(method as GroupSendToken_ToFullToken)]
    pub fn GroupSendToken_ToFullToken<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        token: JsiValue<'rt>,
        expiration: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let token = zkgroup::deserialize::<GroupSendToken>(&get_buffer(token, rt)?)?;
        let expiration = zkgroup::common::simple_types::Timestamp::from_epoch_seconds(get_number(
            expiration, rt,
        )?
            as u64);

        let full_token = token.into_full_token(expiration);
        Ok(serialize_bytes(rt, &zkgroup::serialize(&full_token))?)
    }

    #[host_object(method as HKDF_DeriveSecrets)]
    pub fn HKDF_DeriveSecrets<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        output_length: JsiValue<'rt>,
        ikm: JsiValue<'rt>,
        label: JsiValue<'rt>,
        salt: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let output_length = get_number(output_length, rt)? as u32;

        let ikm = get_buffer(ikm, rt)?;

        let label = if label.is_null() || label.is_undefined() {
            Vec::new()
        } else {
            get_buffer(label, rt)?
        };

        let salt = if salt.is_null() || salt.is_undefined() {
            Vec::new()
        } else {
            get_buffer(salt, rt)?
        };

        let mut buffer = vec![0; output_length as usize];

        hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm)
            .expand(&label, &mut buffer)
            .map_err(|_| anyhow::anyhow!("Output length too long: {}", output_length))?;

        Ok(serialize_bytes(rt, &buffer)?)
    }

    #[host_object(method as GenericServerPublicParams_CheckValidContents)]
    pub fn GenericServerPublicParams_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let params_bytes = get_buffer(params_bytes, rt)?;

        zkgroup::deserialize::<GenericServerPublicParams>(&params_bytes)?;

        Ok(())
    }

    #[host_object(method as GenericServerSecretParams_CheckValidContents)]
    pub fn GenericServerSecretParams_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let params_bytes = get_buffer(params_bytes, rt)?;

        zkgroup::deserialize::<GenericServerSecretParams>(&params_bytes)?;

        Ok(())
    }

    #[host_object(method as GenericServerSecretParams_GenerateDeterministic)]
    pub fn GenericServerSecretParams_GenerateDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        randomness: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let randomness = get_buffer(randomness, rt)?;
        if randomness.len() != RANDOMNESS_LEN {
            return Err(anyhow::anyhow!(
                "Randomness must be {} bytes long",
                RANDOMNESS_LEN
            ));
        }

        let randomness_array: &[u8; RANDOMNESS_LEN] =
            randomness.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("Randomness buffer has invalid length: {}", RANDOMNESS_LEN)
            })?;

        let params = GenericServerSecretParams::generate(*randomness_array);

        let serialized_params = zkgroup::serialize(&params);

        Ok(serialize_bytes(rt, &serialized_params)?)
    }

    #[host_object(method as GenericServerSecretParams_GetPublicParams)]
    pub fn GenericServerSecretParams_GetPublicParams<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params_bytes = get_buffer(params_bytes, rt)?;

        let params = zkgroup::deserialize::<GenericServerSecretParams>(&params_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid server secret params"))?;

        let public_params = params.get_public_params();

        let serialized_public_params = zkgroup::serialize(&public_params);

        Ok(serialize_bytes(rt, &serialized_public_params)?)
    }

    #[host_object(method as GroupMasterKey_CheckValidContents)]
    pub fn GroupMasterKey_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<GroupMasterKey>(&buffer)?;

        Ok(())
    }

    #[host_object(method as GroupPublicParams_CheckValidContents)]
    pub fn GroupPublicParams_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<GroupPublicParams>(&buffer)?;

        Ok(())
    }

    #[host_object(method as GroupPublicParams_GetGroupIdentifier)]
    pub fn GroupPublicParams_GetGroupIdentifier<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        group_public_params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params =
            zkgroup::deserialize::<GroupPublicParams>(&get_buffer(group_public_params, rt)?)?;

        let group_identifier = params.get_group_identifier();

        Ok(serialize_bytes(rt, &group_identifier)?)
    }

    #[host_object(method as GroupSecretParams_CheckValidContents)]
    pub fn GroupSecretParams_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<GroupSecretParams>(&buffer)?;

        Ok(())
    }

    #[host_object(method as GroupSecretParams_DecryptBlobWithPadding)]
    pub fn GroupSecretParams_DecryptBlobWithPadding<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        ciphertext: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let ciphertext = get_buffer(ciphertext, rt)?;

        let plaintext = params.decrypt_blob_with_padding(&ciphertext)?;

        Ok(serialize_bytes(rt, &plaintext)?)
    }

    #[host_object(method as GroupSecretParams_DecryptProfileKey)]
    pub fn GroupSecretParams_DecryptProfileKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        profile_key: JsiValue<'rt>,
        user_id: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let profile_key_ciphertext =
            zkgroup::deserialize::<ProfileKeyCiphertext>(&get_buffer(profile_key, rt)?)?;

        let user_id = get_aci_fixed_width_binary(user_id, rt)?;

        let decrypted_profile_key = params.decrypt_profile_key(profile_key_ciphertext, user_id)?;

        Ok(serialize_bytes(
            rt,
            &zkgroup::serialize(&decrypted_profile_key),
        )?)
    }

    #[host_object(method as GroupSecretParams_DecryptServiceId)]
    pub fn GroupSecretParams_DecryptServiceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        ciphertext: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let ciphertext = zkgroup::deserialize::<UuidCiphertext>(&get_buffer(ciphertext, rt)?)?;

        let service_id = params
            .decrypt_service_id(ciphertext)?
            .service_id_fixed_width_binary();

        Ok(serialize_bytes(rt, &service_id)?)
    }

    #[host_object(method as GroupSecretParams_DeriveFromMasterKey)]
    pub fn GroupSecretParams_DeriveFromMasterKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        master_key: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let master_key = zkgroup::deserialize::<GroupMasterKey>(&get_buffer(master_key, rt)?)?;

        let secret_params = GroupSecretParams::derive_from_master_key(master_key);

        Ok(serialize_bytes(rt, &zkgroup::serialize(&secret_params))?)
    }

    #[host_object(method as GroupSecretParams_EncryptBlobWithPaddingDeterministic)]
    pub fn GroupSecretParams_EncryptBlobWithPaddingDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        randomness: JsiValue<'rt>,
        plaintext: JsiValue<'rt>,
        padding_len: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let randomness = get_buffer(randomness, rt)?;
        let plaintext = get_buffer(plaintext, rt)?;

        let randomness_array: &[u8; RANDOMNESS_LEN] = randomness.as_slice().try_into().unwrap();

        let padding_len = get_number(padding_len, rt)? as u32;

        let ciphertext =
            params.encrypt_blob_with_padding(*randomness_array, &plaintext, padding_len);

        Ok(serialize_bytes(rt, &ciphertext)?)
    }

    #[host_object(method as GroupSecretParams_EncryptProfileKey)]
    pub fn GroupSecretParams_EncryptProfileKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        profile_key: JsiValue<'rt>,
        user_id: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let profile_key = zkgroup::deserialize::<ProfileKey>(&get_buffer(profile_key, rt)?)?;
        let user_id = get_aci_fixed_width_binary(user_id, rt)?;

        let ciphertext = params.encrypt_profile_key(profile_key, user_id);

        Ok(serialize_bytes(rt, &zkgroup::serialize(&ciphertext))?)
    }

    #[host_object(method as GroupSecretParams_EncryptServiceId)]
    pub fn GroupSecretParams_EncryptServiceId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
        service_id: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let service_id: [u8; 17] = get_buffer(service_id, rt)?
            .try_into()
            .map_err(|_| anyhow!("Invalid service id"))?;
        let service_id = ServiceId::parse_from_service_id_fixed_width_binary(&service_id)
            .ok_or(anyhow!("Invalid service id"))?;

        let ciphertext = params.encrypt_service_id(service_id);

        Ok(serialize_bytes(rt, &zkgroup::serialize(&ciphertext))?)
    }

    #[host_object(method as GroupSecretParams_GenerateDeterministic)]
    pub fn GroupSecretParams_GenerateDeterministic<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        randomness: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let randomness = get_buffer(randomness, rt)?;

        let randomness_array: &[u8; RANDOMNESS_LEN] = randomness.as_slice().try_into().unwrap();

        let secret_params = GroupSecretParams::generate(*randomness_array);

        Ok(serialize_bytes(rt, &zkgroup::serialize(&secret_params))?)
    }

    #[host_object(method as GroupSecretParams_GetMasterKey)]
    pub fn GroupSecretParams_GetMasterKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let master_key = params.get_master_key();

        Ok(serialize_bytes(rt, &zkgroup::serialize(&master_key))?)
    }

    #[host_object(method as GroupSecretParams_GetPublicParams)]
    pub fn GroupSecretParams_GetPublicParams<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        params: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let params = zkgroup::deserialize::<GroupSecretParams>(&get_buffer(params, rt)?)?;

        let public_params = params.get_public_params();

        Ok(serialize_bytes(rt, &zkgroup::serialize(&public_params))?)
    }

    #[host_object(method as ProfileKeyCiphertext_CheckValidContents)]
    pub fn ProfileKeyCiphertext_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<ProfileKeyCiphertext>(&buffer)?;

        Ok(())
    }

    #[host_object(method as ProfileKey_CheckValidContents)]
    pub fn ProfileKey_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<ProfileKey>(&buffer)?;

        Ok(())
    }

    #[host_object(method as ProfileKey_DeriveAccessKey)]
    pub fn ProfileKey_DeriveAccessKey<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        profile_key: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let profile_key = zkgroup::deserialize::<ProfileKey>(&get_buffer(profile_key, rt)?)?;

        let access_key = profile_key.derive_access_key();

        Ok(serialize_bytes(rt, &access_key)?)
    }

    #[host_object(method as ProfileKey_GetCommitment)]
    pub fn ProfileKey_GetCommitment<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        profile_key: JsiValue<'rt>,
        user_id: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let profile_key = zkgroup::deserialize::<ProfileKey>(&get_buffer(profile_key, rt)?)?;

        let user_id = get_aci_fixed_width_binary(user_id, rt)?;

        let commitment = profile_key.get_commitment(user_id);

        Ok(serialize_bytes(rt, &zkgroup::serialize(&commitment))?)
    }

    #[host_object(method as ProfileKey_GetProfileKeyVersion)]
    pub fn ProfileKey_GetProfileKeyVersion<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        profile_key: JsiValue<'rt>,
        user_id: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let profile_key = zkgroup::deserialize::<ProfileKey>(&get_buffer(profile_key, rt)?)?;

        let user_id = get_aci_fixed_width_binary(user_id, rt)?;

        let version = profile_key.get_profile_key_version(user_id);

        Ok(serialize_bytes(rt, &zkgroup::serialize(&version))?)
    }

    #[host_object(method as ProfileKeyCredentialPresentation_CheckValidContents)]
    pub fn ProfileKeyCredentialPresentation_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let presentation_bytes = get_buffer(presentation_bytes, rt)?;

        AnyProfileKeyCredentialPresentation::new(&presentation_bytes)?;

        Ok(())
    }

    #[host_object(method as ProfileKeyCredentialPresentation_GetProfileKeyCiphertext)]
    pub fn ProfileKeyCredentialPresentation_GetProfileKeyCiphertext<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let presentation =
            AnyProfileKeyCredentialPresentation::new(&get_buffer(presentation_bytes, rt)?)?;

        let profile_key_ciphertext = presentation.get_profile_key_ciphertext();

        Ok(serialize_bytes(
            rt,
            &zkgroup::serialize(&profile_key_ciphertext),
        )?)
    }

    #[host_object(method as ProfileKeyCredentialPresentation_GetUuidCiphertext)]
    pub fn ProfileKeyCredentialPresentation_GetUuidCiphertext<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        presentation_bytes: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let presentation =
            AnyProfileKeyCredentialPresentation::new(&get_buffer(presentation_bytes, rt)?)?;

        let uuid_ciphertext = presentation.get_uuid_ciphertext();

        Ok(serialize_bytes(rt, &zkgroup::serialize(&uuid_ciphertext))?)
    }

    #[host_object(method as ProfileKeyCredentialRequestContext_CheckValidContents)]
    pub fn ProfileKeyCredentialRequestContext_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<ProfileKeyCredentialRequestContext>(&buffer)?;

        Ok(())
    }

    #[host_object(method as ProfileKeyCredentialRequestContext_GetRequest)]
    pub fn ProfileKeyCredentialRequestContext_GetRequest<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        context: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let context =
            zkgroup::deserialize::<ProfileKeyCredentialRequestContext>(&get_buffer(context, rt)?)?;

        let request = context.get_request();

        Ok(serialize_bytes(rt, &zkgroup::serialize(&request))?)
    }

    #[host_object(method as ProfileKeyCredentialRequest_CheckValidContents)]
    pub fn ProfileKeyCredentialRequest_CheckValidContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        buffer: JsiValue<'rt>,
    ) -> anyhow::Result<()> {
        let buffer = get_buffer(buffer, rt)?;

        zkgroup::deserialize::<ProfileKeyCredentialRequest>(&buffer)?;

        Ok(())
    }

    #[host_object(method as UnidentifiedSenderMessageContent_Deserialize)]
    pub fn UnidentifiedSenderMessageContent_Deserialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        data: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let data = get_buffer(data, rt)?;

        let content = UnidentifiedSenderMessageContent::deserialize(&data)?;

        let content_ptr = Box::into_raw(Box::new(content)) as i64;
        Ok(content_ptr)
    }

    #[host_object(method as UnidentifiedSenderMessageContent_GetContentHint)]
    pub fn UnidentifiedSenderMessageContent_GetContentHint<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        m: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(m, rt)?;

        let content_hint = content.content_hint()?;

        Ok(content_hint.into())
    }

    #[host_object(method as UnidentifiedSenderMessageContent_GetContents)]
    pub fn UnidentifiedSenderMessageContent_GetContents<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(obj, rt)?;

        let contents = content.contents()?;

        Ok(serialize_bytes(rt, contents)?)
    }

    #[host_object(method as UnidentifiedSenderMessageContent_GetGroupId)]
    pub fn UnidentifiedSenderMessageContent_GetGroupId<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(obj, rt)?;

        if let Some(group_id) = content.group_id()? {
            Ok(serialize_bytes(rt, group_id)?)
        } else {
            Ok(JsiValue::new_null())
        }
    }

    #[host_object(method as UnidentifiedSenderMessageContent_GetMsgType)]
    pub fn UnidentifiedSenderMessageContent_GetMsgType<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        m: JsiValue<'rt>,
    ) -> anyhow::Result<u32> {
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(m, rt)?;

        let msg_type = content.msg_type()?;

        Ok(msg_type as u32)
    }

    #[host_object(method as UnidentifiedSenderMessageContent_GetSenderCert)]
    pub fn UnidentifiedSenderMessageContent_GetSenderCert<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        m: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(m, rt)?;

        let sender_cert = content.sender()?;

        let cert_ptr = Box::into_raw(Box::new(sender_cert.clone())) as i64;
        Ok(cert_ptr)
    }

    #[host_object(method as UnidentifiedSenderMessageContent_New)]
    pub fn UnidentifiedSenderMessageContent_New<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        message: JsiValue<'rt>,
        sender: JsiValue<'rt>,
        content_hint: JsiValue<'rt>,
        group_id: JsiValue<'rt>,
    ) -> anyhow::Result<i64> {
        let message: &CiphertextMessage = get_reference_handle(message, rt)?;
        let sender_cert: &SenderCertificate = get_reference_handle(sender, rt)?;

        let content_hint = ContentHint::from(get_number(content_hint, rt)? as u32);
        let group_id = if group_id.is_null() {
            None
        } else {
            Some(get_buffer(group_id, rt)?)
        };

        let content = UnidentifiedSenderMessageContent::new(
            message.message_type(),
            sender_cert.clone(),
            Vec::new(),
            content_hint,
            group_id,
        )?;

        let content_ptr = Box::into_raw(Box::new(content)) as i64;
        Ok(content_ptr)
    }

    #[host_object(method as UnidentifiedSenderMessageContent_Serialize)]
    pub fn UnidentifiedSenderMessageContent_Serialize<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        obj: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let content: &UnidentifiedSenderMessageContent = get_reference_handle(obj, rt)?;

        let serialized = content.serialized()?;

        Ok(serialize_bytes(rt, serialized)?)
    }

    #[host_object(method as Delete)]
    pub fn Delete<'rt>(
        &self,
        rt: &mut RuntimeHandle<'rt>,
        pointer: JsiValue<'rt>,
    ) -> anyhow::Result<jsi::JsiValue<'rt>> {
        let pointer = get_number(pointer, rt)? as i64;

        unsafe {
            let pointer = pointer as *mut std::os::raw::c_void;
            drop(Box::from_raw(pointer))
        };

        Ok(JsiValue::new_null())
    }
}
