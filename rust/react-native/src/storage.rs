use async_trait::async_trait;

use crate::{get_bool, get_number, get_reference, serialize_bytes};
use jsi::de::JsiDeserializeError;
use jsi::{FromObject, FromValue, JsiFn, JsiObject, JsiValue, PropName};
use libsignal_core::ProtocolAddress;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, PrivateKey,
    SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use serde::de::Error;
use uuid::Uuid;

pub struct JSISenderKeyStore<'rt> {
    get_sender_key: JsiFn<'rt>,
    save_sender_key: JsiFn<'rt>,
    rt: jsi::RuntimeHandle<'rt>,
}

impl<'rt> JSISenderKeyStore<'rt> {
    pub fn new(
        store_object: JsiValue<'rt>,
        mut rt: jsi::RuntimeHandle<'rt>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a SenderKeyStore object"),
        )?;

        let getSenderKey: JsiValue =
            store_object.get(PropName::new("_getSenderKey", &mut rt), &mut rt);
        let getSenderKey: JsiObject = JsiObject::from_value(&getSenderKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getSenderKey property"),
        )?;
        let getSenderKey: JsiFn = JsiFn::from_object(&getSenderKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getSenderKey function"),
        )?;

        let saveSenderKey: JsiValue =
            store_object.get(PropName::new("_saveSenderKey", &mut rt), &mut rt);
        let saveSenderKey: JsiObject = JsiObject::from_value(&saveSenderKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveSenderKey property"),
        )?;
        let saveSenderKey: JsiFn = JsiFn::from_object(&saveSenderKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveSenderKey function"),
        )?;

        Ok(Self {
            get_sender_key: getSenderKey,
            save_sender_key: saveSenderKey,
            rt,
        })
    }

    async fn do_get_sender_key(
        &mut self,
        sender: ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, String> {
        let rt = &mut self.rt;

        let distribution_id =
            serialize_bytes(rt, distribution_id.as_bytes()).map_err(|e| e.to_string())?;
        let nativeAddress = JsiValue::new_number(Box::into_raw(Box::new(sender)) as i64 as f64);

        let result = self
            .get_sender_key
            .call([nativeAddress, distribution_id], rt)
            .map_err(|e| e.to_string())?;

        if !result.is_number() {
            return Ok(None);
        }

        let record: &SenderKeyRecord = get_reference(result, rt).map_err(|e| e.to_string())?;

        Ok(Some(record.clone()))
    }

    async fn do_save_sender_key(
        &mut self,
        sender: ProtocolAddress,
        distribution_id: Uuid,
        record: SenderKeyRecord,
    ) -> Result<(), String> {
        let rt = &mut self.rt;

        let distribution_id =
            serialize_bytes(rt, distribution_id.as_bytes()).map_err(|e| e.to_string())?;
        let nativeAddress = JsiValue::new_number(Box::into_raw(Box::new(sender)) as i64 as f64);
        let record = record.serialize().map_err(|e| e.to_string())?;
        let record = serialize_bytes(rt, &record).map_err(|e| e.to_string())?;

        self.save_sender_key
            .call([nativeAddress, distribution_id, record], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'rt> SenderKeyStore for JSISenderKeyStore<'rt> {
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        self.do_get_sender_key(sender.clone(), distribution_id)
            .await
            .map_err(|_| SignalProtocolError::SessionNotFound(sender.clone()))
    }

    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_sender_key(sender.clone(), distribution_id, record.clone())
            .await
            .map_err(|_| SignalProtocolError::SessionNotFound(sender.clone()))
    }
}

pub struct JSISessionStore<'rt> {
    get_session: JsiFn<'rt>,
    save_session: JsiFn<'rt>,
    rt: jsi::RuntimeHandle<'rt>,
}

impl<'rt> JSISessionStore<'rt> {
    pub fn new(
        store_object: JsiValue<'rt>,
        mut rt: jsi::RuntimeHandle<'rt>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a SessionStore object"),
        )?;

        let getSession: JsiValue = store_object.get(PropName::new("_getSession", &mut rt), &mut rt);
        let getSession: JsiObject = JsiObject::from_value(&getSession, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getSession property"),
        )?;
        let getSession: JsiFn = JsiFn::from_object(&getSession, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getSession function"),
        )?;

        let saveSession: JsiValue =
            store_object.get(PropName::new("_saveSession", &mut rt), &mut rt);
        let saveSession: JsiObject = JsiObject::from_value(&saveSession, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveSession property"),
        )?;
        let saveSession: JsiFn = JsiFn::from_object(&saveSession, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveSession function"),
        )?;

        Ok(Self {
            get_session: getSession,
            save_session: saveSession,
            rt,
        })
    }

    async fn do_get_session(
        &mut self,
        address: ProtocolAddress,
    ) -> Result<Option<SessionRecord>, String> {
        let rt = &mut self.rt;

        let pointer = Box::into_raw(Box::new(address)) as i64;
        let nativeAddress = JsiValue::new_number(pointer as f64);

        let result = self
            .get_session
            .call([nativeAddress], rt)
            .map_err(|e| e.to_string());

        let result = result?;

        // unsafe { drop(Box::from_raw(pointer as *mut ProtocolAddress)) }

        let record: Result<&SessionRecord, anyhow::Error> = get_reference(result, rt);

        match record {
            Ok(record) => Ok(Some(record.clone())),
            Err(_) => Ok(None),
        }
    }

    async fn do_save_session(
        &mut self,
        address: ProtocolAddress,
        record: SessionRecord,
    ) -> Result<(), String> {
        let rt = &mut self.rt;

        let nativeAddress = JsiValue::new_number(Box::into_raw(Box::new(address)) as i64 as f64);
        let record = record.serialize().map_err(|e| e.to_string())?;
        let record = serialize_bytes(rt, &record).map_err(|e| e.to_string())?;

        self.save_session
            .call([nativeAddress, record], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'rt> SessionStore for JSISessionStore<'rt> {
    async fn load_session(
        &mut self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        self.do_get_session(address.clone())
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_session(address.clone(), record.clone())
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }
}

pub struct JSIKyberPreKeyStore<'rt> {
    get_kyber_pre_key: JsiFn<'rt>,
    save_kyber_pre_key: JsiFn<'rt>,
    mark_kyber_pre_key_used: JsiFn<'rt>,
    rt: jsi::RuntimeHandle<'rt>,
}

impl<'rt> JSIKyberPreKeyStore<'rt> {
    pub fn new(
        store_object: JsiValue<'rt>,
        mut rt: jsi::RuntimeHandle<'rt>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a KyberPreKeyStore object"),
        )?;

        let getKyberPreKey: JsiValue =
            store_object.get(PropName::new("_getKyberPreKey", &mut rt), &mut rt);
        let getKyberPreKey: JsiObject = JsiObject::from_value(&getKyberPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getKyberPreKey property"),
        )?;
        let getKyberPreKey: JsiFn = JsiFn::from_object(&getKyberPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getKyberPreKey function"),
        )?;

        let saveKyberPreKey: JsiValue =
            store_object.get(PropName::new("_saveKyberPreKey", &mut rt), &mut rt);
        let saveKyberPreKey: JsiObject = JsiObject::from_value(&saveKyberPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveKyberPreKey property"),
        )?;
        let saveKyberPreKey: JsiFn = JsiFn::from_object(&saveKyberPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveKyberPreKey function"),
        )?;

        let markKyberPreKeyUsed: JsiValue =
            store_object.get(PropName::new("_markKyberPreKeyUsed", &mut rt), &mut rt);
        let markKyberPreKeyUsed: JsiObject = JsiObject::from_value(&markKyberPreKeyUsed, &mut rt)
            .ok_or(JsiDeserializeError::custom(
            "Expected a _markKyberPreKeyUsed property",
        ))?;
        let markKyberPreKeyUsed: JsiFn = JsiFn::from_object(&markKyberPreKeyUsed, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _markKyberPreKeyUsed function"),
        )?;

        Ok(Self {
            get_kyber_pre_key: getKyberPreKey,
            save_kyber_pre_key: saveKyberPreKey,
            mark_kyber_pre_key_used: markKyberPreKeyUsed,
            rt,
        })
    }

    async fn do_get_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(kyber_prekey_id) as f64);

        let result = self
            .get_kyber_pre_key
            .call([key_id_value], rt)
            .map_err(|e| e.to_string())?;

        let record: &KyberPreKeyRecord = get_reference(result, rt).map_err(|e| e.to_string())?;

        Ok(record.clone())
    }

    async fn do_save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: KyberPreKeyRecord,
    ) -> Result<(), String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(kyber_prekey_id) as f64);
        let record = record.serialize().map_err(|e| e.to_string())?;
        let record = serialize_bytes(rt, &record).map_err(|e| e.to_string())?;

        self.save_kyber_pre_key
            .call([key_id_value, record], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn do_mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(kyber_prekey_id) as f64);

        self.mark_kyber_pre_key_used
            .call([key_id_value], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'rt> KyberPreKeyStore for JSIKyberPreKeyStore<'rt> {
    async fn get_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        self.do_get_kyber_pre_key(kyber_prekey_id)
            .await
            .map_err(|_| SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_kyber_pre_key(kyber_prekey_id, record.clone())
            .await
            .map_err(|_| SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        self.do_mark_kyber_pre_key_used(kyber_prekey_id)
            .await
            .map_err(|_| SignalProtocolError::InvalidKyberPreKeyId)
    }
}

pub struct JSISignedPreKeyStore<'rt> {
    get_signed_pre_key: JsiFn<'rt>,
    save_signed_pre_key: JsiFn<'rt>,
    rt: jsi::RuntimeHandle<'rt>,
}

impl<'rt> JSISignedPreKeyStore<'rt> {
    pub fn new(
        store_object: JsiValue<'rt>,
        mut rt: jsi::RuntimeHandle<'rt>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a SignedPreKeyStore object"),
        )?;

        let getSignedPreKey: JsiValue =
            store_object.get(PropName::new("_getSignedPreKey", &mut rt), &mut rt);
        let getSignedPreKey: JsiObject = JsiObject::from_value(&getSignedPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getSignedPreKey object"),
        )?;
        let getSignedPreKey: JsiFn = JsiFn::from_object(&getSignedPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getSignedPreKey function"),
        )?;

        let saveSignedPreKey: JsiValue =
            store_object.get(PropName::new("_saveSignedPreKey", &mut rt), &mut rt);
        let saveSignedPreKey: JsiObject = JsiObject::from_value(&saveSignedPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveSignedPreKey object"),
        )?;
        let saveSignedPreKey: JsiFn = JsiFn::from_object(&saveSignedPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveSignedPreKey function"),
        )?;

        Ok(Self {
            get_signed_pre_key: getSignedPreKey,
            save_signed_pre_key: saveSignedPreKey,
            rt,
        })
    }

    async fn do_get_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(signed_prekey_id) as f64);

        let result = self
            .get_signed_pre_key
            .call([key_id_value], rt)
            .map_err(|e| e.to_string())?;

        let record: &SignedPreKeyRecord = get_reference(result, rt).map_err(|e| e.to_string())?;

        Ok(record.clone())
    }

    async fn do_save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: SignedPreKeyRecord,
    ) -> Result<(), String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(signed_prekey_id) as f64);
        let record = record.serialize().map_err(|e| e.to_string())?;
        let record = serialize_bytes(rt, &record).map_err(|e| e.to_string())?;

        self.save_signed_pre_key
            .call([key_id_value, record], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'rt> SignedPreKeyStore for JSISignedPreKeyStore<'rt> {
    async fn get_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        self.do_get_signed_pre_key(signed_prekey_id)
            .await
            .map_err(|_| SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_signed_pre_key(signed_prekey_id, record.clone())
            .await
            .map_err(|_| SignalProtocolError::InvalidSignedPreKeyId)
    }
}

pub struct JSIPreKeyStore<'rt> {
    get_pre_key: JsiFn<'rt>,
    save_pre_key: JsiFn<'rt>,
    remove_pre_key: JsiFn<'rt>,
    rt: jsi::RuntimeHandle<'rt>,
}

impl<'rt> JSIPreKeyStore<'rt> {
    pub fn new(
        store_object: JsiValue<'rt>,
        mut rt: jsi::RuntimeHandle<'rt>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected a PreKeyStore object"))?;

        let getPreKey: JsiValue = store_object.get(PropName::new("_getPreKey", &mut rt), &mut rt);
        let getPreKey: JsiObject = JsiObject::from_value(&getPreKey, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected a _getPreKey object"))?;
        let getPreKey: JsiFn = JsiFn::from_object(&getPreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getPreKey function"),
        )?;

        let savePreKey: JsiValue = store_object.get(PropName::new("_savePreKey", &mut rt), &mut rt);
        let savePreKey: JsiObject = JsiObject::from_value(&savePreKey, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected a _savePreKey object"))?;
        let savePreKey: JsiFn = JsiFn::from_object(&savePreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _savePreKey function"),
        )?;

        let removePreKey: JsiValue =
            store_object.get(PropName::new("_removePreKey", &mut rt), &mut rt);
        let removePreKey: JsiObject = JsiObject::from_value(&removePreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _removePreKey object"),
        )?;
        let removePreKey: JsiFn = JsiFn::from_object(&removePreKey, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _removePreKey function"),
        )?;

        Ok(Self {
            get_pre_key: getPreKey,
            save_pre_key: savePreKey,
            remove_pre_key: removePreKey,
            rt,
        })
    }

    async fn do_get_pre_key(&mut self, prekey_id: PreKeyId) -> Result<PreKeyRecord, String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(prekey_id) as f64);

        let result = self
            .get_pre_key
            .call([key_id_value], rt)
            .map_err(|e| e.to_string())?;

        let record: &PreKeyRecord = get_reference(result, rt).map_err(|e| e.to_string())?;

        Ok(record.clone())
    }

    async fn do_save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: PreKeyRecord,
    ) -> Result<(), String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(prekey_id) as f64);
        let record = record.serialize().map_err(|e| e.to_string())?;
        let record = serialize_bytes(rt, &record).map_err(|e| e.to_string())?;

        self.save_pre_key
            .call([key_id_value, record], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn do_remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), String> {
        let rt = &mut self.rt;
        let key_id_value = JsiValue::new_number(u32::from(prekey_id) as f64);

        self.remove_pre_key
            .call([key_id_value], rt)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'rt> PreKeyStore for JSIPreKeyStore<'rt> {
    async fn get_pre_key(
        &mut self,
        prekey_id: PreKeyId,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        self.do_get_pre_key(prekey_id)
            .await
            .map_err(|_| SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_pre_key(prekey_id, record.clone())
            .await
            .map_err(|_| SignalProtocolError::InvalidPreKeyId)
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.do_remove_pre_key(prekey_id)
            .await
            .map_err(|_| SignalProtocolError::InvalidPreKeyId)
    }
}

pub struct JSIIdentityKeyStore<'rt> {
    get_identity_key: JsiFn<'rt>,
    get_local_registration_id: JsiFn<'rt>,
    save_identity: JsiFn<'rt>,
    is_trusted_identity: JsiFn<'rt>,
    get_identity: JsiFn<'rt>,
    rt: jsi::RuntimeHandle<'rt>,
}

impl<'rt> JSIIdentityKeyStore<'rt> {
    pub fn new(
        store_object: JsiValue<'rt>,
        mut rt: jsi::RuntimeHandle<'rt>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a IdentityKeyStore object"),
        )?;

        let get_identity_key: JsiValue =
            store_object.get(PropName::new("_getIdentityKey", &mut rt), &mut rt);
        let get_identity_key: JsiObject = JsiObject::from_value(&get_identity_key, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getIdentityKey object"),
        )?;
        let get_identity_key: JsiFn = JsiFn::from_object(&get_identity_key, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getIdentityKey function"),
        )?;

        let get_local_registration_id: JsiValue =
            store_object.get(PropName::new("_getLocalRegistrationId", &mut rt), &mut rt);
        let get_local_registration_id: JsiObject =
            JsiObject::from_value(&get_local_registration_id, &mut rt).ok_or(
                JsiDeserializeError::custom("Expected a _getLocalRegistrationId object"),
            )?;
        let get_local_registration_id: JsiFn =
            JsiFn::from_object(&get_local_registration_id, &mut rt).ok_or(
                JsiDeserializeError::custom("Expected a _getLocalRegistrationId function"),
            )?;

        let save_identity: JsiValue =
            store_object.get(PropName::new("_saveIdentity", &mut rt), &mut rt);
        let save_identity: JsiObject = JsiObject::from_value(&save_identity, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveIdentity object"),
        )?;
        let save_identity: JsiFn = JsiFn::from_object(&save_identity, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _saveIdentity function"),
        )?;

        let is_trusted_identity: JsiValue =
            store_object.get(PropName::new("_isTrustedIdentity", &mut rt), &mut rt);
        let is_trusted_identity: JsiObject = JsiObject::from_value(&is_trusted_identity, &mut rt)
            .ok_or(JsiDeserializeError::custom(
            "Expected a _isTrustedIdentity object",
        ))?;
        let is_trusted_identity: JsiFn = JsiFn::from_object(&is_trusted_identity, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _isTrustedIdentity function"),
        )?;

        let get_identity: JsiValue =
            store_object.get(PropName::new("_getIdentity", &mut rt), &mut rt);
        let get_identity: JsiObject = JsiObject::from_value(&get_identity, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getIdentity object"),
        )?;
        let get_identity: JsiFn = JsiFn::from_object(&get_identity, &mut rt).ok_or(
            JsiDeserializeError::custom("Expected a _getIdentity function"),
        )?;

        Ok(Self {
            get_identity_key,
            get_local_registration_id,
            save_identity,
            is_trusted_identity,
            get_identity,
            rt,
        })
    }

    async fn do_get_identity_key_pair(&mut self) -> Result<IdentityKeyPair, String> {
        let rt = &mut self.rt;
        let result = self
            .get_identity_key
            .call([], rt)
            .map_err(|e| e.to_string())?;

        let privateKey: PrivateKey = *get_reference(result, rt).map_err(|e| e.to_string())?;
        let publiceKey = privateKey.public_key().map_err(|e| e.to_string())?;
        let identityKey = IdentityKey::new(publiceKey);
        let pair = IdentityKeyPair::new(identityKey, privateKey);

        Ok(pair)
    }

    async fn do_get_local_registration_id(&mut self) -> Result<u32, String> {
        let rt = &mut self.rt;
        let result = self
            .get_local_registration_id
            .call([], rt)
            .map_err(|e| e.to_string())?;

        let id = get_number(result, rt).map_err(|e| e.to_string())?;

        Ok(id as u32)
    }

    async fn do_save_identity(
        &mut self,
        address: ProtocolAddress,
        identity: IdentityKey,
    ) -> Result<bool, String> {
        let rt = &mut self.rt;
        let native_address = JsiValue::new_number(Box::into_raw(Box::new(address)) as i64 as f64);
        let identity_value =
            serialize_bytes(rt, &identity.serialize()).map_err(|e| e.to_string())?;

        let result = self
            .save_identity
            .call([native_address, identity_value], rt)
            .map_err(|e| e.to_string())?;

        let result = get_bool(result, rt).map_err(|e| e.to_string())?;

        Ok(result)
    }

    async fn do_is_trusted_identity(
        &mut self,
        address: ProtocolAddress,
        identity: IdentityKey,
        direction: Direction,
    ) -> Result<bool, String> {
        let rt = &mut self.rt;
        let native_address = JsiValue::new_number(Box::into_raw(Box::new(address)) as i64 as f64);
        let identity_value =
            serialize_bytes(rt, &identity.serialize()).map_err(|e| e.to_string())?;
        let direction_value = JsiValue::new_number(direction as i32 as f64);

        let result = self
            .is_trusted_identity
            .call([native_address, identity_value, direction_value], rt)
            .map_err(|e| e.to_string())?;

        let result = get_bool(result, rt).map_err(|e| e.to_string())?;

        Ok(result)
    }

    async fn do_get_identity(
        &mut self,
        address: ProtocolAddress,
    ) -> Result<Option<IdentityKey>, String> {
        let rt = &mut self.rt;
        let native_address = JsiValue::new_number(Box::into_raw(Box::new(address)) as i64 as f64);

        let result = self
            .get_identity
            .call([native_address], rt)
            .map_err(|e| e.to_string())?;

        if !result.is_object() {
            return Ok(None);
        }

        let key: &IdentityKey = get_reference(result, rt).map_err(|e| e.to_string())?;
        Ok(Some(key.clone()))
    }
}

#[async_trait(?Send)]
impl<'rt> IdentityKeyStore for JSIIdentityKeyStore<'rt> {
    async fn get_identity_key_pair(&mut self) -> Result<IdentityKeyPair, SignalProtocolError> {
        self.do_get_identity_key_pair()
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }

    async fn get_local_registration_id(&mut self) -> Result<u32, SignalProtocolError> {
        self.do_get_local_registration_id()
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        self.do_save_identity(address.clone(), identity.clone())
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }

    async fn is_trusted_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        self.do_is_trusted_identity(address.clone(), identity.clone(), direction)
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }

    async fn get_identity(
        &mut self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        self.do_get_identity(address.clone())
            .await
            .map_err(|s| SignalProtocolError::InvalidArgument(s))
    }
}
