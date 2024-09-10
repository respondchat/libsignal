store = {
	registration_id: 5,
	device_id: 1,
	senderKeys: {},
	sessions: {},
	kybers: {},
	signedPreKeys: {},
	preKeys: {},
	identies: {},
	identity: Libsignal.PrivateKey_Generate(),
	_saveSenderKey(sender, distributionId, record) {
		sender = Libsignal.ProtocolAddress_Name({ _nativeHandle: sender })
		console.log("_saveSenderKey", sender, distributionId, record, "this", this)
		store.senderKeys[sender] = record
	},
	_getSenderKey(sender, distributionId) {
		sender = Libsignal.ProtocolAddress_Name({ _nativeHandle: sender })
		console.log("_getSenderKey", sender, distributionId, "this", this)
		return store.senderKeys[sender]
	},
	_getSession(sender) {
		sender = Libsignal.ProtocolAddress_Name({ _nativeHandle: sender })
		console.log("_getSession", sender, store.sessions[sender], "this", this)
		return store.sessions[sender]
	},
	_saveSession(sender, record) {
		sender = Libsignal.ProtocolAddress_Name({ _nativeHandle: sender })
		console.log("_saveSession", sender, record, "this", this)
		store.sessions[sender] = record
	},
	_getKyberPreKey(kyberPreKeyId) {
		console.log("_getKyberPreKey", kyberPreKeyId, "this", this)
		return store.kybers[kyberPreKeyId]
	},
	_saveKyberPreKey(kyberPreKeyId, record) {
		console.log("_saveKyberPreKey", kyberPreKeyId, record, "this", this)
		store.kybers[kyberPreKeyId] = record
	},
	_markKyberPreKeyUsed(kyberPreKeyId) {
		console.log("_markKyberPreKeyUsed", kyberPreKeyId, "this", this)
	},
	_saveSignedPreKey(signedPreKeyId, record) {
		console.log("_saveSignedPreKey", signedPreKeyId, record, "this", this)
		store.signedPreKeys[signedPreKeyId] = record
	},
	_getSignedPreKey(signedPreKeyId) {
		console.log("_getSignedPreKey", signedPreKeyId, "this", this)
		return store.signedPreKeys[signedPreKeyId]
	},
	_savePreKey(preKeyId, record) {
		console.log("_savePreKey", preKeyId, record, "this", this)
		store.preKeys[preKeyId] = record
	},
	_getPreKey(preKeyId) {
		console.log("_getPreKey", preKeyId, "this", this)
		return store.preKeys[preKeyId]
	},
	_removePreKey(preKeyId) {
		console.log("_removePreKey", preKeyId, "this", this)
		delete store.preKeys[preKeyId]
	},
	_getIdentityKey() {
		console.log("_getIdentityKey", "this", this)
		return store.identity
	},
	_getLocalRegistrationId() {
		console.log("_getLocalRegistrationId", "this", this)
		return store.registration_id
	},
	_saveIdentity(name, key) {
		name = Libsignal.ProtocolAddress_Name({ _nativeHandle: name })
		console.log("_saveIdentity", name, "this", this)

		store.identies[name] = key
		return true
	},
	_isTrustedIdentity(name, key, sending) {
		name = Libsignal.ProtocolAddress_Name({ _nativeHandle: name })
		console.log("_isTrustedIdentity", name, "this", this)
		return true
	},
	_getIdentity(name) {
		name = Libsignal.ProtocolAddress_Name({ _nativeHandle: name })
		console.log("_getIdentity", name, "this", this)

		return store.identies[name]
	}
}

Object.keys(store).forEach(key => {
	if (typeof store[key] === "function") {
		store[key] = store[key].bind(store)
	}
})

prekey_id = 1
prekey_privateKey = Libsignal.PrivateKey_Generate()
prekey_publicKey = Libsignal.PrivateKey_GetPublicKey({ _nativeHandle: prekey_privateKey })
prekey = Libsignal.PreKeyRecord_New(prekey_id, { _nativeHandle: prekey_publicKey }, { _nativeHandle: prekey_privateKey })
store._savePreKey(prekey_id, prekey)


signed_id = 2
signed_privateKey = Libsignal.PrivateKey_Generate()
signed_publicKey = Libsignal.PrivateKey_GetPublicKey({ _nativeHandle: signed_privateKey })
buffer = Libsignal.PublicKey_Serialize({ _nativeHandle: signed_publicKey })
signature = Libsignal.PrivateKey_Sign({ _nativeHandle: store.identity }, buffer)
timestamp = Date.now()
signed = Libsignal.SignedPreKeyRecord_New(signed_id, timestamp, { _nativeHandle: signed_publicKey }, { _nativeHandle: signed_privateKey }, signature)
store._saveSignedPreKey(signed_id, signed)

identity_publicKey = Libsignal.PrivateKey_GetPublicKey({ _nativeHandle: store.identity })

kyber_pre_key_id = 3
kyber_key_pair = Libsignal.KyberKeyPair_Generate()
kyber_public_key = Libsignal.KyberKeyPair_GetPublicKey({ _nativeHandle: kyber_key_pair })
kyber_private_key = Libsignal.KyberKeyPair_GetSecretKey({ _nativeHandle: kyber_key_pair })
buffer = Libsignal.KyberPublicKey_Serialize({ _nativeHandle: kyber_public_key })
kyber_signature = Libsignal.PrivateKey_Sign({ _nativeHandle: store.identity }, buffer)

kyber_record = Libsignal.KyberPreKeyRecord_New(kyber_pre_key_id, Date.now(), { _nativeHandle: kyber_key_pair }, kyber_signature)

bundle = Libsignal.PreKeyBundle_New(
	store.registration_id,
	store.device_id,
	prekey_id,
	{ _nativeHandle: prekey_publicKey },
	signed_id,
	{ _nativeHandle: signed_publicKey },
	signature,
	{ _nativeHandle: identity_publicKey },
	kyber_pre_key_id,
	{ _nativeHandle: kyber_public_key },
	kyber_signature
	// null,
	// null,
	// Buffer.alloc(0)
)

address = Libsignal.ProtocolAddress_New("test", store.device_id)

Libsignal.SessionBuilder_ProcessPreKeyBundle({ _nativeHandle: bundle }, { _nativeHandle: address }, store, store, Date.now())

msg = Libsignal.SessionCipher_EncryptMessage(Buffer.from("test"), { _nativeHandle: address }, store, store, Date.now())

serialized = Libsignal.CiphertextMessage_Serialize({ _nativeHandle: msg })

ciphertext = Libsignal.PreKeySignalMessage_Deserialize(serialized)

