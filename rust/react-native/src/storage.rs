use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use jsi::de::JsiDeserializeError;
use jsi::{AsValue, FromObject, FromValue, JsiFn, JsiObject, JsiValue, PropName};
use libsignal_core::ProtocolAddress;
use libsignal_protocol::{SenderKeyRecord, SenderKeyStore, SignalProtocolError};
use serde::de::Error;
use uuid::Uuid;

use crate::{get_number, get_reference, serialize_bytes};

pub async fn await_promise(
    rt: &mut jsi::RuntimeHandle<'static>,
    result: JsiValue<'static>,
) -> Result<JsiValue<'static>, String> {
    let future = CallbackFuture::<JsiValue>::new();
    let future_resolver = future.clone();

    let promise = JsiObject::from_value(&result, rt).ok_or("Expected an object")?;
    let then = JsiObject::from_value(&promise.get(PropName::new("then", rt), rt), rt)
        .ok_or("Expected a then promise")?;
    let then = JsiFn::from_object(&then, rt).ok_or("Expected a function")?;

    let callback = JsiFn::from_host_fn(
        &PropName::new("_", rt),
        2,
        Box::new(move |_this, mut args, rt| {
            if args.len() != 1 {
                return Err(anyhow::Error::msg("Expected an result").into());
            }

            future_resolver.resolve(args.remove(0));

            Ok(JsiValue::new_undefined())
        }),
        rt,
    )
    .as_value(rt);

    then.call([callback], rt).map_err(|e| e.to_string())?;

    let result = future.await;

    Ok(result)
}

struct CallbackFuture<T> {
    result: Arc<Mutex<Option<T>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    completed: AtomicBool,
}

impl<T> Clone for CallbackFuture<T> {
    fn clone(&self) -> Self {
        CallbackFuture {
            result: Arc::clone(&self.result),
            waker: Arc::clone(&self.waker),
            completed: AtomicBool::new(false),
        }
    }
}

impl<T> CallbackFuture<T> {
    fn new() -> Self {
        CallbackFuture {
            result: Arc::new(Mutex::new(None)),
            waker: Arc::new(Mutex::new(None)),
            completed: AtomicBool::new(false),
        }
    }

    // Function to resolve the future with a value
    fn resolve(&self, value: T) {
        let mut result = self.result.lock().unwrap();
        *result = Some(value);
        self.completed.store(true, Ordering::SeqCst);

        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

impl<T> Future for CallbackFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed.load(Ordering::SeqCst) {
            let mut result = self.result.lock().unwrap();
            Poll::Ready(result.take().unwrap())
        } else {
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

pub struct JSISenderKeyStore {
    store_object: JsiObject<'static>,
    get_sender_key: JsiFn<'static>,
    save_sender_key: JsiFn<'static>,
    rt: jsi::RuntimeHandle<'static>,
}

impl JSISenderKeyStore {
    pub fn new(
        store_object: JsiValue<'static>,
        mut rt: jsi::RuntimeHandle<'static>,
    ) -> Result<Self, JsiDeserializeError> {
        let store_object: JsiObject = JsiObject::from_value(&store_object, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected an object"))?;

        let getSenderKey: JsiValue =
            store_object.get(PropName::new("_getSenderKey", &mut rt), &mut rt);
        let getSenderKey: JsiObject = JsiObject::from_value(&getSenderKey, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected an object"))?;
        let getSenderKey: JsiFn = JsiFn::from_object(&getSenderKey, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected a function"))?;

        let saveSenderKey: JsiValue =
            store_object.get(PropName::new("_saveSenderKey", &mut rt), &mut rt);
        let saveSenderKey: JsiObject = JsiObject::from_value(&saveSenderKey, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected an object"))?;
        let saveSenderKey: JsiFn = JsiFn::from_object(&saveSenderKey, &mut rt)
            .ok_or(JsiDeserializeError::custom("Expected a function"))?;

        Ok(Self {
            store_object,
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

        let promise = self
            .get_sender_key
            .call([nativeAddress, distribution_id], rt)
            .map_err(|e| e.to_string())?;

        if promise.is_null() || !promise.is_object() {
            return Ok(None);
        }

        let result = await_promise(rt, promise).await?;

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

        let promise = self
            .save_sender_key
            .call([nativeAddress, distribution_id, record], rt)
            .map_err(|e| e.to_string())?;

        await_promise(rt, promise).await?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for JSISenderKeyStore {
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        self.do_get_sender_key(sender.clone(), distribution_id)
            .await
            .map_err(|s| SignalProtocolError::SessionNotFound(sender.clone()))
    }

    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_sender_key(sender.clone(), distribution_id, record.clone())
            .await
            .map_err(|s| SignalProtocolError::SessionNotFound(sender.clone()))
    }
}

unsafe impl Send for JSISenderKeyStore {}
unsafe impl Sync for JSISenderKeyStore {}
