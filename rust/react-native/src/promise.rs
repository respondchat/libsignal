use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures::executor;
use jsi::{JsiValue, PropName, RuntimeHandle};

// use crate::console_log;

pub type _CallbackType<'a> = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<JsiValue<'a>>> + Send + 'a>>
        + Send
        + Sync
        + 'a,
>;

pub fn clone_runtime_handle<'rt>(handle: &mut RuntimeHandle<'rt>) -> RuntimeHandle<'static> {
    let inner_runtime_ptr: *mut jsi::sys::Runtime = handle.get_inner() as *const _ as *mut _;

    RuntimeHandle::new_unchecked(inner_runtime_ptr)
}

pub struct SendableRuntimeHandle {
    inner: RuntimeHandle<'static>,
}

impl SendableRuntimeHandle {
    pub fn new(handle: RuntimeHandle<'static>) -> Self {
        SendableRuntimeHandle { inner: handle }
    }

    pub fn get_inner(&self) -> &RuntimeHandle<'static> {
        &self.inner
    }

    pub fn get_inner_mut(&mut self) -> &mut RuntimeHandle<'static> {
        &mut self.inner
    }
}

unsafe impl Send for SendableRuntimeHandle {}
unsafe impl Sync for SendableRuntimeHandle {}

pub fn _make_async<'rt>(
    rt: &mut jsi::RuntimeHandle<'rt>,
    callback: _CallbackType<'static>,
    _callInvoker: jsi::CallInvoker<'static>,
) -> anyhow::Result<jsi::JsiValue<'rt>> {
    let mut sendable_handle = SendableRuntimeHandle::new(clone_runtime_handle(rt));

    // console_log("jsi::create_promise", rt).ok();

    let res = std::thread::spawn(move || -> anyhow::Result<JsiValue<'static>> {
        let rt = sendable_handle.get_inner_mut();

        let promise = jsi::create_promise(
            move |resolve: jsi::JsiFn, reject: jsi::JsiFn, rt: &mut jsi::RuntimeHandle| {
                let res = callback();
                let res = executor::block_on(res);

                // let job: Box<dyn FnOnce() -> anyhow::Result<()>> = Box::new(|| {

                match res {
                    Ok(val) => {
                        let val = jsi::IntoValue::into_value(val, rt);

                        // console_log("resolve promise", rt).ok();

                        resolve.call(std::iter::once(val), rt).ok();

                        // console_log("resolved", rt).ok();
                    }
                    Err(err) => {
                        // reject.call(std::iter::empty(), rt)?;

                        // console_log("reject promise", rt).ok();

                        // for some reason, just calling reject() doesn't actually cause
                        // the promise to reject, so instead we create a rejected
                        // promise and return that

                        let promise_ctor = rt.global().get(jsi::PropName::new("Promise", rt), rt);
                        let promise_ctor: jsi::JsiObject =
                            jsi::FromValue::from_value(&promise_ctor, rt)
                                .expect("Promise constructor is not an object");
                        let promise_reject: jsi::JsiFn = jsi::FromValue::from_value(
                            &promise_ctor.get(jsi::PropName::new("reject", rt), rt),
                            rt,
                        )
                        .expect("Promise.reject is not a function");

                        let rt_clone = &mut clone_runtime_handle(rt);

                        let err = jsi::js_error!(rt_clone, "{err}");
                        let err = jsi::IntoValue::into_value(err, rt);

                        let rejection = promise_reject.call(std::iter::once(err), rt).unwrap();
                        reject.call(std::iter::once(rejection), rt).ok();

                        // console_log("rejected", rt).ok();
                    }
                }

                // Ok(())
                // });

                // callInvoker.invoke_async(job);

                // Ok::<(), anyhow::Error>(())
                // })
            },
            &mut clone_runtime_handle(rt),
        );

        let promise = jsi::IntoValue::into_value(promise, rt);

        Ok(promise)
    })
    .join()
    .unwrap()
    .unwrap();

    Ok(res)
}
