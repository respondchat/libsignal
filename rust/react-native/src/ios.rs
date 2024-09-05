#[no_mangle]
pub extern "C" fn Libsignal_init(
    rt: *mut jsi::sys::Runtime,
    call_invoker: cxx::SharedPtr<jsi::sys::CallInvoker>,
) {
    crate::init(rt, call_invoker);
}
