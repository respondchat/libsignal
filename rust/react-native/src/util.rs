use anyhow::anyhow;
use core::fmt;
use jsi::de::JsiDeserializeError;
use jsi::ser::JsiSerializeError;
use jsi::{
    FromObject, FromValue, IntoValue, JsiArrayBuffer, JsiFn, JsiObject, JsiString, JsiValue,
    PropName, RuntimeDisplay, RuntimeHandle,
};
use libsignal_core::Aci;
use serde::de::Error;
use serde::ser::Error as _;

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

pub fn serialize_bytes<'rt>(
    rt: &mut RuntimeHandle<'rt>,
    v: &[u8],
) -> Result<JsiValue<'rt>, JsiSerializeError> {
    let buffer_ctor = rt.global().get(PropName::new("Buffer", rt), rt);
    let buffer_ctor: JsiFn = buffer_ctor
        .try_into_js(rt)
        .ok_or(JsiSerializeError::custom("Buffer constructor not found"))?;
    let buffer = buffer_ctor
        .call_as_constructor(vec![JsiValue::new_number(v.len() as f64)], rt)
        .map_err(|e| JsiSerializeError::custom(format!("Buffer constructor failed: {:?}", e)))?;

    let buffer = JsiObject::from_value(&buffer, rt)
        .ok_or(JsiSerializeError::custom("Expected an object"))?;
    let array_buffer = buffer.get(PropName::new("buffer", rt), rt);

    let array_buffer: JsiArrayBuffer = array_buffer
        .try_into_js(rt)
        .ok_or(JsiSerializeError::custom("Expected an ArrayBuffer"))?;

    array_buffer.data(rt).copy_from_slice(v);

    Ok(buffer.into_value(rt))
}

pub fn get_buffer<'rt>(
    value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<Vec<u8>> {
    if !value.is_object() {
        return Err(anyhow!("Expected an Buffer"));
    }

    let value = JsiObject::from_value(&value, rt)
        .ok_or(JsiDeserializeError::custom("Expected an Buffer"))?;

    let value = value.get(PropName::new("buffer", rt), rt);

    let value = JsiArrayBuffer::from_value(&value, rt)
        .ok_or(JsiDeserializeError::custom("Expected an ArrayBuffer"))?;

    Ok(value.data(rt).to_vec())
}

pub fn get_number<'rt>(value: JsiValue<'rt>, rt: &mut RuntimeHandle<'rt>) -> anyhow::Result<f64> {
    if !value.is_number() {
        return Err(anyhow!("Expected a number"));
    }

    Ok(f64::from_value(&value, rt).ok_or(JsiDeserializeError::custom("Expected a number"))?)
}

pub fn get_bool<'rt>(value: JsiValue<'rt>, rt: &mut RuntimeHandle<'rt>) -> anyhow::Result<bool> {
    if !value.is_bool() {
        return Err(anyhow!("Expected a boolean"));
    }

    Ok(bool::from_value(&value, rt).ok_or(JsiDeserializeError::custom("Expected a boolean"))?)
}

pub fn get_string<'rt>(
    value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<String> {
    if !value.is_string() {
        return Err(anyhow!("Expected a string"));
    }

    let value = JsiString::from_value(&value, rt)
        .ok_or(JsiDeserializeError::custom("Expected a string"))?;

    let mut output = String::new();
    let mut formatter = fmt::Formatter::new(&mut output);
    value.fmt(&mut formatter, rt)?;

    Ok(output)
}

pub fn get_reference_handle<'rt, T>(
    wrapper: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<&'rt T> {
    if !wrapper.is_object() {
        return Err(anyhow!("Expected an {{ _nativeHandle }} Object"));
    }

    let wrapper = JsiObject::from_value(&wrapper, rt).ok_or(JsiDeserializeError::custom(
        "Expected an { _nativeHandle } Object",
    ))?;

    let handle = wrapper.get(PropName::new("_nativeHandle", rt), rt);

    return get_reference(handle, rt);
}

pub fn get_reference_handle_mut<'rt, T>(
    wrapper: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<&'rt mut T> {
    if !wrapper.is_object() {
        return Err(anyhow!("Expected an object"));
    }

    let wrapper = JsiObject::from_value(&wrapper, rt)
        .ok_or(JsiDeserializeError::custom("Expected an object"))?;

    let handle = wrapper.get(PropName::new("_nativeHandle", rt), rt);

    return get_reference_mut(handle, rt);
}

pub fn get_reference<'rt, T>(
    pointer_value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<&'rt T> {
    if !pointer_value.is_number() {
        return Err(anyhow!("Expected a number"));
    }

    let pointer = get_number(pointer_value, rt)? as i64;

    let reference = unsafe { &*(pointer as *const T) };

    Ok(reference)
}

pub fn get_reference_mut<'rt, T>(
    pointer_value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<&'rt mut T> {
    if !pointer_value.is_number() {
        return Err(anyhow!("Expected a number"));
    }

    let pointer = get_number(pointer_value, rt)? as i64;

    let reference = unsafe { &mut *(pointer as *mut T) };

    Ok(reference)
}

pub fn get_array<'rt>(
    array: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<Vec<JsiValue<'rt>>> {
    if !array.is_object() {
        return Err(anyhow!("Expected an array"));
    }

    let array = JsiObject::from_value(&array, rt)
        .ok_or(JsiDeserializeError::custom("Expected an object"))?;

    let length = array.get(PropName::new("length", rt), rt);
    let length = get_number(length, rt)? as usize;

    let mut result = Vec::with_capacity(length);

    for i in 0..length {
        let value = array.get(PropName::new(&i.to_string(), rt), rt);
        result.push(value);
    }

    Ok(result)
}

pub fn get_array_of_references<'rt, T>(
    array: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<Vec<&'rt T>> {
    let mut array = get_array(array, rt)?;

    let mut result = Vec::with_capacity(array.len());

    for value in array.drain(..) {
        let reference = get_reference(value, rt)?;
        result.push(reference);
    }

    Ok(result)
}

pub fn get_array_of_handles<'rt, T>(
    array: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<Vec<&'rt T>> {
    let mut array = get_array(array, rt)?;

    let mut result = Vec::with_capacity(array.len());

    for value in array.drain(..) {
        let handle: &T = get_reference_handle(value, rt)?;

        result.push(handle);
    }

    Ok(result)
}

pub fn get_aci_fixed_width_binary<'rt>(
    value: JsiValue<'rt>,
    rt: &mut RuntimeHandle<'rt>,
) -> anyhow::Result<Aci> {
    let value: [u8; 17] = get_buffer(value, rt)?
        .try_into()
        .map_err(|_| anyhow!("Invalid user id"))?;
    let value =
        Aci::parse_from_service_id_fixed_width_binary(&value).ok_or(anyhow!("Invalid user id"))?;

    Ok(value)
}
