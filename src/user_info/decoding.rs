use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};

use crate::Result;

pub(super) fn decode_required_base64_string(value: &str) -> Result<String> {
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(value)?;
    Ok(String::from_utf8(decoded)?)
}

pub(super) fn decode_optional_base64_string(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(value)?;
    if decoded.is_empty() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(decoded)?))
}

pub(super) fn decode_optional_base64_u32(value: Option<&str>) -> Result<Option<u32>> {
    let Some(value) = decode_optional_base64_string(value)? else {
        return Ok(None);
    };
    Ok(Some(value.parse::<u32>()?))
}

pub(super) fn decode_optional_base64_i32(value: Option<&str>) -> Result<Option<i32>> {
    let Some(value) = decode_optional_base64_string(value)? else {
        return Ok(None);
    };
    Ok(Some(value.parse::<i32>()?))
}
