use chrono::NaiveDate;

use crate::protocol::commands;
use crate::Result;

mod decoding;

/// Represents information about a MEGA user.
#[derive(Debug, Clone, PartialEq)]
pub struct UserInfo {
    /// The ID of the user.
    pub id: String,
    /// The first name of the user.
    pub first_name: String,
    /// The last name of the user.
    pub last_name: String,
    /// The main email of the user.
    pub email: String,
    /// The birth date of the user.
    pub birth_date: Option<NaiveDate>,
    /// The country code of the user.
    pub country_code: Option<String>,
}

impl TryFrom<&commands::UserInfoResponse> for UserInfo {
    type Error = crate::Error;

    fn try_from(value: &commands::UserInfoResponse) -> Result<Self> {
        Ok(Self {
            id: value.u.clone(),
            first_name: decoding::decode_required_base64_string(&value.firstname)?,
            last_name: decoding::decode_required_base64_string(&value.lastname)?,
            email: value.email.clone(),
            country_code: decoding::decode_optional_base64_string(value.country.as_deref())?,
            birth_date: 'result: {
                let Some(day) = decoding::decode_optional_base64_u32(value.birthday.as_deref())?
                else {
                    break 'result None;
                };
                let Some(month) =
                    decoding::decode_optional_base64_u32(value.birthmonth.as_deref())?
                else {
                    break 'result None;
                };
                let Some(year) = decoding::decode_optional_base64_i32(value.birthyear.as_deref())?
                else {
                    break 'result None;
                };

                NaiveDate::from_ymd_opt(year, month, day)
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};

    use super::*;
    use crate::protocol::commands::UserInfoResponse;

    // These regressions mirror the MEGA SDK's ug parser and empty-attribute handling:
    // - https://github.com/meganz/sdk/blob/d41138b3b6acce78353434af30e582d38bba6a73/src/commands.cpp#L4393-L4404
    // - https://github.com/meganz/sdk/blob/d41138b3b6acce78353434af30e582d38bba6a73/src/commands.cpp#L4584-L4597
    // - https://github.com/meganz/sdk/blob/d41138b3b6acce78353434af30e582d38bba6a73/src/commands.cpp#L5048-L5072
    // - https://github.com/meganz/sdk/blob/d41138b3b6acce78353434af30e582d38bba6a73/src/commands.cpp#L5576-L5585

    fn sample_user_info_response() -> UserInfoResponse {
        UserInfoResponse {
            u: String::from("user-handle"),
            s: 0,
            email: String::from("user@example.com"),
            firstname: BASE64_URL_SAFE_NO_PAD.encode("Jane"),
            lastname: BASE64_URL_SAFE_NO_PAD.encode("Doe"),
            country: None,
            birthday: None,
            birthmonth: None,
            birthyear: None,
            name: String::new(),
            key: String::new(),
            c: 0,
            pubk: String::new(),
            privk: String::new(),
            terms: None,
            ts: String::from("0"),
        }
    }

    #[test]
    fn optional_base64_fields_treat_empty_payload_as_missing() {
        assert_eq!(
            decoding::decode_optional_base64_string(Some("")).unwrap(),
            None
        );
        assert_eq!(
            decoding::decode_optional_base64_string(Some(&BASE64_URL_SAFE_NO_PAD.encode("US")))
                .unwrap(),
            Some(String::from("US"))
        );
        assert_eq!(
            decoding::decode_optional_base64_u32(Some("")).unwrap(),
            None
        );
        assert_eq!(
            decoding::decode_optional_base64_u32(Some(&BASE64_URL_SAFE_NO_PAD.encode("12")))
                .unwrap(),
            Some(12)
        );
        assert_eq!(
            decoding::decode_optional_base64_i32(Some("")).unwrap(),
            None
        );
        assert_eq!(
            decoding::decode_optional_base64_i32(Some(&BASE64_URL_SAFE_NO_PAD.encode("2024")))
                .unwrap(),
            Some(2024)
        );
    }

    #[test]
    fn user_info_response_treats_empty_optional_attrs_as_missing() {
        let response = UserInfoResponse {
            country: Some(String::new()),
            birthday: Some(String::new()),
            birthmonth: Some(String::new()),
            birthyear: Some(String::new()),
            ..sample_user_info_response()
        };

        let user = UserInfo::try_from(&response).unwrap();

        assert_eq!(user.id, "user-handle");
        assert_eq!(user.first_name, "Jane");
        assert_eq!(user.last_name, "Doe");
        assert_eq!(user.email, "user@example.com");
        assert_eq!(user.country_code, None);
        assert_eq!(user.birth_date, None);
    }

    #[test]
    fn user_info_response_maps_populated_optional_attrs() {
        let response = UserInfoResponse {
            country: Some(BASE64_URL_SAFE_NO_PAD.encode("US")),
            birthday: Some(BASE64_URL_SAFE_NO_PAD.encode("27")),
            birthmonth: Some(BASE64_URL_SAFE_NO_PAD.encode("5")),
            birthyear: Some(BASE64_URL_SAFE_NO_PAD.encode("2026")),
            ..sample_user_info_response()
        };

        let user = UserInfo::try_from(&response).unwrap();

        assert_eq!(user.country_code, Some(String::from("US")));
        assert_eq!(user.birth_date, NaiveDate::from_ymd_opt(2026, 5, 27));
    }

    #[test]
    fn user_info_response_returns_none_for_partial_birth_date() {
        for response in [
            UserInfoResponse {
                birthday: Some(BASE64_URL_SAFE_NO_PAD.encode("27")),
                birthmonth: Some(BASE64_URL_SAFE_NO_PAD.encode("5")),
                ..sample_user_info_response()
            },
            UserInfoResponse {
                birthday: Some(BASE64_URL_SAFE_NO_PAD.encode("27")),
                birthyear: Some(BASE64_URL_SAFE_NO_PAD.encode("2026")),
                ..sample_user_info_response()
            },
            UserInfoResponse {
                birthmonth: Some(BASE64_URL_SAFE_NO_PAD.encode("5")),
                birthyear: Some(BASE64_URL_SAFE_NO_PAD.encode("2026")),
                ..sample_user_info_response()
            },
        ] {
            let user = UserInfo::try_from(&response).unwrap();
            assert_eq!(user.birth_date, None);
        }
    }

    #[test]
    fn user_info_response_returns_none_for_invalid_birth_date() {
        let response = UserInfoResponse {
            birthday: Some(BASE64_URL_SAFE_NO_PAD.encode("31")),
            birthmonth: Some(BASE64_URL_SAFE_NO_PAD.encode("2")),
            birthyear: Some(BASE64_URL_SAFE_NO_PAD.encode("2026")),
            ..sample_user_info_response()
        };

        let user = UserInfo::try_from(&response).unwrap();

        assert_eq!(user.birth_date, None);
    }
}
