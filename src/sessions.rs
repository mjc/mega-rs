use chrono::{DateTime, TimeZone, Utc};

use crate::protocol::commands;

/// Represents information about a user session.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionInfo {
    /// The ID of the session.
    pub id: String,
    /// The creation date of the session.
    pub created_at: DateTime<Utc>,
    /// The date of last activity of the session.
    pub last_activity_at: DateTime<Utc>,
    /// The user agent string for the session.
    pub user_agent: String,
    /// The IP address of the session.
    pub ip: String,
    /// The country code for the session.
    pub country_code: String,
    /// Whether this session is the current one.
    pub current: bool,
    /// Whether this session is still alive.
    pub alive: bool,
}

impl From<commands::SessionInfo> for SessionInfo {
    fn from(value: commands::SessionInfo) -> Self {
        Self {
            id: value.id,
            created_at: Utc.timestamp_opt(value.timestamp, 0).unwrap(),
            last_activity_at: Utc.timestamp_opt(value.mru, 0).unwrap(),
            user_agent: value.user_agent,
            ip: value.ip,
            country_code: value.country,
            current: value.current == 1,
            alive: value.alive == 1,
        }
    }
}

impl From<&commands::SessionInfo> for SessionInfo {
    fn from(value: &commands::SessionInfo) -> Self {
        Self {
            id: value.id.clone(),
            created_at: Utc.timestamp_opt(value.timestamp, 0).unwrap(),
            last_activity_at: Utc.timestamp_opt(value.mru, 0).unwrap(),
            user_agent: value.user_agent.clone(),
            ip: value.ip.clone(),
            country_code: value.country.clone(),
            current: value.current == 1,
            alive: value.alive == 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_protocol_session() -> commands::SessionInfo {
        commands::SessionInfo {
            timestamp: 1_716_920_000,
            mru: 1_716_921_111,
            user_agent: String::from("Firefox"),
            ip: String::from("203.0.113.4"),
            country: String::from("US"),
            current: 1,
            id: String::from("abcdef01"),
            alive: 1,
        }
    }

    fn assert_session_mapped(session: &SessionInfo) {
        assert_eq!(session.id, "abcdef01");
        assert_eq!(
            session.created_at,
            Utc.timestamp_opt(1_716_920_000, 0).unwrap()
        );
        assert_eq!(
            session.last_activity_at,
            Utc.timestamp_opt(1_716_921_111, 0).unwrap()
        );
        assert_eq!(session.user_agent, "Firefox");
        assert_eq!(session.ip, "203.0.113.4");
        assert_eq!(session.country_code, "US");
        assert!(session.current);
        assert!(session.alive);
    }

    #[test]
    fn owned_protocol_session_maps_to_public_session_info() {
        let session = SessionInfo::from(sample_protocol_session());

        assert_session_mapped(&session);
    }

    #[test]
    fn borrowed_protocol_session_maps_to_public_session_info() {
        let protocol = sample_protocol_session();
        let session = SessionInfo::from(&protocol);

        assert_session_mapped(&session);
    }
}
