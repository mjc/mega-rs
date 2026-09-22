use std::borrow::Borrow;
use std::fmt;

use url::Url;
use zeroize::Zeroize;

use crate::error::Result;

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Zeroize)]
        pub(crate) struct $name(String);

        impl $name {
            pub(crate) fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

string_identifier!(SessionId);
string_identifier!(UserHandle);

macro_rules! fixed_bytes {
    ($name:ident, $size:literal) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Zeroize)]
        pub(crate) struct $name([u8; $size]);

        impl $name {
            pub(crate) const fn new(value: [u8; $size]) -> Self {
                Self(value)
            }

            pub(crate) const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub(crate) const fn into_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(value: [u8; $size]) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for [u8; $size] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }
    };
}

fixed_bytes!(SessionKey, 16);
fixed_bytes!(SessionExchangeKey, 16);

/// A validated public MEGA file or folder link.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicLink(String);

impl PublicLink {
    /// Parses a public MEGA link in the supported file or folder format.
    pub fn parse(value: &str) -> Result<Self> {
        let Some(payload) = value.strip_prefix("https://mega.nz/") else {
            return Err(crate::Error::InvalidPublicUrlFormat);
        };
        let Some((kind, payload)) = payload.split_once('/') else {
            return Err(crate::Error::InvalidPublicUrlFormat);
        };
        if !matches!(kind, "file" | "folder") {
            return Err(crate::Error::InvalidPublicUrlFormat);
        }
        let Some((node_id, node_key)) = payload.split_once('#') else {
            return Err(crate::Error::InvalidPublicUrlFormat);
        };
        if node_id.is_empty() || node_key.split('/').next().is_none_or(str::is_empty) {
            return Err(crate::Error::InvalidPublicUrlFormat);
        }

        Ok(Self(value.to_owned()))
    }

    /// Returns the original link text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PublicLink {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PublicLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for PublicLink {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for PublicLink {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

/// A byte count used at the download protocol boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileSize(u64);

impl FileSize {
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> u64 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the inclusive range covering this file, or `None` for an empty file.
    pub const fn range(self) -> Option<ByteRange> {
        if self.0 == 0 {
            None
        } else {
            Some(ByteRange {
                start: 0,
                end: self.0 - 1,
            })
        }
    }
}

impl From<u64> for FileSize {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<FileSize> for u64 {
    fn from(value: FileSize) -> Self {
        value.bytes()
    }
}

/// An inclusive byte range used by MEGA transfer URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    /// Creates an inclusive range, rejecting inverted ranges.
    pub const fn new(start: u64, end: u64) -> Option<Self> {
        if start > end {
            None
        } else {
            Some(Self { start, end })
        }
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn len(self) -> Option<u64> {
        match self.end.checked_sub(self.start) {
            Some(length) => length.checked_add(1),
            None => None,
        }
    }

    pub const fn is_empty(self) -> bool {
        false
    }
}

/// A server-provided MEGA transfer URL before a byte range is appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferUrl(Url);

impl TransferUrl {
    pub fn parse(value: &str) -> Result<Self> {
        let url = Url::parse(value)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(crate::Error::InvalidResponseFormat);
        }
        Ok(Self(url))
    }

    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Builds a ranged transfer URL without exposing string concatenation to callers.
    pub fn for_range(&self, range: ByteRange) -> Url {
        let mut url = self.0.clone();
        let path = format!(
            "{}/{}-{}",
            url.path().trim_end_matches('/'),
            range.start(),
            range.end()
        );
        url.set_path(&path);
        url
    }
}

impl TryFrom<&str> for TransferUrl {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for TransferUrl {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl fmt::Display for TransferUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteRange, FileSize, PublicLink, TransferUrl};

    #[test]
    fn public_link_accepts_supported_file_and_folder_links() {
        let file = PublicLink::parse("https://mega.nz/file/abc#key").unwrap();
        let folder = PublicLink::parse("https://mega.nz/folder/abc#key/subfolder").unwrap();

        assert_eq!(file.as_str(), "https://mega.nz/file/abc#key");
        assert_eq!(
            folder.to_string(),
            "https://mega.nz/folder/abc#key/subfolder"
        );
    }

    #[test]
    fn public_link_rejects_other_origins_and_missing_fragments() {
        assert!(PublicLink::parse("https://example.test/file/abc#key").is_err());
        assert!(PublicLink::parse("https://mega.nz/file/abc").is_err());
        assert!(PublicLink::parse("https://mega.nz/unknown/abc#key").is_err());
    }

    #[test]
    fn file_size_and_byte_range_define_inclusive_boundaries() {
        assert_eq!(FileSize::new(0).range(), None);
        let range = FileSize::new(100).range().unwrap();
        assert_eq!(range, ByteRange::new(0, 99).unwrap());
        assert_eq!(range.start(), 0);
        assert_eq!(range.end(), 99);
        assert_eq!(range.len(), Some(100));
        assert_eq!(ByteRange::new(10, 9), None);
    }

    #[test]
    fn transfer_url_appends_an_inclusive_range_without_losing_query() {
        let transfer = TransferUrl::parse("https://download.example/file?token=abc").unwrap();
        let ranged = transfer.for_range(ByteRange::new(0, 99).unwrap());

        assert_eq!(
            ranged.as_str(),
            "https://download.example/file/0-99?token=abc"
        );
    }
}
