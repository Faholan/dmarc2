//! Common enums and structs between the borrowed and owned variants.

use core::str::FromStr;
use core::fmt::{Display, Formatter, Result as FmtResult};

use bitflags::bitflags;
use serde::{Deserialize, de};

/// UTC time range, expressed as Unix timestamps,
/// defining the reporting period of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct DateRange {
    /// Start of the reporting period.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub begin: i64,
    /// End of the reporting period.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub end: i64,
}

// Some DMARC reporters don't respect the RFC and put the timestamps as floating-point values, not integers
// This workaround allows us to parse both as integers
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
struct TimestampField {
    #[serde(rename = "$text", deserialize_with = "deserialize_int")]
    value: i64,
}

fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: de::Deserializer<'de>,
{
    let t: TimestampField = Deserialize::deserialize(deserializer)?;

    Ok(t.value)
}

fn deserialize_int<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    #[expect(
        clippy::unwrap_used,
        reason = "The iterator returned by .split has at least one element"
    )]
    s.trim_start_matches('"')
        .trim_end_matches('"')
        .split('.')
        .next()
        .unwrap()
        .parse()
        .map_err(de::Error::custom)
}

/// Method used to discover the DMARC policy.
///
/// Defined in [RFC 9990 section 3.1.1.5](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMethod {
    /// PSL method, defined in [RFC 7489](https://www.rfc-editor.org/info/rfc7489/).
    PSL,
    /// Treewalk method, defined in [RFC 9989](https://www.rfc-editor.org/info/rfc9989/).
    TreeWalk,
}

impl Display for DiscoveryMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::PSL => write!(f, "psl"),
            Self::TreeWalk => write!(f, "treewalk"),
        }
    }
}

/// Message handling preferences for messages failing DMARC validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// Treat the mail as suspicious.
    Quarantine,
    /// Reject the mail.
    Reject,
    /// Deliver the mail normally.
    #[cfg_attr(not(any(test, feature = "strict")), serde(other))]
    None,
}

impl Display for Disposition {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Quarantine => write!(f, "quarantine"),
            Self::Reject => write!(f, "reject"),
            Self::None => write!(f, "none"),
        }
    }
}

bitflags! {
    /// DMARC failure reporting options.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FailureReporting: u8 {
        /// Generate a failure report if all authentication mechanisms fail.
        const ALL = 0b0000_0000;
        /// Generate a failure report if any authentication mechanism fails.
        const ANY = 0b0000_0001;
        /// Generate a failure report if the message had a signature that failed verification.
        const DKIM = 0b000_00010;
        /// Generate a failure report if the messaged failed SPF evaluation.
        const SPF = 0b0000_0100;
    }
}

impl FromStr for FailureReporting {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = Self::ALL;

        for v in s.split(':') {
            match v {
                "0" => {}
                "1" => res |= Self::ANY,
                "d" => res |= Self::DKIM,
                "s" => res |= Self::SPF,
                v => {
                    if cfg!(any(test, feature = "strict")) {
                        return Err(format!("Invalid failure reporting option {v}"));
                    }
                }
            }
        }
        Ok(res)
    }
}

impl Display for FailureReporting {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if Self::contains(self, Self::ANY) {
            write!(f, "1")?;
        } else {
            write!(f, "0")?;
        }
        if Self::contains(self, Self::DKIM) {
            write!(f, ":d")?;
        }
        if Self::contains(self, Self::SPF) {
            write!(f, ":s")?;
        }
        Ok(())
    }
}

pub(crate) fn deserialize_failure_reporting<'de, D>(
    deserializer: D,
) -> Result<Option<FailureReporting>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: Option<&'de str> = Deserialize::deserialize(deserializer)?;

    s.map_or(Ok(None), |s| {
        FromStr::from_str(s).map(Some).map_err(de::Error::custom)
    })
}

pub(crate) fn deserialize_testing<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: Option<&'de str> = Deserialize::deserialize(deserializer)?;
    s.map_or(Ok(None), |s| match s {
        "y" => Ok(Some(true)),
        "n" => Ok(Some(false)),
        _ => {
            if cfg!(any(test, feature = "strict")) {
                Err(de::Error::custom(format!(
                    "Invalid testing value {s}, expected \"y\" or \"n\""
                )))
            } else {
                Ok(Some(false))
            }
        }
    })
}

/// Alignment mode for DKIM or SPF.
///
/// See [RFC 9989 section 4.4.1](https://www.rfc-editor.org/info/rfc9989#section-4.4.1) for DKIM,
/// and [RFC 9989 section 4.4.2](https://www.rfc-editor.org/info/rfc9989#section-4.4.2) for SPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum AlignmentMode {
    /// Relaxed mode.
    #[serde(rename = "r")]
    Relaxed,

    /// Strict mode.
    #[serde(rename = "s")]
    Strict,
}

impl Display for AlignmentMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Relaxed => write!(f, "r"),
            Self::Strict => write!(f, "s"),
        }
    }
}

/// Result of a DMARC alignment test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlignmentResult {
    /// Authentication succeeded.
    Pass,
    /// Authentication failed.
    Fail,
}

impl Display for AlignmentResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
        }
    }
}

/// Result of DKIM signature verification.
///
/// Defined in [RFC 8601 section 2.7.1](https://www.rfc-editor.org/info/rfc8601/#section-2.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DKIMResult {
    /// The message wasn't signed.
    None,
    /// The messaged was signed, and the signature(s) passed verification tests.
    Pass,
    /// The message was signed, but the signature(s) failed the verification tests.
    Fail,
    /// The message was signed, but the signature(s) weren't accepted by the Administrative Management Domain.
    Policy,
    /// The message was signed, but the signature(s) contained syntax errors
    /// or were otherwise unprocessable. Default result in case of uncovered error.
    #[serde(alias = "NEUTRAL")] // Seen in a real-world example
    Neutral,
    /// The message couldn't be verified due to a likely temporary error.
    TempError,
    /// The message couldn't be verified due to an unrecoverable error.
    PermError,
}

impl Display for DKIMResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => write!(f, "none"),
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Policy => write!(f, "policy"),
            Self::Neutral => write!(f, "neutral"),
            Self::TempError => write!(f, "temperror"),
            Self::PermError => write!(f, "permerror"),
        }
    }
}

/// SPF domain source.
///
/// Defined in [RFC 9990 section 3.1.13](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SPFScope {
    /// "MAIL FROM" identity.
    MFrom,
}

impl Display for SPFScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::MFrom => write!(f, "mfrom"),
        }
    }
}

/// Result of SPF authentication.
///
/// Defined in [RFC 8601 section 2.7.2](https://www.rfc-editor.org/info/rfc8601/#section-2.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SPFResult {
    /// No valid domain could be retrieved, or no SPF record could be retrieved from DNS.
    ///
    /// See [RFC 7208 section 2.6.1](https://www.rfc-editor.org/info/rfc7208/#section-2.6.1).
    None,
    /// The given client is authorized to inject mail with the given identity.
    ///
    /// See [RFC 7208 section 2.6.3](https://www.rfc-editor.org/info/rfc7208/#section-2.6.3).
    Pass,
    /// The given client is forbidden from using the domain in the given identity.
    ///
    /// See [RFC 7208 section 2.6.4](https://www.rfc-editor.org/info/rfc7208/#section-2.6.4).
    Fail,
    /// The given client is probably unauthorized.
    ///
    /// See [RFC 7208 section 2.6.5](https://www.rfc-editor.org/info/rfc7208/#section-2.6.5).
    SoftFail,
    /// The client was authorized, but local policy didn't accept this result.
    Policy,
    /// There is no result on whether the given IP is authorized or not.
    ///
    /// See [RFC 7208 section 2.6.2](https://www.rfc-editor.org/info/rfc7208/#section-2.6.2).
    #[serde(alias = "NEUTRAL")] // Seen in a real-world example
    Neutral,
    /// Verification failed due to a temporary error.
    ///
    /// See [RFC 7208 section 2.6.6](https://www.rfc-editor.org/info/rfc7208/#section-2.6.6).
    TempError,
    /// The domain's records could not be interpreted.
    ///
    /// See [RFC 7208 section 2.6.7](https://www.rfc-editor.org/info/rfc7208/#section-2.6.7).
    PermError,
}

impl Display for SPFResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => write!(f, "none"),
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::SoftFail => write!(f, "softfail"),
            Self::Policy => write!(f, "policy"),
            Self::Neutral => write!(f, "neutral"),
            Self::TempError => write!(f, "temperror"),
            Self::PermError => write!(f, "permerror"),
        }
    }
}

/// Reason for changing the stated DMARC policy.
///
/// Defined in [RFC 9990 section 3.1.6](https://www.rfc-editor.org/info/rfc9990/#section-3.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOverrideReasonType {
    /// Local policy overrode the published DMARC policy.
    LocalPolicy,
    /// Messaged arrived via a mailing list.
    MailingList,
    /// Other reason.
    Other,
    /// Message was exempted due to the policy being in test mode.
    PolicyTestMode,
    /// Message was from a trusted forwarder.
    TrustedForwarder,
}

impl Display for PolicyOverrideReasonType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::LocalPolicy => write!(f, "local_policy"),
            Self::MailingList => write!(f, "mailing_list"),
            Self::Other => write!(f, "other"),
            Self::PolicyTestMode => write!(f, "policy_test_mode"),
            Self::TrustedForwarder => write!(f, "trusted_forwarder"),
        }
    }
}

// Trait implementations
impl From<bool> for AlignmentResult {
    fn from(value: bool) -> Self {
        if value { Self::Pass } else { Self::Fail }
    }
}

impl From<AlignmentResult> for bool {
    fn from(value: AlignmentResult) -> Self {
        matches!(value, AlignmentResult::Pass)
    }
}
