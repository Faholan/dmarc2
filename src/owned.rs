//! Owned version of a DMARC aggregate report.

use core::net::IpAddr;

use serde::Deserialize;

pub use crate::common::{
    AlignmentMode, AlignmentResult, DKIMResult, DateRange, DiscoveryMethod, Disposition,
    FailureReporting, FailureReportingParseError, PolicyOverrideReasonType, SPFResult, SPFScope,
};
use crate::common::{deserialize_failure_reporting, deserialize_testing};

/// DMARC aggregate feedback report.
///
/// Defined as the root XML element in [RFC 9990 section 3.1.1.1](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.1) (`<feedback>`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename = "feedback")]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Report {
    /// Report format version (optional).
    pub version: Option<String>,

    /// Report generator metadata.
    pub report_metadata: ReportMetadata,

    /// DMARC policy configuration observed by the receiving system.
    pub policy_published: PolicyPublished,

    /// Record(s) of the feedback from the report generator.
    #[serde(rename = "record")]
    pub records: Vec<Record>,

    // Extra fields that should be ignored
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "extension")]
    _junk1: (),
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "@xmlns")]
    _junk2: (),
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "@xmlns:tns")]
    _junk3: (),
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "@xmlns:xs")]
    _junk4: (),
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "@xmlns:xsd")]
    _junk5: (),
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "@xmlns:xsi")]
    _junk6: (),
}

/// Report generator metadata.
///
/// Defined in [RFC 9990 section 3.1.1.3](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct ReportMetadata {
    /// Name of the Reporting Organization.
    pub org_name: String,

    /// Contact to use when contacting the Reporting Organization.
    pub email: String,

    /// Additional contact details.
    pub extra_contact_info: Option<String>,

    /// Unique Report-ID.
    pub report_id: String,

    /// Reporting period.
    pub date_range: DateRange,

    /// Error messages encountered when processing the DMARC Policy Record.
    #[serde(default, rename = "error")]
    pub errors: Vec<String>,

    /// Name and version of the report generator.
    pub generator: Option<String>,
}

/// DMARC policy published for the Author Domain.
///
/// Defined in [RFC 9990 section 3.1.1.5](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct PolicyPublished {
    /// DMARC policy domain.
    pub domain: String,

    /// Method used to discover the DMARC Policy Record used during evaluation.
    pub discovery_method: Option<DiscoveryMethod>,

    /// Policy action applied to the domain.
    pub p: Disposition,

    /// Policy action applied to subdomains that exist in DNS records.
    pub sp: Option<Disposition>,

    /// Policy action applied to subdomains that don't exist in DNS records.
    pub np: Option<Disposition>,

    /// Failure reporting options.
    #[serde(default, deserialize_with = "deserialize_failure_reporting")]
    pub fo: Option<FailureReporting>,

    /// DKIM alignment mode.
    pub adkim: Option<AlignmentMode>,

    /// SPF alignment mode.
    pub aspf: Option<AlignmentMode>,

    /// Percentage of messages to which the policy is applied (0-100).
    pub pct: Option<u32>,

    /// DMARC policy test mode.
    #[serde(default, deserialize_with = "deserialize_testing")]
    pub testing: Option<bool>,
}

/// Record of the DMARC result for a set of messages.
///
/// Defined in [RFC 9990 section 3.1.1.7](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Record {
    /// Status of the system for the given set of messages.
    pub row: Row,

    /// Identifiers extracted from the messages.
    pub identifiers: Identifiers,

    /// Result of the authentication tests.
    pub auth_results: AuthResults,
}

/// Row information about a given record.
///
/// Defined in [RFC 9990 section 3.1.1.8](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.8).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Row {
    /// Connecting IP address of the mail server.
    pub source_ip: IpAddr,

    /// Number of messages on which the policy was applied.
    pub count: u64,

    /// DMARC disposition applied to matching messages.
    pub policy_evaluated: PolicyEvaluated,
}

/// DMARC policy effectively applied to the messages.
///
/// Defined in [RFC 9990 section 3.1.1.9](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.9).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct PolicyEvaluated {
    /// Result of applying the DMARC policy.
    pub disposition: Disposition,

    /// Result of the DKIM alignment test.
    pub dkim: AlignmentResult,

    /// Result of the SPF alignment test.
    pub spf: AlignmentResult,

    /// Potential reasons for changing the policy.
    #[serde(default)]
    pub reason: Vec<PolicyOverrideReason>,
}

/// Identifiers extracted from a message.
///
/// Defined in [RFC 9990 section 3.1.10](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.10).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Identifiers {
    /// Message `From` domain, as defined in [RFC 5322](https://www.rfc-editor.org/info/rfc5322/).
    pub header_from: String,

    /// `MailFrom` domain that the SPF check has been applied to, as defined in [RFC 5321](https://www.rfc-editor.org/info/rfc5321/), if any.
    pub envelope_from: Option<String>,

    /// `RcpTo` domain from the message, as defined in [RFC 5321](https://www.rfc-editor.org/info/rfc5321/), if any.
    pub envelope_to: Option<String>,
}

/// Uninterpreted DKIM and SPF results.
///
/// Defined in [RFC 9990 section 3.1.11](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.11).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct AuthResults {
    /// DKIM authentication results (zero or more).
    #[serde(default)]
    pub dkim: Vec<DKIMAuthResult>,

    /// SPF authentication result (zero or one).
    pub spf: Option<SPFAuthResult>,
}
/// Result of evaluating a DKIM signature.
///
/// Defined in [RFC 9990 section 3.1.12](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.12).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct DKIMAuthResult {
    /// Domain used during validation ("d=" tag of the signature).
    pub domain: String,

    /// Selector used during validation ("s=" tag of the signature).
    #[serde(default)]
    // Some DMARC implementations forego the selector even though it is required by the RFC.
    pub selector: String,

    /// Result of the DKIM verification.
    pub result: DKIMResult,

    /// Descriptive information about the failure.
    pub human_result: Option<String>,
}

/// Result of validating with SPF.
///
/// Defined in [RFC 9990 section 3.1.13](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.13).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct SPFAuthResult {
    /// Domain used during validation.
    #[serde(default)]
    // Some DMARC implementations forego the domain even though it is required by the RFC.
    pub domain: String,

    /// Source of the domain used during validation.
    pub scope: Option<SPFScope>,

    /// Result of the SPF verification.
    pub result: SPFResult,

    /// Descriptive information about the failure.
    pub human_result: Option<String>,
}

/// Reason for changing the published policy.
///
/// Defined in [RFC 9990 section 3.1.14](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.14).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct PolicyOverrideReason {
    /// Reason for changing the policy.
    #[serde(rename = "type")]
    pub reason_type: PolicyOverrideReasonType,

    /// Details about why the policy was changed.
    pub comment: Option<String>,
}

impl Report {
    /// Create a new DMARC report.
    #[must_use]
    pub const fn new(
        version: Option<String>,
        report_metadata: ReportMetadata,
        policy_published: PolicyPublished,
        records: Vec<Record>,
    ) -> Self {
        #[cfg(any(test, feature = "strict"))]
        return Self {
            version,
            report_metadata,
            policy_published,
            records,
            _junk1: (),
            _junk2: (),
            _junk3: (),
            _junk4: (),
            _junk5: (),
            _junk6: (),
        };

        #[cfg(not(any(test, feature = "strict")))]
        Self {
            version,
            report_metadata,
            policy_published,
            records,
        }
    }
}
