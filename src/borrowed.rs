//! Zero-copy version of a DMARC aggregate report.

use core::net::IpAddr;

use serde::Deserialize;

pub use crate::common::{
    AlignmentMode, AlignmentResult, DKIMResult, DateRange, DiscoveryMethod, Disposition,
    FailureReporting, PolicyOverrideReasonType, SPFResult, SPFScope,
};
use crate::common::{deserialize_failure_reporting, deserialize_testing};
use crate::owned;

/// DMARC aggregate feedback report.
///
/// Defined as the root XML element in [RFC 9990 section 3.1.1.1](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.1) (`<feedback>`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename = "feedback")]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Report<'a> {
    /// Report format version (optional).
    pub version: Option<&'a str>,

    /// Report generator metadata.
    #[serde(borrow)]
    pub report_metadata: ReportMetadata<'a>,

    /// DMARC policy configuration observed by the receiving system.
    #[serde(borrow)]
    pub policy_published: PolicyPublished<'a>,

    /// Record(s) of the feedback from the report generator.
    #[serde(borrow, rename = "record")]
    pub records: Vec<Record<'a>>,

    // Extra fields that should be discarded
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
    #[cfg(any(test, feature = "strict"))]
    #[serde(default, rename = "@xmlns:ext")]
    _junk7: (),
}

/// Report generator metadata.
///
/// Defined in [RFC 9990 section 3.1.1.3](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct ReportMetadata<'a> {
    /// Name of the Reporting Organization.
    pub org_name: &'a str,

    /// Contact to use when contacting the Reporting Organization.
    pub email: &'a str,

    /// Additional contact details.
    pub extra_contact_info: Option<&'a str>,

    /// Unique Report-ID.
    pub report_id: &'a str,

    /// Reporting period.
    pub date_range: DateRange,

    /// Error messages encountered when processing the DMARC Policy Record.
    #[serde(default, rename = "error")]
    pub errors: Vec<&'a str>,

    /// Name and version of the report generator.
    pub generator: Option<&'a str>,
}

/// DMARC policy published for the Author Domain.
///
/// Defined in [RFC 9990 section 3.1.1.5](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct PolicyPublished<'a> {
    /// DMARC policy domain.
    pub domain: &'a str,

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
pub struct Record<'a> {
    /// Status of the system for the given set of messages.
    #[serde(borrow)]
    pub row: Row<'a>,

    /// Identifiers extracted from the messages.
    #[serde(borrow)]
    pub identifiers: Identifiers<'a>,

    /// Result of the authentication tests.
    #[serde(borrow)]
    pub auth_results: AuthResults<'a>,
}

/// Row information about a given record.
///
/// Defined in [RFC 9990 section 3.1.1.8](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.8).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Row<'a> {
    /// Connecting IP address of the mail server.
    pub source_ip: IpAddr,

    /// Number of messages on which the policy was applied.
    pub count: u64,

    /// DMARC disposition applied to matching messages.
    #[serde(borrow)]
    pub policy_evaluated: PolicyEvaluated<'a>,
}

/// DMARC policy effectively applied to the messages.
///
/// Defined in [RFC 9990 section 3.1.1.9](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.9).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct PolicyEvaluated<'a> {
    /// Result of applying the DMARC policy.
    pub disposition: Disposition,

    /// Result of the DKIM alignment test.
    pub dkim: AlignmentResult,

    /// Result of the SPF alignment test.
    pub spf: AlignmentResult,

    /// Potential reasons for changing the policy.
    #[serde(default, borrow)]
    pub reason: Vec<PolicyOverrideReason<'a>>,
}

/// Identifiers extracted from a message.
///
/// Defined in [RFC 9990 section 3.1.10](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct Identifiers<'a> {
    /// Message `From` domain, as defined in [RFC 5322](https://www.rfc-editor.org/info/rfc5322/).
    pub header_from: &'a str,

    /// `MailFrom` domain that the SPF check has been applied to, as defined in [RFC 5321](https://www.rfc-editor.org/info/rfc5321/), if any.
    pub envelope_from: Option<&'a str>,

    /// `RcpTo` domain from the message, as defined in [RFC 5321](https://www.rfc-editor.org/info/rfc5321/), if any.
    pub envelope_to: Option<&'a str>,
}

/// Uninterpreted DKIM and SPF results.
///
/// Defined in [RFC 9990 section 3.1.11](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.11).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct AuthResults<'a> {
    /// DKIM authentication results (zero or more).
    #[serde(default, borrow)]
    pub dkim: Vec<DKIMAuthResult<'a>>,

    /// SPF authentication result (zero or one).
    #[serde(borrow)]
    pub spf: Option<SPFAuthResult<'a>>,
}

/// Result of evaluating a DKIM signature.
///
/// Defined in [RFC 9990 section 3.1.12](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct DKIMAuthResult<'a> {
    /// Domain used during validation ("d=" tag of the signature).
    pub domain: &'a str,

    /// Selector used during validation ("s=" tag of the signature).
    #[serde(default)]
    // Some DMARC implementations forego the selector even though it is required by the RFC.
    pub selector: &'a str,

    /// Result of the DKIM verification.
    pub result: DKIMResult,

    /// Descriptive information about the failure.
    pub human_result: Option<&'a str>,
}

/// Result of validating with SPF.
///
/// Defined in [RFC 9990 section 3.1.13](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct SPFAuthResult<'a> {
    /// Domain used during validation.
    #[serde(default)]
    // Some DMARC implementations forego the domain even though it is required by the RFC.
    pub domain: &'a str,

    /// Source of the domain used during validation.
    pub scope: Option<SPFScope>,

    /// Result of the SPF verification.
    pub result: SPFResult,

    /// Descriptive information about the failure.
    pub human_result: Option<&'a str>,
}

/// Reason for changing the published policy.
///
/// Defined in [RFC 9990 section 3.1.14](https://www.rfc-editor.org/info/rfc9990/#section-3.1.1.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(any(test, feature = "strict"), serde(deny_unknown_fields))]
pub struct PolicyOverrideReason<'a> {
    /// Reason for changing the policy.
    #[serde(rename = "type")]
    pub reason_type: PolicyOverrideReasonType,

    /// Details about why the policy was changed.
    pub comment: Option<&'a str>,
}

// Conversion
impl<'a> From<Report<'a>> for owned::Report {
    fn from(value: Report<'a>) -> Self {
        Self::new(
            value.version.map(ToOwned::to_owned),
            value.report_metadata.into(),
            value.policy_published.into(),
            value.records.into_iter().map(From::from).collect(),
        )
    }
}
impl<'a> From<&Report<'a>> for owned::Report {
    fn from(value: &Report<'a>) -> Self {
        Self::new(
            value.version.map(ToOwned::to_owned),
            From::from(&value.report_metadata),
            From::from(&value.policy_published),
            value.records.iter().map(From::from).collect(),
        )
    }
}

impl<'a> From<ReportMetadata<'a>> for owned::ReportMetadata {
    fn from(value: ReportMetadata<'a>) -> Self {
        Self {
            org_name: value.org_name.to_owned(),
            email: value.email.to_owned(),
            extra_contact_info: value.extra_contact_info.map(ToOwned::to_owned),
            report_id: value.report_id.to_owned(),
            date_range: value.date_range,
            errors: value.errors.into_iter().map(ToOwned::to_owned).collect(),
            generator: value.generator.map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<&ReportMetadata<'a>> for owned::ReportMetadata {
    fn from(value: &ReportMetadata<'a>) -> Self {
        Self {
            org_name: value.org_name.to_owned(),
            email: value.email.to_owned(),
            extra_contact_info: value.extra_contact_info.map(ToOwned::to_owned),
            report_id: value.report_id.to_owned(),
            date_range: value.date_range,
            errors: value.errors.iter().map(ToString::to_string).collect(),
            generator: value.generator.map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<PolicyPublished<'a>> for owned::PolicyPublished {
    fn from(value: PolicyPublished<'a>) -> Self {
        Self {
            domain: value.domain.to_owned(),
            discovery_method: value.discovery_method,
            p: value.p,
            sp: value.sp,
            np: value.np,
            fo: value.fo,
            adkim: value.adkim,
            aspf: value.aspf,
            pct: value.pct,
            testing: value.testing,
        }
    }
}

impl<'a> From<&PolicyPublished<'a>> for owned::PolicyPublished {
    fn from(value: &PolicyPublished<'a>) -> Self {
        Self {
            domain: value.domain.to_owned(),
            discovery_method: value.discovery_method,
            p: value.p,
            sp: value.sp,
            np: value.np,
            fo: value.fo,
            adkim: value.adkim,
            aspf: value.aspf,
            pct: value.pct,
            testing: value.testing,
        }
    }
}

impl<'a> From<Record<'a>> for owned::Record {
    fn from(value: Record<'a>) -> Self {
        Self {
            row: value.row.into(),
            identifiers: value.identifiers.into(),
            auth_results: value.auth_results.into(),
        }
    }
}

impl<'a> From<&Record<'a>> for owned::Record {
    fn from(value: &Record<'a>) -> Self {
        Self {
            row: From::from(&value.row),
            identifiers: value.identifiers.into(),
            auth_results: From::from(&value.auth_results),
        }
    }
}

impl<'a> From<Row<'a>> for owned::Row {
    fn from(value: Row<'a>) -> Self {
        Self {
            source_ip: value.source_ip,
            count: value.count,
            policy_evaluated: value.policy_evaluated.into(),
        }
    }
}

impl<'a> From<&Row<'a>> for owned::Row {
    fn from(value: &Row<'a>) -> Self {
        Self {
            source_ip: value.source_ip,
            count: value.count,
            policy_evaluated: From::from(&value.policy_evaluated),
        }
    }
}

impl<'a> From<PolicyEvaluated<'a>> for owned::PolicyEvaluated {
    fn from(value: PolicyEvaluated<'a>) -> Self {
        Self {
            disposition: value.disposition,
            dkim: value.dkim,
            spf: value.spf,
            reason: value.reason.into_iter().map(From::from).collect(),
        }
    }
}

impl<'a> From<&PolicyEvaluated<'a>> for owned::PolicyEvaluated {
    fn from(value: &PolicyEvaluated<'a>) -> Self {
        Self {
            disposition: value.disposition,
            dkim: value.dkim,
            spf: value.spf,
            reason: value.reason.iter().map(From::from).collect(),
        }
    }
}

impl<'a> From<Identifiers<'a>> for owned::Identifiers {
    fn from(value: Identifiers<'a>) -> Self {
        Self {
            header_from: value.header_from.to_owned(),
            envelope_from: value.envelope_from.map(ToOwned::to_owned),
            envelope_to: value.envelope_to.map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<&Identifiers<'a>> for owned::Identifiers {
    fn from(value: &Identifiers<'a>) -> Self {
        From::from(*value)
    }
}

impl<'a> From<AuthResults<'a>> for owned::AuthResults {
    fn from(value: AuthResults<'a>) -> Self {
        Self {
            dkim: value.dkim.into_iter().map(From::from).collect(),
            spf: value.spf.map(From::from),
        }
    }
}

impl<'a> From<&AuthResults<'a>> for owned::AuthResults {
    fn from(value: &AuthResults<'a>) -> Self {
        Self {
            dkim: value.dkim.iter().map(From::from).collect(),
            spf: value.spf.map(From::from),
        }
    }
}

impl<'a> From<DKIMAuthResult<'a>> for owned::DKIMAuthResult {
    fn from(value: DKIMAuthResult<'a>) -> Self {
        Self {
            domain: value.domain.to_owned(),
            selector: value.selector.to_owned(),
            result: value.result,
            human_result: value.human_result.map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<&DKIMAuthResult<'a>> for owned::DKIMAuthResult {
    fn from(value: &DKIMAuthResult<'a>) -> Self {
        From::from(*value)
    }
}

impl<'a> From<SPFAuthResult<'a>> for owned::SPFAuthResult {
    fn from(value: SPFAuthResult<'a>) -> Self {
        Self {
            domain: value.domain.to_owned(),
            scope: value.scope,
            result: value.result,
            human_result: value.human_result.map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<&SPFAuthResult<'a>> for owned::SPFAuthResult {
    fn from(value: &SPFAuthResult<'a>) -> Self {
        From::from(*value)
    }
}

impl<'a> From<PolicyOverrideReason<'a>> for owned::PolicyOverrideReason {
    fn from(value: PolicyOverrideReason<'a>) -> Self {
        Self {
            reason_type: value.reason_type,
            comment: value.comment.map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<&PolicyOverrideReason<'a>> for owned::PolicyOverrideReason {
    fn from(value: &PolicyOverrideReason<'a>) -> Self {
        From::from(*value)
    }
}

// Comparison.
impl<'a> PartialEq<Report<'a>> for owned::Report {
    fn eq(&self, other: &Report<'a>) -> bool {
        self.version.as_deref() == other.version
            && self.report_metadata == other.report_metadata
            && self.policy_published == other.policy_published
            && self.records == other.records
    }
}

impl PartialEq<owned::Report> for Report<'_> {
    fn eq(&self, other: &owned::Report) -> bool {
        other == self
    }
}

impl<'a> PartialEq<ReportMetadata<'a>> for owned::ReportMetadata {
    fn eq(&self, other: &ReportMetadata<'a>) -> bool {
        self.org_name == other.org_name
            && self.email == other.email
            && self.extra_contact_info.as_deref() == other.extra_contact_info
            && self.report_id == other.report_id
            && self.date_range == other.date_range
            && self.errors == other.errors
            && self.generator.as_deref() == other.generator
    }
}

impl PartialEq<owned::ReportMetadata> for ReportMetadata<'_> {
    fn eq(&self, other: &owned::ReportMetadata) -> bool {
        other == self
    }
}

impl<'a> PartialEq<PolicyPublished<'a>> for owned::PolicyPublished {
    fn eq(&self, other: &PolicyPublished<'a>) -> bool {
        self.domain == other.domain
            && self.discovery_method == other.discovery_method
            && self.p == other.p
            && self.np == other.np
            && self.fo == other.fo
            && self.adkim == other.adkim
            && self.aspf == other.aspf
            && self.pct == other.pct
            && self.testing == other.testing
    }
}

impl PartialEq<owned::PolicyPublished> for PolicyPublished<'_> {
    fn eq(&self, other: &owned::PolicyPublished) -> bool {
        other == self
    }
}

impl<'a> PartialEq<Record<'a>> for owned::Record {
    fn eq(&self, other: &Record<'a>) -> bool {
        self.row == other.row
            && self.identifiers == other.identifiers
            && self.auth_results == other.auth_results
    }
}

impl PartialEq<owned::Record> for Record<'_> {
    fn eq(&self, other: &owned::Record) -> bool {
        other == self
    }
}

impl<'a> PartialEq<Row<'a>> for owned::Row {
    fn eq(&self, other: &Row<'a>) -> bool {
        self.source_ip == other.source_ip
            && self.count == other.count
            && self.policy_evaluated == other.policy_evaluated
    }
}

impl PartialEq<owned::Row> for Row<'_> {
    fn eq(&self, other: &owned::Row) -> bool {
        other == self
    }
}

impl<'a> PartialEq<PolicyEvaluated<'a>> for owned::PolicyEvaluated {
    fn eq(&self, other: &PolicyEvaluated<'a>) -> bool {
        self.disposition == other.disposition
            && self.dkim == other.dkim
            && self.spf == other.spf
            && self.reason == other.reason
    }
}

impl PartialEq<owned::PolicyEvaluated> for PolicyEvaluated<'_> {
    fn eq(&self, other: &owned::PolicyEvaluated) -> bool {
        other == self
    }
}

impl<'a> PartialEq<Identifiers<'a>> for owned::Identifiers {
    fn eq(&self, other: &Identifiers<'a>) -> bool {
        self.header_from == other.header_from
            && self.envelope_from.as_deref() == other.envelope_from
            && self.envelope_to.as_deref() == other.envelope_to
    }
}

impl PartialEq<owned::Identifiers> for Identifiers<'_> {
    fn eq(&self, other: &owned::Identifiers) -> bool {
        other == self
    }
}

impl<'a> PartialEq<AuthResults<'a>> for owned::AuthResults {
    fn eq(&self, other: &AuthResults<'a>) -> bool {
        self.dkim == other.dkim
            && match (&self.spf, &other.spf) {
                (None, None) => true,
                (None, _) | (_, None) => false,
                (Some(self_spf), Some(other_spf)) => self_spf == other_spf,
            }
    }
}

impl PartialEq<owned::AuthResults> for AuthResults<'_> {
    fn eq(&self, other: &owned::AuthResults) -> bool {
        other == self
    }
}

impl<'a> PartialEq<DKIMAuthResult<'a>> for owned::DKIMAuthResult {
    fn eq(&self, other: &DKIMAuthResult<'a>) -> bool {
        self.domain == other.domain
            && self.selector == other.selector
            && self.result == other.result
            && self.human_result.as_deref() == other.human_result
    }
}
impl PartialEq<owned::DKIMAuthResult> for DKIMAuthResult<'_> {
    fn eq(&self, other: &owned::DKIMAuthResult) -> bool {
        other == self
    }
}

impl<'a> PartialEq<SPFAuthResult<'a>> for owned::SPFAuthResult {
    fn eq(&self, other: &SPFAuthResult<'a>) -> bool {
        self.domain == other.domain
            && self.scope == other.scope
            && self.result == other.result
            && self.human_result.as_deref() == other.human_result
    }
}

impl PartialEq<owned::SPFAuthResult> for SPFAuthResult<'_> {
    fn eq(&self, other: &owned::SPFAuthResult) -> bool {
        other == self
    }
}

impl<'a> PartialEq<PolicyOverrideReason<'a>> for owned::PolicyOverrideReason {
    fn eq(&self, other: &PolicyOverrideReason<'a>) -> bool {
        self.reason_type == other.reason_type && self.comment.as_deref() == other.comment
    }
}

impl PartialEq<owned::PolicyOverrideReason> for PolicyOverrideReason<'_> {
    fn eq(&self, other: &owned::PolicyOverrideReason) -> bool {
        other == self
    }
}
