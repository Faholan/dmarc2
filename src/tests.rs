#![allow(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::cognitive_complexity
)]
use core::net::{IpAddr, Ipv4Addr};

use crate::{from_str, from_str_owned, owned};
use quick_xml::de::DeError;

const RFC_SAMPLE: &str = include_str!("tests/rfc.xml");

#[test]
fn rfc_sample() -> Result<(), DeError> {
    let report = from_str(RFC_SAMPLE)?;
    let report_owned = from_str_owned(RFC_SAMPLE)?;
    assert_eq!(report, report_owned);

    let report_borrowed_owned: owned::Report = From::from(&report);

    assert_eq!(report_borrowed_owned, report_owned);

    assert_eq!(report.report_metadata.org_name, "Sample Reporter");
    assert_eq!(
        report.report_metadata.email,
        "report_sender@example-reporter.com"
    );
    assert_eq!(report.report_metadata.extra_contact_info, Some("..."));
    assert_eq!(
        report.report_metadata.report_id,
        "3v98abbp8ya9n3va8yr8oa3ya"
    );
    assert_eq!(report.report_metadata.date_range.begin, 302_832_000);
    assert_eq!(report.report_metadata.date_range.end, 302_918_399);
    assert!(report.report_metadata.errors.is_empty());
    assert_eq!(
        report.report_metadata.generator,
        Some("Example DMARC Aggregate Reporter v1.2")
    );
    assert_eq!(report.policy_published.domain, "example.com");
    assert_eq!(report.policy_published.p, owned::Disposition::Quarantine);
    assert_eq!(report.policy_published.sp, Some(owned::Disposition::None));
    assert_eq!(report.policy_published.np, Some(owned::Disposition::None));
    assert!(report.policy_published.fo.is_none());
    assert!(report.policy_published.adkim.is_none());
    assert!(report.policy_published.aspf.is_none());
    assert!(report.policy_published.pct.is_none());
    assert_eq!(report.policy_published.testing, Some(false));
    assert_eq!(
        report.policy_published.discovery_method,
        Some(owned::DiscoveryMethod::TreeWalk)
    );
    assert_eq!(report.records.len(), 1);
    let record = &report.records[0];
    assert_eq!(
        record.row.source_ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123))
    );
    assert_eq!(record.row.count, 123);
    assert_eq!(
        record.row.policy_evaluated.disposition,
        owned::Disposition::None
    );
    assert_eq!(
        record.row.policy_evaluated.dkim,
        owned::AlignmentResult::Pass
    );
    assert_eq!(
        record.row.policy_evaluated.spf,
        owned::AlignmentResult::Fail
    );
    assert!(record.row.policy_evaluated.reason.is_empty());
    assert_eq!(record.identifiers.header_from, "example.com");
    assert_eq!(record.identifiers.envelope_from, Some("example.com"));
    assert!(record.identifiers.envelope_to.is_none());
    assert_eq!(record.auth_results.dkim.len(), 1);
    let dkim_result = &record.auth_results.dkim[0];
    assert_eq!(dkim_result.domain, "example.com");
    assert_eq!(dkim_result.result, owned::DKIMResult::Pass);
    assert_eq!(dkim_result.selector, "abc123");
    assert!(dkim_result.human_result.is_none());
    let spf_result = &record.auth_results.spf.unwrap();
    assert_eq!(spf_result.domain, "example.com");
    assert_eq!(spf_result.result, owned::SPFResult::Fail);
    assert!(spf_result.scope.is_none());
    assert!(spf_result.human_result.is_none());
    Ok(())
}

const XML_MINIMAL: &str = include_str!("tests/minimal.xml");

#[test]
fn minimal_xml() -> Result<(), DeError> {
    let report = from_str(XML_MINIMAL)?;
    let report_owned = from_str_owned(XML_MINIMAL)?;
    assert_eq!(report, report_owned);

    let report_borrowed_owned: owned::Report = From::from(&report);

    assert_eq!(report_borrowed_owned, report_owned);
    Ok(())
}

/// Simply check that parsing doesn't fail.
fn minimum_example(s: &str) -> Result<(), DeError> {
    let report = from_str(s)?;
    let report_owned = from_str_owned(s)?;
    assert_eq!(report, report_owned);

    let report_borrowed_owned: owned::Report = From::from(&report);

    assert_eq!(report_borrowed_owned, report_owned);
    Ok(())
}

const XML_1: &str = include_str!("tests/example1.xml");

#[test]
fn xml1() -> Result<(), DeError> {
    minimum_example(XML_1)
}

const XML_2: &str = include_str!("tests/example2.xml");

#[test]
fn xml2() -> Result<(), DeError> {
    minimum_example(XML_2)
}

const XML_3: &str = include_str!("tests/example3.xml");

#[test]
fn xml3() -> Result<(), DeError> {
    minimum_example(XML_3)
}

const XML_4: &str = include_str!("tests/example4.xml");

#[test]
fn xml4() -> Result<(), DeError> {
    minimum_example(XML_4)
}

const XML_5: &str = include_str!("tests/example5.xml");

#[test]
fn xml5() -> Result<(), DeError> {
    minimum_example(XML_5)
}

const XML_6: &str = include_str!("tests/example6.xml");

#[test]
fn xml6() -> Result<(), DeError> {
    minimum_example(XML_6)
}

const XML_7: &str = include_str!("tests/example7.xml");

#[test]
fn xml7() -> Result<(), DeError> {
    minimum_example(XML_7)
}

const XML_8: &str = include_str!("tests/example8.xml");

#[test]
fn xml8() -> Result<(), DeError> {
    minimum_example(XML_8)
}

const XML_9: &str = include_str!("tests/example9.xml");

#[test]
fn xml9() -> Result<(), DeError> {
    minimum_example(XML_9)
}

const XML_10: &str = include_str!("tests/example10.xml");

#[test]
fn xml10() -> Result<(), DeError> {
    minimum_example(XML_10)
}

const XML_11: &str = include_str!("tests/example11.xml");

#[test]
fn xml11() -> Result<(), DeError> {
    minimum_example(XML_11)
}

const XML_12: &str = include_str!("tests/example12.xml");

#[test]
fn xml12() -> Result<(), DeError> {
    minimum_example(XML_12)
}
