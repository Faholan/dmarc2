# dmarc2

An [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989)-compliant DMARC aggregate report parser written in Rust.

## Features

- Parse XML DMARC aggregate reports as defined in [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990).
- Zero-copy deserialization into borrowed Rust structs via the `borrowed` module.
- Deserialization into fully owned types.
- `FromStr`, `TryFrom<&str>`, `PartialEq`... trait implementations for ergonomic and idiomatic usage.
- Support for variations present in real-world DMARC reports that don't exactly follow the RFC.

## Installation

In your project:

```sh
cargo add dmarc2
```

## Usage

### Parsing with zero-copy

```rust
use dmarc2::parse;

let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>ACME corporation</org_name>
    <email>wile.e.coyote@acme.corp</email>
    <report_id>beepbeep</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>road.runner</domain>
    <adkim>r</adkim>
    <aspf>s</aspf>
    <p>none</p>
    <sp>quarantine</sp>
    <np>reject</np>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>127.0.0.1</source_ip>
      <count>195</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>example.com</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#;

let report = parse(xml).unwrap();

assert_eq!(report.report_metadata.email, "wile.e.coyote@acme.corp");
assert_eq!(report.policy_published.domain, "road.runner");
assert_eq!(report.records.len(), 1);
```

### Parsing into an owned struct

```rust
use dmarc2::{parse, parse_owned};
use dmarc2::owned::Report as OwnedReport;
use dmarc2::borrowed::Report as BorrowedReport;

# let xml = r#"<?xml version="1.0"?>
# <feedback>
#   <report_metadata>
#     <org_name>ACME corporation</org_name>
#     <email>wile.e.coyote@acme.corp</email>
#     <report_id>beepbeep</report_id>
#     <date_range>
#       <begin>1609459200</begin>
#       <end>1609545600</end>
#     </date_range>
#   </report_metadata>
#   <policy_published>
#     <domain>road.runner</domain>
#     <adkim>r</adkim>
#     <aspf>s</aspf>
#     <p>none</p>
#   </policy_published>
#   <record>
#     <row>
#       <source_ip>127.0.0.1</source_ip>
#       <count>195</count>
#       <policy_evaluated>
#         <disposition>none</disposition>
#         <dkim>pass</dkim>
#         <spf>pass</spf>
#       </policy_evaluated>
#     </row>
#     <identifiers>
#       <header_from>example.com</header_from>
#     </identifiers>
#     <auth_results>
#       <spf>
#         <domain>example.com</domain>
#         <result>pass</result>
#       </spf>
#     </auth_results>
#   </record>
# </feedback>"#;

let report_owned: OwnedReport = parse_owned(xml).unwrap();

let report_borrowed: BorrowedReport = parse(xml).unwrap();

// Owned and borrowed variants can be compared.
assert_eq!(report_borrowed, report_owned);

// Or the borrowed variant can be converted into an owned version.
let report_upgrade: OwnedReport = From::from(&report_borrowed);

assert_eq!(report_borrowed, report_upgrade);
```

## Supported types

Each type is exposed as a borrowed (in the `borrowed` module) and
an owned variant (in the `owned` module).

## License

MIT — see [LICENSE](LICENSE) for details.
