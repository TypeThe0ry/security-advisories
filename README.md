# TypeThe0ry Security Research

This repository is the public disclosure channel for security vulnerabilities researched and reported by TypeThe0ry. It provides stable advisory identifiers, technical reports, remediation guidance, disclosure timelines, and links to assigned CVE records.

## Why

Coordinating an open source vulnerability can require more time than the technical investigation itself: identifying the right contact, establishing a private communication channel, tracking remediation, coordinating publication, and following up on a CVE request.

This repository provides a consistent process for that work. TypeThe0ry prepares an advisory under a permanent `TTA` identifier, contacts the maintainer, and invites the maintainer to participate in validation, remediation, and disclosure. If the maintainer prefers to coordinate through a GitHub Security Advisory in the affected project's own repository or through another established security channel, the discussion can move there while the `TTA` identifier remains the stable public reference.

The workflow is informed by [JLLeitschuh's security-research disclosure model](https://github.com/JLLeitschuh/security-research) and adapted to this repository's `TTA` identifier scheme and reporting history.

## Advisory identifiers

`TTA` identifiers are the stable and canonical advisory identifiers used by this repository. Every report remains in its `TTA-YYYY-NNN` directory. An assigned CVE is recorded as an external cross-reference in the index and report; assigning a CVE does not rename or replace the `TTA` identifier. A TTA may also document a deployment or hardening issue that is not submitted for a CVE; the status column distinguishes those reports.

## Coordinated disclosure process

1. The vulnerability is validated using an isolated environment and synthetic data. A `TTA` identifier is assigned and a report is prepared for eventual public consumption.
2. The maintainer is contacted through a published security address, [a private GitHub Security Advisory in this repository](https://github.com/TypeThe0ry/security-advisories/security/advisories), a vulnerability disclosure platform, or another appropriate private channel. The initial message contains enough information to route and triage the report; reproduction details are exchanged privately.
3. TypeThe0ry and the maintainer coordinate validation, remediation, affected versions, publication timing, and appropriate user guidance. If the maintainer creates an advisory in the affected project's repository, that advisory becomes the preferred coordination channel.
4. A CVE is requested through the maintainer's CNA or an appropriate third-party CNA when the issue is eligible. The `TTA` report is updated with the assigned CVE without changing its directory or canonical identifier.
5. Public disclosure occurs when a fix or advisory is widely available, when the coordinated deadline is reached, or earlier when the policy below permits accelerated disclosure. The public report records the actual timeline and known fix status.

## Disclosure policy

For new private notices sent on or after 2026-10-24, this repository follows the [OpenSSF Model Outbound Vulnerability Disclosure Policy, version 0.1.1](https://openssf.org/about/vulnerability-disclosure-policy/), unless an individual advisory documents a different agreement.

- The normal maximum embargo is 90 calendar days from the date the maintainer receives private notice. Publication may occur sooner when a fix is made widely available.
- Maintainers are asked to acknowledge the report within 21 calendar days and to provide a meaningful remediation update. If there is no engagement confirming an intent to remediate within 35 days, disclosure may be brought forward.
- When a fix is firmly scheduled shortly after the 90-day deadline, publication may be delayed by up to 14 additional days to align with that release.
- A previously unknown vulnerability observed under active exploitation is handled on an accelerated timeline, normally no more than 7 days from notice, unless a documented harm-reduction exception justifies more time.
- A maintainer's statement that an issue will not be fixed or is not considered a vulnerability may end private coordination and lead to earlier publication.
- Exceptional circumstances may justify moving a publication date. Material changes will be communicated to the maintainer and recorded in the advisory timeline.

This policy is prospective. Advisories that were already public before 2026-10-24 retain their actual historical timelines and are not represented as having followed a retroactive 90-day embargo.

## Publication safeguards

Reports contain only the technical information needed to understand, reproduce, and remediate the vulnerability. Reproduction steps use synthetic laboratory evidence. Non-public hostnames, internal IP addresses, credentials, session values, real user information, ticket contents, and production data are not published in this repository. A report may identify a public application URL when it is necessary to establish product ownership or the affected deployment.

## Advisories

| Advisory | CVE | Status | Product | Vulnerability |
| --- | --- | --- | --- | --- |
| [TTA-2026-001](TTA-2026-001/) | — | CVE request pending | Request Tracker 5.0.5 | REST 1.0 group membership authorization bypass |
| [TTA-2026-002](TTA-2026-002/) | — | CVE request pending | Request Tracker 5.0.5 | CustomFieldValue parent authorization bypass |
| [TTA-2026-003](TTA-2026-003/) | — | CVE request pending | Request Tracker 5.0.5 | SavedSearch cross-user disclosure |
| [TTA-2026-004](TTA-2026-004/) | — | CVE request pending | Request Tracker 5.0.5 | `RT::Attribute` authorization fail-open |
| [TTA-2026-005](TTA-2026-005/) | [CVE-2026-114243](https://www.cve.org/CVERecord?id=CVE-2026-114243) | Published | dhikshitha29 Insurance-Management-System | Unauthenticated SQL injection in `EditPolicyHolder.php` |
| [TTA-2026-006](TTA-2026-006/) | [CVE-2026-114245](https://www.cve.org/CVERecord?id=CVE-2026-114245) | Published | dhikshitha29 Insurance-Management-System | Unauthenticated administrator account creation |
| [TTA-2026-007](TTA-2026-007/) | — | Vendor confirmation pending | Request Tracker 5.0.5 | `text/calendar` attachment filename stored XSS candidate |
| [TTA-2026-008](TTA-2026-008/) | — | Vendor confirmation pending | Request Tracker 5.0.5 with DBI ExternalAuth | Exception-path authentication bypass candidate |
| [TTA-2026-009](TTA-2026-009/) | — | CVE eligibility pending | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Password recovery accepts reset before OTP completion |
| [TTA-2026-010](TTA-2026-010/) | — | Published deployment report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Unlinked identity record causes authentication failure |
| [TTA-2026-011](TTA-2026-011/) | — | Published deployment report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Authentication responses disclose account lifecycle state |
| [TTA-2026-012](TTA-2026-012/) | — | Published integration report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Adaptive-authentication workflow prevents MFA login |
| [TTA-2026-013](TTA-2026-013/) | — | Published configuration report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | MFA enforcement depends on a mutable deployment flag |
| [TTA-2026-014](TTA-2026-014/) | — | Published impact report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Authentication ticket forgery after machine-key compromise |
| [TTA-2026-015](TTA-2026-015/) | — | CVE eligibility pending | Insurance-Management-System, commit `125362cc21dca20d74091a4913a5096bb58dd837` | Unauthenticated policy-holder record modification |

TTA-2026-004 combines the read, update, and delete effects of one `RT::Attribute` fail-open authorization root cause. It is submitted as one vulnerability unless the assigning CNA determines that the affected paths are independently fixable.

## Existing disclosure history

- TTA-2026-001 through TTA-2026-004 were privately reported to Best Practical at `security@bestpractical.com` on 2026-10-23 and publicly disclosed on 2026-10-24. No vendor response, fix confirmation, or CVE assignment had been received at publication time.
- TTA-2026-007 and TTA-2026-008 are public candidates based on isolated RT 5.0.5 reproduction. Vendor scope, duplicate status, affected ranges, fix status, and CVE eligibility remain unconfirmed. No advisory-specific vendor notice had been recorded before publication. At the researcher's direction, both candidates were published after evidence review and data sanitization instead of entering a new private embargo; they are documented exceptions to the repository's normal private-notice timeline.
- TTA-2026-009 through TTA-2026-014 cover the publicly reachable [UWCSEA College Information Management System (CIMS) login application](https://webapps.uwcsea.edu.sg/cims/Account/Login). The login page labels the application “College Information Management System”, uses UWCSEA branding and `/cims/` routes, exposes ASP.NET MVC 5/IIS indicators, and loads a SecureAuth identity-integration script. No public third-party product name, source repository, version, or build has been identified. The evidence supports a UWCSEA-specific application or a heavily customized deployment; it does not prove that every component was written by UWCSEA. TTA-2026-009 is the only current CVE candidate in this group; the remaining reports document lower-severity application, integration, configuration, or post-compromise issues.
- TTA-2026-015 documents a separate unauthenticated policy-holder update issue in the Insurance-Management-System sample project. It is a local synthetic-data reproduction and has no assigned CVE.
- The Insurance-Management-System vulnerabilities were publicly reported to the upstream project on 2026-10-07. VulDB, acting as the CNA, published CVE-2026-114243 and CVE-2026-114245 on 2026-10-21. No upstream response or fix is known at the time of this update.

## Researcher

TypeThe0ry

## License

Unless an advisory states otherwise, the reports and documentation in this repository are licensed under [CC BY 4.0](LICENSE). Keep the original advisory link and identify any changes when reusing a report. Third-party code, trademarks, personal data, and quoted external material are not relicensed by this notice.

