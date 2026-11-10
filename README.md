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
| [TTA-2026-001](TTA-2026-001/) | [CVE-2026-108276](https://www.cve.org/CVERecord?id=CVE-2026-108276) | Already addressed: 5.0.11 / 6.0.4 | Request Tracker (5.0.5 reproduced) | REST 1.0 group membership authorization bypass |
| [TTA-2026-002](TTA-2026-002/) | [CVE-2026-108274](https://www.cve.org/CVERecord?id=CVE-2026-108274) | Already addressed: 5.0.11 / 6.0.4 | Request Tracker (5.0.5 reproduced) | CustomFieldValue parent authorization bypass |
| [TTA-2026-003](TTA-2026-003/) | [CVE-2026-108282](https://www.cve.org/CVERecord?id=CVE-2026-108282) | Already addressed: RT 5.0.11; no 6.x range inferred | Request Tracker (5.0.5 reproduced) | SavedSearch cross-user disclosure |
| [TTA-2026-004](TTA-2026-004/) | Partial overlap with [CVE-2026-108282](https://www.cve.org/CVERecord?id=CVE-2026-108282) | Saved-search fix overlap; separate read path unverified | Request Tracker (5.0.5 reproduced) | `RT::Attribute` authorization fail-open |
| [TTA-2026-005](TTA-2026-005/) | [CVE-2026-114243](https://www.cve.org/CVERecord?id=CVE-2026-114243) | Published | dhikshitha29 Insurance-Management-System | Unauthenticated SQL injection in `EditPolicyHolder.php` |
| [TTA-2026-006](TTA-2026-006/) | [CVE-2026-114245](https://www.cve.org/CVERecord?id=CVE-2026-114245) | Published | dhikshitha29 Insurance-Management-System | Unauthenticated administrator account creation |
| [TTA-2026-007](TTA-2026-007/) | Unconfirmed; possible CVE-2026-108342 overlap | Filename sink addressed: 5.0.11 / 6.0.4 (source review) | Request Tracker (5.0.5 unsafe HTML reproduced) | `text/calendar` attachment filename stored XSS candidate |
| [TTA-2026-008](TTA-2026-008/) | — | Current-release candidate unverified; not marked addressed | Request Tracker 5.0.5 with DBI ExternalAuth (historical reproduction) | Exception-path authentication bypass candidate |
| [TTA-2026-009](TTA-2026-009/) | — | Fix reported by operator; validation pending | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Password recovery accepted reset before OTP completion |
| [TTA-2026-010](TTA-2026-010/) | — | Published deployment report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Unlinked identity record causes authentication failure |
| [TTA-2026-011](TTA-2026-011/) | — | Published deployment report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Authentication responses disclose account lifecycle state |
| [TTA-2026-012](TTA-2026-012/) | — | Published integration report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Adaptive-authentication workflow prevents MFA login |
| [TTA-2026-013](TTA-2026-013/) | — | Published configuration report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | MFA enforcement depends on a mutable deployment flag |
| [TTA-2026-014](TTA-2026-014/) | — | Published impact report | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Authentication ticket forgery after machine-key compromise |
| [TTA-2026-015](TTA-2026-015/) | — | CVE eligibility pending | Insurance-Management-System, commit `125362cc21dca20d74091a4913a5096bb58dd837` | Unauthenticated policy-holder record modification |
| [TTA-2026-016](TTA-2026-016/) | [CVE-2026-108365](https://www.cve.org/CVERecord?id=CVE-2026-108365) | Already addressed: 5.0.11 / 6.0.4; CVE record RESERVED when checked 2026-11-10 | Request Tracker (5.0.5 reproduced; 5.0.10 / 6.0.3 source-reviewed) | Cross-site request forgery in `/Helpers/RightsInspector/Revoke` revokes arbitrary ACL entries |
| [TTA-2026-017](TTA-2026-017/) | Same scope review as TTA-2026-004 | Follow-up, not separate defect; remaining read path unverified | Request Tracker (5.0.10 / 6.0.3 source review only) | `RT::Attribute` version-scope follow-up |
| [TTA-2026-018](TTA-2026-018/) | — | Recovery fix reported; identity response unverified | UWCSEA College Information Management System (CIMS), ASP.NET MVC 5 | Password reset wrote the directory account password, escalating to domain administrator takeover |
| [TTA-2026-019](TTA-2026-019/) | — | CVE eligibility pending | Tridium Niagara 4 (Web Supervisor and JACE) | Stored SCRAM `SaltedPassword` permits offline forged authentication without a password |

TTA-2026-004 and TTA-2026-017 describe the same `RT::Attribute` report family, not two independent defects. The saved-search consumer overlaps the [RT 5.0.11 fix](https://github.com/bestpractical/rt/commit/82093b255f5a965cee669021dae5feba5107f76b) associated with CVE-2026-108282. The separate `/Prefs/Search.html` read path remains unverified on 5.0.11; neither complete coverage nor a distinct remaining vulnerability is asserted. The 5.0.10 and 6.0.3 observations are source review, not runtime reproductions.

TTA-2026-018 does not restate the OTP bypass in TTA-2026-009. It documents the separate behaviour that makes the password reset write a directory credential, and therefore the escalation from application account takeover to domain administrator access.

TTA-2026-016 is already addressed under vendor-announced CVE-2026-108365; Best Practical confirmed the fixed versions on 2026-11-09. TTA-2026-019 remains a public candidate published after isolated reproduction and source review, with no vendor response at publication time.

## Existing disclosure history

- TTA-2026-001 through TTA-2026-004 were privately reported to Best Practical at `security@bestpractical.com` on 2026-10-23 and publicly disclosed on 2026-10-24, before a vendor response. Best Practical replied separately to all four on 2026-10-27, saying the issues were already known and would be addressed in the next RT 5 release. The 2026-10-29 releases and matching source changes establish existing-CVE coverage for 001–003; 004 retains the partial-overlap limits above. VulDB receipts confirm requests for 001–004 on 2026-10-24, but their current processing status has not been verified or changed by this GitHub update.
- TTA-2026-007 and TTA-2026-008 were published on 2026-10-24 from isolated RT 5.0.5 evidence, without a recorded advisory-specific private notice beforehand. They are documented exceptions to the normal private-notice timeline. Source review now confirms 007's filename sink is escaped in 5.0.11 and 6.0.4, but its CVE mapping is unconfirmed. For 008, the 5.0.11 upstream DBI baseline passed 31/31 assertions; the custom malformed-password/session case was not run, so current-release exploitability and fix status remain unverified. An encrypted follow-up on 2026-11-10 included both report links; no advisory-specific vendor response has been recorded.
- TTA-2026-009 through TTA-2026-014 cover the publicly reachable [UWCSEA College Information Management System (CIMS) login application](https://webapps.uwcsea.edu.sg/cims/Account/Login). The login page labels the application “College Information Management System”, uses UWCSEA branding and `/cims/` routes, exposes ASP.NET MVC 5/IIS indicators, and loads a SecureAuth identity-integration script. No public third-party product name, source repository, version, or build has been identified. The evidence supports a UWCSEA-specific application or a heavily customized deployment; it does not prove that every component was written by UWCSEA. TTA-2026-009 is the only current CVE candidate in this group; the remaining reports document lower-severity application, integration, configuration, or post-compromise issues.
- TTA-2026-015 documents a separate unauthenticated policy-holder update issue in the Insurance-Management-System sample project. It is a local synthetic-data reproduction and has no assigned CVE.
- TTA-2026-016 was published on 2026-10-28 from isolated RT 5.0.5 reproduction and 5.0.10/6.0.3 source review. An encrypted private report followed on 2026-10-29. On 2026-11-09, Best Practical confirmed fixes in 5.0.11 and 6.0.4 and conditionally asked that a corresponding VulDB submission, if one existed, be marked already addressed. The report now references CVE-2026-108365; no separate 016 VulDB submission has been verified.
- TTA-2026-017 is a source-review follow-up to TTA-2026-004, not a new defect. It contains no runtime reproduction on 5.0.10 or 6.0.3 and makes no claim of a reachable 6.0.3 exploitation path. The current saved-search fix overlap and unverified remaining read path are recorded in both reports.
- On 2026-11-10, TypeThe0ry sent Best Practical an encrypted follow-up confirming existing-CVE coverage for 001–003 and 016, retaining the limits for 004/017, 007 and 008, supplying a public key, and requesting consideration of independent co-discovery credit. No later vendor response or credit confirmation has been recorded. No CVE request, withdrawal, or VulDB status change was performed by this documentation update.
- TTA-2026-018 covers the same CIMS deployment as TTA-2026-009 through TTA-2026-014. The operating organisation was notified out of band, the affected directory account password was changed through the organisation's own procedure, and the password value obtained during testing is excluded from every report in this repository.
- TTA-2026-019 covers building-management equipment assessed in the same authorised engagement. It is published with all station addresses, site names, account names, salts, verifiers, and share paths removed, and with no control action performed on production equipment. Tridium coordinates product disclosure through CISA ICS advisories; no private notice had been sent at publication time.
- In an operator email supplied to the researcher and recorded on 2026-11-03 (email date not provided), UWCSEA stated that its CIMS password-recovery bug was fixed, its RT server was retired, and a BMS issue remained unresolved while it worked with an external vendor. No technical validation, retirement date, or BMS report identifier was supplied. The RT statement concerns the school's deployment, not Request Tracker as a product; the BMS statement cannot be mapped conclusively to TTA-2026-019 or any other specific finding.
- The Insurance-Management-System vulnerabilities were publicly reported to the upstream project on 2026-10-07. VulDB, acting as the CNA, published CVE-2026-114243 and CVE-2026-114245 on 2026-10-21. No upstream response or fix is known at the time of this update.

## Researcher

TypeThe0ry

## License

Unless an advisory states otherwise, the reports and documentation in this repository are licensed under [CC BY 4.0](LICENSE). Keep the original advisory link and identify any changes when reusing a report. Third-party code, trademarks, personal data, and quoted external material are not relicensed by this notice.

