# Security Research

This repository hosts security advisories and supporting technical information for vulnerability research conducted by TypeThe0ry.

## Responsible disclosure

Vendors are notified before publication. Reports are limited to the technical information needed to reproduce and remediate the issue, and use only synthetic laboratory evidence.

The Request Tracker vulnerabilities currently documented here were privately reported to Best Practical at `security@bestpractical.com` on 2026-10-23 and publicly disclosed on 2026-10-24. No vendor response, fix confirmation, or CVE assignment had been received at publication time.

Customer hostnames, IP addresses, credentials, session values, real user information, ticket contents, and production data are not published in this repository.

## Advisories

| Advisory | Product | Vulnerability |
| --- | --- | --- |
| [TTA-2026-001](TTA-2026-001/) | Request Tracker 5.0.5 | REST 1.0 group membership authorization bypass |
| [TTA-2026-002](TTA-2026-002/) | Request Tracker 5.0.5 | CustomFieldValue parent authorization bypass |
| [TTA-2026-003](TTA-2026-003/) | Request Tracker 5.0.5 | SavedSearch cross-user disclosure |
| [TTA-2026-004](TTA-2026-004/) | Request Tracker 5.0.5 | `RT::Attribute` authorization fail-open |

`TTA` identifiers are local advisory identifiers, not CVE IDs. Each advisory is stored in a dedicated folder. A folder will be renamed to its assigned `CVE-YYYY-NNNN` identifier after allocation.

TTA-2026-004 combines the read, update, and delete effects of one `RT::Attribute` fail-open authorization root cause. It is submitted as one vulnerability unless the assigning CNA determines that the affected paths are independently fixable.

## Researcher

TypeThe0ry

