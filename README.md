# TypeTheory Security Advisories: Request Tracker 5.0.5

These advisories document vulnerabilities reproduced in an isolated Request Tracker 5.0.5 laboratory instance with synthetic accounts and data.

## Disclosure status

Best Practical was privately notified at `security@bestpractical.com` on 2026-10-23. These advisories were publicly disclosed on 2026-10-24. No vendor response, fix confirmation, or CVE assignment had been received at the time of publication.

The reports intentionally contain only synthetic laboratory evidence. Customer hostnames, IP addresses, credentials, session values, real user information, ticket contents, and production data have been removed.

## Advisories

1. **TTA-2026-001** — `01-rest1-group-membership-authorization-bypass.md`
2. **TTA-2026-002** — `02-custom-field-value-parent-authorization-bypass.md`
3. **TTA-2026-003** — `03-saved-search-cross-user-disclosure.md`
4. **TTA-2026-004** — `04-attribute-authorization-fail-open.md`

`TTA` identifiers are local advisory identifiers, not CVE IDs. The fourth advisory combines the read, update, and delete effects of the same `RT::Attribute` authorization fail-open root cause. It is being requested as one CVE unless the assigning CNA determines that the affected paths are independently fixable vulnerabilities.

## Researcher

TypeThe0ry

