# TTA-2026-003: Request Tracker 5.0.5 SavedSearch widget permits cross-user private search disclosure

**Status update (2026-11-10):** **Already addressed** under vendor-announced [CVE-2026-108282](https://www.cve.org/CVERecord?id=CVE-2026-108282); fixed in RT **5.0.11**. The original RT 5.0.5 reproduction is retained below as historical evidence.

**Severity: Medium** — Suggested CVSS 3.1: 4.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`)

### Title

Missing ownership enforcement in the SavedSearch widget discloses another user's private saved searches.

### Summary

The `share/html/Widgets/SavedSearch` component in Request Tracker 5.0.5 parses a saved-search reference into a container object and an Attribute identifier, but discards the parsed container object and loads the Attribute directly by identifier. Its remaining display check maps SavedSearch visibility to the broad system-level `ShowSavedSearches` right rather than enforcing ownership of a personal saved search.

As a result, a non-SuperUser staff account with `ShowSavedSearches` can retrieve another user's private saved-search description, query, format, and chart values.


### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Component: `share/html/Widgets/SavedSearch`
- Demonstrated entry point: `/Search/Chart.html`
- Parameter: `SavedSearchLoad`

Only RT 5.0.5 was dynamically tested. Other versions have not been claimed as affected without separate verification.


### Vulnerability Type

Incorrect Authorization / IDOR (CWE-863; related to CWE-639).

### Affected Code

File: `share/html/Widgets/SavedSearch`

Demonstrated entry point: `/Search/Chart.html` using the saved-search load parameter.

### Root Cause

`Widgets/SavedSearch` receives both `$container_object` and `$search_id` from the saved-search parser, but does not use `$container_object` for authorization before loading the `RT::Attribute` by identifier. Other RT search-loading implementations enforce the missing container check.


### Steps to Reproduce

The following procedure uses two synthetic staff users in an isolated RT 5.0.5 instance.

1. Deploy RT 5.0.5 in a disposable lab instance and set `RT_BASE` to the lab URL.
2. Create synthetic users `owner` and `reader`. Give `reader` the broad `ShowSavedSearches` right, but no ownership, `AdminUsers`, or SuperUser rights over `owner`.
3. As `owner`, create a private personal saved search with a unique marker such as `SYNTHETIC-SAVEDSEARCH-CANARY`. Record the synthetic Attribute ID.
4. Log in as `owner` and `reader` in the isolated lab; export their lab-only sessions separately to `owner.jar` and `reader.jar`. Confirm that the owner's private search is absent from the normal search builder when viewed as `reader`.
5. Load the search through the chart endpoint using the parsed container reference:

   ```bash
   curl -sS -b reader.jar -w '\nHTTP %{http_code}\n' \
     "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT::User-<OWNER_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchLoadSubmit=1" \
     -o chart.html
   ```

6. Search the response for `SYNTHETIC-SAVEDSEARCH-CANARY`, the private description, or the synthetic query text.
7. Vulnerable result: the reader receives private search metadata or chart data despite not owning the search.
8. Compare with the normal search builder and a `reader-no-right` account that lacks `ShowSavedSearches`; both should deny or omit the private values.
9. Confirm `owner.jar` can still load the private search. Remove the synthetic search after verification and retain only response status, a canary marker, and the test account class.


### Impact

Private saved searches may reveal sensitive keywords, custom-field names, queue and ticket-selection logic, named users, internal workflow structure, and the business topics monitored by another staff member. Attribute identifiers are numeric and may be enumerable, allowing the issue to be scaled beyond a single object.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` — 4.3 Medium.

## Status

**Already addressed; covered by [CVE-2026-108282](https://www.cve.org/CVERecord?id=CVE-2026-108282).** The [RT 5.0.11 release notes](https://docs.bestpractical.com/release-notes/rt/5.0.11), together with the [matching upstream fix](https://github.com/bestpractical/rt/commit/82093b255f5a965cee669021dae5feba5107f76b), support this mapping. Fixed release is RT **5.0.11**. The RT 6.0.4 notes do not list this CVE; this update does not claim a 6.x affected range or a 6.0.4 fix for this finding.

This issue was privately reported to Best Practical on 2026-10-23 and publicly disclosed on 2026-10-24. On 2026-10-27, Best Practical replied that the issue had already been reported and would be addressed in the next RT 5 release, and requested testing on the latest release and encrypted reports. The earlier absence of a response at publication time is historical, not the current status.

A VulDB receipt dated 2026-10-24 records a CVE request. Its current processing status has not been verified, and this GitHub update does not change or withdraw that submission. This report now references the existing vendor-announced CVE rather than presenting the same finding as a new-CVE claim. Vendor or CNA credit for TypeThe0ry as an independent co-discoverer has not been confirmed.

Only RT 5.0.5 was dynamically tested for this report. The fixed-version conclusion is based on vendor documentation and source changes, not a completed dynamic regression test of this finding on the fixed releases.

## Prerequisites

- A valid authenticated privileged RT account.
- The `ShowSavedSearches` right, but no ownership or administrative rights over the victim user.
- Knowledge or enumeration of the target user and saved-search Attribute identifiers.

## Recommended remediation

- Upgrade to RT **5.0.11**, or a later supported release containing the fix. The following checks describe the authorization requirements, not additional unconfirmed defects in the fixed release.
- Require ownership or container visibility using the parsed container object before loading and rendering the Attribute.
- Centralize saved-search loading and authorization in one helper shared by all consumers.
- Add cross-user negative tests for every saved-search consumer.
- Return a generic permission error without revealing whether a target Attribute exists.

## Evidence boundary

The vulnerability was dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using synthetic users and searches. No customer hostname, IP address, credential, cookie, real user, ticket, or production search content is included in this advisory.

## Timeline

- 2026-10-23: Privately reported to Best Practical.
- 2026-10-24: Public TTA report published; VulDB acknowledged the CVE request.
- 2026-10-27: Best Practical replied that the issue was already known and the next RT 5 release would address it.
- 2026-10-29: Vendor release notes announced the fix under CVE-2026-108282.
- 2026-11-10: Confirmed existing-CVE coverage in an encrypted follow-up to Best Practical; updated this report to already addressed. Independent-discovery credit remains unconfirmed. No VulDB status change was made by this documentation update.
