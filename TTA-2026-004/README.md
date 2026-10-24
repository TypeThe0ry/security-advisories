# TTA-2026-004: Request Tracker 5.0.5 RT::Attribute authorization defaults to allow for unmapped attribute types

**Severity: High** — Suggested CVSS 3.1: 8.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`)

### Title

Fail-open `RT::Attribute` authorization allows cross-user and system-level read, update, and delete operations.

### Summary

The Attribute permission lookup returns `allow` for names that are not present in its ACL map. Consumers that load an Attribute by identifier without an ownership or container check then treat unsupported Attribute types as authorized.

### Affected Version

Request Tracker 5.0.5. Only this version was dynamically tested.

### Vulnerability Type

Incorrect Authorization / Fail-Open Access Control (CWE-863, CWE-862, CWE-639).

### Affected Code

Files: `lib/RT/Attribute.pm`, `/Prefs/Search.html`, and `share/html/Widgets/SavedSearch`.

Affected operations include Attribute read, update, and delete paths that accept a numeric Attribute identifier.

### Root Cause

`LookupObjectRight` treats an unmapped Attribute name or operation as allowed. Several consumers then load the object by ID without a second ownership or container visibility check. The combination turns an incomplete ACL map into a write-capable authorization bypass.

### Steps to Reproduce

1. In staging, create synthetic user-owned `Dashboard` and `UserLogo` Attributes and a synthetic system `DefaultDashboard` Attribute.
2. Use a staff account with no ownership or administrative rights over those objects.
3. Load the victim-owned Attribute through the normal preferences page and record whether its description is exposed.
4. Use the normal SavedSearch widget save action with the synthetic Attribute ID and a harmless marker; verify whether the victim-owned description changes.
5. Use the corresponding delete action against a restorable synthetic Attribute.
6. Repeat with a mapped `SavedSearch` Attribute as a negative control; it should be denied.

### Impact

Depending on the Attribute type and consumer, an authenticated user may read private data, modify another user's dashboard, delete a user-owned object, or change system-level dashboard configuration.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` — 8.3 High.

## Status

Privately reported to Best Practical on 2026-10-23 and publicly disclosed on 2026-10-24. No vendor response or CVE assignment had been received at the time of publication.

## Summary

Request Tracker 5.0.5 implements `RT::Attribute` permission lookup using an ACL map that explicitly covers `SavedSearch`, but returns the literal result `allow` for unmapped Attribute names. Consumers that load an Attribute by numeric identifier without a separate ownership check therefore treat display, update, and delete operations as authorized for names such as `Dashboard`, `UserLogo`, `Subscription`, and `DefaultDashboard`.

In an isolated RT 5.0.5 instance, this root cause was used to:

- read another user's private Attribute description and scalar content;
- update another user's private Dashboard Attribute;
- delete another user's private UserLogo Attribute; and
- modify a system-level `DefaultDashboard` Attribute.

These effects share the same fail-open authorization root cause and are presented as one CVE request unless the assigning CNA determines that individual consumer paths are independently fixable vulnerabilities.

## Affected product

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Core component: `lib/RT/Attribute.pm`, including `LookupObjectRight` and its ACL map
- Demonstrated consumers:
  - `/Prefs/Search.html?name=RT::Attribute-<id>`
  - `share/html/Widgets/SavedSearch`, reachable through `/Search/Chart.html`

Only RT 5.0.5 was dynamically tested. Other versions have not been claimed as affected without separate verification.

## Security impact

Depending on the reachable consumer and the Attribute name, an authenticated user can cross user or system boundaries to read, modify, or delete Attribute-backed configuration and private user data. Demonstrated impact includes private Dashboard metadata and content, UserLogo content, deletion of private Attribute records, and modification of the instance-wide default dashboard.

The write and delete effects require access to the affected staff-facing page in the reproduced scenario. The `/Prefs/Search.html` read effect was reproduced with an ordinary authenticated account and no administrative rights over the victim user.

## Reproduction: unauthorized read

1. In an isolated RT 5.0.5 instance, create an attacker and a separate victim user.
2. Create synthetic victim-owned `Dashboard` and scalar `UserLogo` Attributes.
3. Confirm the attacker has no administrative or ownership rights over the victim.
4. As the attacker, request:

   ```text
   GET /Prefs/Search.html?name=RT::Attribute-<VICTIM_DASHBOARD_ATTRIBUTE_ID>
   ```

5. Observe that the victim's private Dashboard description is rendered.
6. Repeat with the scalar canary Attribute. In the reproduced version, the scalar content is exposed in the generated error page when the page treats it as a hash value.
7. Use a victim `SavedSearch` Attribute as a negative control; the explicitly mapped Attribute name is denied.

## Reproduction: unauthorized update and delete

1. Use a non-administrator staff account with no rights over a separate victim user or the system Attribute.
2. Submit the SavedSearch widget's save action while setting `SavedSearchLoad` to a victim-owned, non-`SavedSearch` Attribute identifier.
3. Verify in the database that the victim-owned synthetic Dashboard description/content changed.
4. Submit the delete action for a separate victim-owned synthetic UserLogo Attribute.
5. Verify that the Attribute record was removed.
6. Repeat the update against a synthetic or safely restorable system `DefaultDashboard` canary and verify the change, then restore it.
7. Repeat against an Attribute whose actual name is `SavedSearch`; the explicitly mapped name is rejected, providing a negative control for the fail-open mapping.

Generic request shapes used in the isolated test were:

```text
GET /Search/Chart.html?SavedSearchLoad=RT::User-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchSave=1&SavedSearchDescription=<CANARY>

GET /Search/Chart.html?SavedSearchLoad=RT::User-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchDelete=1
```

## Expected result

An Attribute operation should be denied unless an explicit mapping and an object-level ownership or visibility check authorize it.

## Observed result

Unmapped Attribute names are treated as allowed. Consumer pages that load by identifier without their own object-level check expose unauthorized read, update, and delete operations.

## Root cause

The `RT::Attribute` ACL map defines permissions for only a limited set of Attribute names. `LookupObjectRight` returns `allow` when a name or operation is not mapped, and `CurrentUserHasRight` accepts that result without a per-object fallback. Separately, the demonstrated consumers load Attributes by numeric identifier without consistently checking the Attribute's owner or container.

## Recommended remediation

- Change the default for unknown Attribute names and operations from allow to deny.
- Define an explicit permission mapping for every supported Attribute name.
- Add a per-instance ownership/container authorization check below the name mapping.
- Require consumer pages to use a centralized authorized Attribute loader instead of raw `Load` or `LoadById` calls.
- Prevent exception pages from including raw Attribute content.
- Add regression tests covering read, update, and delete for user-owned and system-owned Attributes, including mapped and unmapped names.

## Classification

- CWE-863: Incorrect Authorization
- CWE-862: Missing Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- Suggested CVSS 3.1 for the demonstrated write/delete effect: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` (8.3), subject to CNA review of the exact privilege requirement and affected Attribute classes.

## Evidence boundary

All effects were dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using synthetic accounts, Attributes, and restorable canaries. No customer hostname, IP address, credential, cookie, real user content, ticket, or production value is included in this advisory.

