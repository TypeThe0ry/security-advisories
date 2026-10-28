# TTA-2026-017: Request Tracker 5.0.10 still affected by the `RT::Attribute` fail-open authorization default (follow-up to TTA-2026-004), and 6.0.3 remains fail-open by design

**Severity: High** — Suggested CVSS 3.1: 7.6 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`) for 5.0.5 and 5.0.10

### Title

The `RT::Attribute` authorization map returns `allow` for every attribute name it does not know, and the map is empty in 6.0.3, so authorization for all attribute rows still defaults to permitted.

### Summary

TTA-2026-004 described a fail-open authorization default in `RT::Attribute::LookupObjectRight`: the method returns the literal string `allow` when a name or right is absent from `$ACL_MAP`, and only `SavedSearch` was ever mapped. The published advisory covered RT 5.0.5.

This report extends the confirmed affected range to RT 5.0.10, where `lib/RT/Attribute.pm` and the consuming widget are byte-identical to 5.0.5, and documents the state of the newest release, RT 6.0.3.

In 6.0.3 both `$ACL_MAP` and `$PERSONAL_ACL_MAP` are empty. Every attribute name therefore resolves to `allow`, and all four gates that guard an attribute — create, display, update, delete — resolve through that method. The two concrete request paths used in TTA-2026-004 were closed in 6.0.3 by rewriting the *callers* to use a new `RT::SavedSearch` class with its own container checks; the default itself was not changed. Authorization therefore remains dependent on every caller choosing the right class, which is the property that produced the original vulnerability.

### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5 and 5.0.10 (identical vulnerable code; 5.0.5 was dynamically reproduced for TTA-2026-004)
- Still fail-open, no reachable path demonstrated in this review: 6.0.3
- Core components: `lib/RT/Attribute.pm`, `share/html/Widgets/SavedSearch`, `share/html/Prefs/Search.html`, `share/html/Search/Chart.html`
- Endpoints (5.0.5 / 5.0.10): `GET /Prefs/Search.html?name=RT::Attribute-<ATTRIBUTE_ID>`, `GET|POST /Search/Chart.html?SavedSearchLoad=RT::User-<VICTIM_ID>-SavedSearch-<ATTRIBUTE_ID>&SavedSearchSave=1`, and the same URL with `SavedSearchDelete=1`

Only RT 5.0.5 was dynamically tested, and only for the concrete gadgets listed above. RT 5.0.10 and 6.0.3 were compared at the source level and were not executed. The 5.0.10 claim rests on code identity; the 6.0.3 claim is limited to the authorization default and does not assert a reachable exploitation path.

### Vulnerability Type

Incorrect Authorization (CWE-863); missing authorization on an object referenced by a user-controlled identifier, i.e. insecure direct object reference (CWE-639), applied to stored configuration objects; fail-open default (CWE-636).

### Affected Code

- `lib/RT/Attribute.pm` — `$ACL_MAP`, `$PERSONAL_ACL_MAP`, `LookupObjectRight`, `Create`, `Delete`, `_Value`, `_Set`, `CurrentUserHasRight`.
- `share/html/Widgets/SavedSearch` — loads an attribute by id taken from the `SavedSearchLoad` / `SavedChartSearchId` parameter.
- `share/html/Prefs/Search.html` — loads an attribute by name taken from the `name` parameter.
- `lib/RT/Dashboard.pm`, `lib/RT/SavedSearch.pm` — subclasses that implement their own container authorization and are never consulted when a row is loaded as `RT::Attribute`.

### Root Cause

The authorization decision is a map lookup with an allow-shaped default:

```perl
our $ACL_MAP = {};

sub LookupObjectRight {
    my $self = shift;
    my %args = @_;

    my $MAP = $ACL_MAP;
    if ( ($args{'ObjectType'} eq 'RT::User')
        && ($args{'ObjectId'} eq $self->CurrentUser->Id) )
    {
        $MAP = $PERSONAL_ACL_MAP;
    }

    # Now that we have the right MAP, use it
    return('allow') unless ($MAP->{ $args{'Name'} });
    return('allow') unless ($MAP->{ $args{'Name'} }{ $args{'Right'} });
    return($MAP->{ $args{'Name'} }{ $args{'Right'} });
}
```

The POD states the intent plainly: "Returns `allow` if the right is otherwise unspecified." Every consumer inherits it:

```perl
sub CurrentUserHasRight {
    my $object_right = $self->LookupObjectRight( ... );
    return (1) if ($object_right eq 'allow');
    return (0) if ($object_right eq 'deny');
    return(1) if ($self->CurrentUser->HasRight( Object => $self->Object, Right => $object_right));
    return(0);
}
```

so `Create` (line 128 in 6.0.3, 141 in 5.0.5) does nothing when the answer is `allow`, `Delete` (402 / 417) checks `CurrentUserHasRight('delete')`, `_Value` (456 / 281) checks `display`, and `_Set` (478 / ~300) checks `update` — all of which pass.

The second half of the defect is class-based authorization. `RT::Dashboard` and, since 6.0.3, `RT::SavedSearch` implement `_CurrentUserCan` / `CurrentUserCanSee`, including the guard that a user may not load another user's container:

```perl
    # users can not see other users' user-level saved searches
    if ( $object->isa('RT::User') && $object->Id != $self->CurrentUser->Id ) {
        RT->Logger->warning("Permission denied: User #". $self->CurrentUser->Id
            ." does not have rights to load container user #". $object->id);
        return 0;
    }
```

Those checks live in the subclass. `RT::Record::Load` performs no authorization, and `RT::Attribute->new($current_user)->Load($id)` never routes through `RT::Dashboard` or `RT::SavedSearch`. So the authorization decision depends on which class a caller happens to instantiate, not on the row being loaded. Any component that reaches an attribute row through the base class bypasses every container check the subclasses implement.

Version status:

| Version | `$ACL_MAP` | `$PERSONAL_ACL_MAP` | `LookupObjectRight` default | Consumers |
| --- | --- | --- | --- | --- |
| 5.0.5 | `SavedSearch` only | `SavedSearch` only | `allow` | base-class loads in widget and prefs page — **reproduced** |
| 5.0.10 | `SavedSearch` only | `SavedSearch` only | `allow` | byte-identical to 5.0.5 — **affected** |
| 6.0.3 | `{}` | `{}` | `allow` | `Widgets/SavedSearch` and `Prefs/Search.html` rewritten to use `RT::SavedSearch` and `CurrentUserCanModify` — default still fail-open, path not demonstrated |

The 6.0.3 rewrite is a caller-side fix. It closes the two gadgets that were reported, and it does not change the answer `LookupObjectRight` gives for any name.

### Steps to Reproduce

The procedure below is the TTA-2026-004 reproduction that was executed on an isolated RT 5.0.5 instance; it applies unchanged to 5.0.10 because the code is identical. Values are synthetic.

1. Deploy the target RT version in an isolated lab with two synthetic users, `victim-1` (id `<SYNTHETIC_VICTIM_ID>`) and `attacker-1` (id `<SYNTHETIC_ATTACKER_ID>`). `attacker-1` has no administrative rights, no group membership, and no relationship to `victim-1`.
2. As `victim-1`, create a dashboard and note the attribute id of its `RT::Attribute` row as `<SYNTHETIC_DASHBOARD_ATTRIBUTE_ID>`, then log out.
3. As `attacker-1`, read the row through the base class:

   ```bash
   curl -sS -b attacker.jar \
     "$RT_BASE/Prefs/Search.html?name=RT::Attribute-<SYNTHETIC_DASHBOARD_ATTRIBUTE_ID>" \
     -o read.html
   ```

   Vulnerable result: HTTP 200 with the victim's stored attribute content rendered (TTA-2026-004 used a canary string embedded in the dashboard definition as proof). Negative control: the same request against a `SavedSearch` row owned by `victim-1` returns `Permission Denied`, because `SavedSearch` is the one mapped name.

4. As `attacker-1`, overwrite and then delete the row through the widget:

   ```bash
   curl -sS -b attacker.jar \
     "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT::User-<SYNTHETIC_VICTIM_ID>-SavedSearch-<SYNTHETIC_DASHBOARD_ATTRIBUTE_ID>&SavedSearchSave=1&SavedSearchName=<SYNTHETIC_NAME>" \
     -o save.html
   curl -sS -b attacker.jar \
     "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT::User-<SYNTHETIC_VICTIM_ID>-SavedSearch-<SYNTHETIC_DASHBOARD_ATTRIBUTE_ID>&SavedSearchDelete=1" \
     -o delete.html
   ```

   Vulnerable result: the row is rewritten and then removed. The application log does not record a denial; in the 5.0.5 run it recorded only the container-load warning emitted by the subclass, which the base-class path never reaches.

5. Negative control for ownership: query the same attribute id as a *third* synthetic user with no session at all. Expected: login redirect, no content.

6. For 6.0.3, the expectation to test is different: step 3 and step 4 should now be refused by `RT::SavedSearch` / `CurrentUserCanModify`. A test against a non-`SavedSearch` attribute name through a base-class consumer is the open question this report leaves to the vendor.

### Impact

On 5.0.5 and 5.0.10, a user with no administrative rights can read, rewrite, and delete attribute rows belonging to other users and to the system, including user dashboards, user logos, subscriptions, and the system-level default dashboard. In the 5.0.5 run this included modifying a system-wide `DefaultDashboard` row, which changes what every user sees, and deleting other users' `UserLogo` rows.

The attacker needs only a valid low-privileged account and an attribute id, which is a sequential integer and is discoverable from the container id encoded in the widget parameter.

In 6.0.3 the demonstrated paths are closed. The residual issue is architectural: authorization for these rows is decided by the caller's choice of class, and the base class still answers `allow` for every name. A future or third-party component that loads an attribute row through `RT::Attribute` receives no authorization at all, and the failure is silent.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` — 7.6 High. Assigned to 5.0.5 and 5.0.10. No score is assigned to the 6.0.3 fail-open default, because no reachable path was demonstrated.

## Status

Published as TTA-2026-017 on 2026-10-28 as a follow-up to TTA-2026-004, which was privately reported to `security@bestpractical.com` on 2026-10-23 and published on 2026-10-24 with no vendor response. This report records that the reported defect is unchanged in 5.0.10 and that the default is unchanged in 6.0.3. CVE eligibility for the 5.0.10 range extension is pending; TTA-2026-004 itself has no assigned CVE.

## Prerequisites

- A valid RT account without administrative rights (5.0.5 / 5.0.10).
- `ShowSavedSearches` and `LoadSavedSearch` present in the deployment's `Everyone` grants, which is the default in `etc/initialdata`.
- Knowledge of an attribute id belonging to another principal or to the system.

## Relationship to existing CVEs

- [CVE-2026-44231](https://www.cve.org/CVERecord?id=CVE-2026-44231) (GHSA-7rx2-x357-wv74) concerns REST2 exposure of `AuthToken` and was fixed in 5.0.10 / 6.0.3. It is a different object and a different sink.
- [CVE-2026-41075](https://www.cve.org/CVERecord?id=CVE-2026-41075) concerns REST2 query construction and was fixed in 5.0.10 / 6.0.3. Unrelated.
- No published CVE covers fail-open authorization defaults in `RT::Attribute`.

Whether the 6.0.3 default-deny gap warrants its own identifier, or should be treated as an incomplete fix for TTA-2026-004, is for Best Practical or the assigning CNA to decide. This report does not assert an exploitable 6.0.3 path.

## Recommended remediation

- Invert the default in `LookupObjectRight`: return `deny` for any name or right that is not explicitly mapped, and populate `$ACL_MAP` for every attribute name RT itself writes (`Dashboard`, `UserLogo`, `Subscription`, `DefaultDashboard`, `SavedSearch`).
- Move authorization out of the callers and into the row: have `RT::Attribute` dispatch to the subclass that owns the name, so loading a `Dashboard` row as `RT::Attribute` still enforces `RT::Dashboard`'s container checks.
- Make `RT::Record::Load` able to refuse rows the current user may not see, or provide a single authorized loader and use it in `Widgets/SavedSearch`, `Prefs/Search.html`, and `Search/Chart.html`.
- Add regression tests that assert cross-user read, update, and delete are refused for every attribute name, not only `SavedSearch`.
- Keep the 6.0.3 `RT::SavedSearch` / `RT::Dashboard` container checks and add a test that they survive a caller using the base class.

## Validation controls

| Case | 5.0.5 / 5.0.10 expected | 6.0.3 expected |
| --- | --- | --- |
| Read another user's `Dashboard` row via `Prefs/Search.html?name=RT::Attribute-<id>` | content returned | refused (caller rewritten) |
| Read another user's `SavedSearch` row the same way | `Permission Denied` | refused |
| Save/delete another user's `Dashboard` row via the widget | performed | refused |
| Same operations against a row owned by the requesting user | performed | performed |
| Any attribute name not present in `$ACL_MAP` | `allow` | `allow` (default unchanged) |

## Evidence boundary

The reproduction was performed on an isolated RT 5.0.5 laboratory instance with synthetic users, a synthetic dashboard, and canary string content; the instance was restored from a snapshot afterwards. No customer hostname, IP address, credential, ticket content, or personal data is included. The 5.0.10 and 6.0.3 statements are source reviews of the public upstream repository: `lib/RT/Attribute.pm` is byte-identical between 5.0.5 and 5.0.10, and in 6.0.3 both authorization maps are empty while `LookupObjectRight` retains its `allow` default.

## Timeline

- 2026-10-09: Root cause reproduced on an isolated RT 5.0.5 instance.
- 2026-10-23: TTA-2026-004 reported privately to Best Practical.
- 2026-10-24: TTA-2026-004 published; no vendor response.
- 2026-10-28: Version-matrix review completed for 5.0.10 and 6.0.3; TTA-2026-017 published.
