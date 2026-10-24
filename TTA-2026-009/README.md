# TTA-2026-009: CIMS password recovery does not enforce OTP completion before password reset

**Severity: Critical** — Provisional CVSS 3.1: 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), pending product attribution and deployment confirmation

### Title

Missing server-side OTP enforcement in CIMS password recovery allows unauthenticated account takeover.

### Summary

The assessed CIMS password-recovery workflow authorizes the final password change without requiring the server-side recovery transaction to record successful OTP verification. An unauthenticated requester can obtain a recovery transaction reference and use it to set a new password before completing the intended identity challenge.

The behavior was verified end to end: a synthetic account accepted the new password and obtained an authenticated session. An invalid recovery reference was rejected as a negative control.


### Affected Version

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Public ownership evidence: UWCSEA describes CIMS as its College Information Management System and student management system.
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified

The public link identifies the affected application. The page and its asset layout indicate a UWCSEA-specific application or customized deployment, but do not establish whether the implementation was written entirely by UWCSEA or delivered by a third-party contractor.


### Vulnerability Type

Broken Password Recovery / Improper Authentication (CWE-640, CWE-287).

### Affected Code

Application flow: `ForgotPassword` → OTP step → `ResetPassword` → `Login`.

The implementation source is not public. The tested behavior identifies the final password-reset handler as the affected authorization boundary.

### Root Cause

The recovery reference is issued before the identity challenge is complete, but the final reset handler treats that reference as a complete password-change authorization. The OTP pages are part of the intended browser sequence, yet the server does not persist and enforce a successful challenge state tied to the same account and transaction.

In practical terms, the implementation behaves like this:

```text
recovery_reference = start_recovery(account)

if valid(recovery_reference):
    allow_password_change()
```

The secure design must behave like this:

```text
recovery_reference = start_recovery(account)
challenge_ok = verify_otp(account, recovery_reference, otp)

if valid(recovery_reference) and challenge_ok and not_expired(recovery_reference):
    consume(recovery_reference)
    allow_password_change()
else:
    reject()
```

The visible OTP page is therefore not the security boundary. The security boundary is the authorization check performed by the final password-reset handler.


### Steps to Reproduce

Run this sequence only against a UWCSEA-approved staging copy or a disposable clone with a synthetic account. Use `<redacted>` for every token, cookie, username, and password in any shared evidence.

1. Open `GET /cims/Account/ForgotPassword` and keep the test session and anti-forgery state in a local staging browser or test-only cookie jar.
2. Submit the normal recovery request to `POST /cims/Account/ForgotPassword` for a synthetic username. The request should be sent through the normal application form with the anti-forgery field and the synthetic username.
3. Record the response status and redirect target. In the vulnerable behavior, the response returns a recovery reference and points the browser toward the OTP step, represented by a path similar to `ForgotPasswordOtp`.
4. Stop at this point. Do not enter or approve an OTP.
5. Open the final reset page directly with the same staging recovery reference, using a path similar to `GET /cims/Account/ResetPassword?accessKey=<redacted>`.
6. Inspect the response. In the vulnerable behavior, the application renders the password-reset form and includes the account and recovery reference even though no server-side OTP-success state exists.
7. Submit the final reset form to `POST /cims/Account/ResetPassword` with the synthetic account, the same redacted recovery reference, the anti-forgery field, and a new synthetic password.
8. In the vulnerable behavior, the application returns a successful reset result even though the OTP step was skipped.
9. Submit the new synthetic password through the normal `POST /cims/Account/Login` flow. In the vulnerable behavior, the login succeeds and the application creates an authenticated session.

The key comparison is between step 5 and step 7: the reset page and reset operation accept a valid recovery reference without checking that the corresponding OTP challenge was completed.


### Impact

An attacker who knows a valid username can take over the corresponding CIMS account without knowing its existing password or completing the OTP challenge. The affected deployment also linked some CIMS identities to an enterprise directory, so the same root cause could change a linked directory password. That directory impact depends on the deployment's identity mapping and service permissions.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — 9.8 Critical, provisional.

## Status

Published on 2026-10-24. Product owner, vendor, version, and build are not yet confirmed. CVE eligibility is pending product attribution.

## Validation controls

### Controls

- Repeat the same sequence with an invalid or expired recovery reference. It should be rejected.
- Complete the OTP step before the final reset. The normal control should succeed.
- Reuse a successfully consumed recovery reference. It should be rejected.
- Complete a challenge for synthetic account A and try to use that reference for synthetic account B. It should be rejected.

### What the original test demonstrated

The original authorized test used a synthetic canary account. The no-OTP sequence returned a successful reset result, and the new synthetic password was accepted by the normal login flow. An invalid recovery reference was rejected. No real administrator account, production password, OTP value, cookie, or directory credential was used.

The public report intentionally leaves out the live hostname, real account values, recovery references, anti-forgery values, cookies, raw response bodies, and executable request script. Those values are not needed to understand the missing server-side state check and should be exchanged only through UWCSEA's secure evidence channel.

## Preconditions

- The attacker can reach the public password-recovery function.
- The attacker knows or can determine a target account identifier.
- The target account is eligible for the recovery workflow.
- The deployment accepts the recovery reference at the final password-change step without a completed challenge state.

No existing session, current password, valid OTP, or administrator role is required in the reproduced path.

## Verification matrix

| Test case | Challenge state | Recovery reference | Result |
| --- | --- | --- | --- |
| Synthetic target, normal flow | Completed | Bound to target transaction | Password change succeeds as designed |
| Synthetic target, tested flaw | Not completed | Bound to target transaction | Password change was accepted |
| Synthetic target, invalid reference | Not applicable | Invalid or unrelated | Request was rejected |
| Synthetic target, replay check | Previously consumed | Previously used | Must be rejected after remediation |
| Synthetic target, cross-account check | Completed for another account | Wrong account binding | Must be rejected after remediation |

The last two rows are remediation acceptance cases. They define the security properties that the fixed implementation must demonstrate; they are not claims that the original deployment passed those checks.

## Fix acceptance criteria

- A password change is rejected unless the server records a successful challenge for the exact account and transaction.
- The challenge result cannot be supplied only by a browser field or client-side flag.
- A recovery transaction expires and is single-use.
- A reference cannot be moved to another account or transaction.
- A successful reset invalidates older recovery references and relevant existing sessions.
- Audit records distinguish recovery start, challenge success, password change, and rejection.
- Privileged and directory-backed accounts use an additional controlled recovery policy.

## Suggested vendor triage questions

1. Which product, version, and build implement the assessed CIMS workflow?
2. Is the recovery reference intended to authorize the final password change by itself?
3. Where is the OTP completion state stored and checked server side?
4. Does the same workflow change application-only and directory-backed passwords?
5. Which releases contain the fix, and can the fix be tested with replay, cross-account, and incomplete-challenge cases?

## Recommended remediation

- Implement a server-side state machine for recovery initiation, challenge verification, password-change authorization, and one-time consumption.
- Bind each recovery transaction to one account, one challenge, a short expiry, and a single successful use.
- Reject missing, incomplete, expired, replayed, or cross-account recovery transactions.
- Invalidate existing sessions and outstanding recovery transactions after a successful password change.
- Separate public application password recovery from enterprise-directory password administration.
- Apply an additional controlled recovery process to privileged accounts.

## Evidence scope

The issue was reproduced in one authorized deployment using controlled identities. The report omits deployment identifiers, account values, recovery values, session material, directory details, and original requests.

## Timeline

- 2026-10-22: Findings consolidated from the assessment record.
- 2026-10-24: Public TTA report published.
