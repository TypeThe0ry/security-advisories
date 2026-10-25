# TTA-2026-011: CIMS authentication responses disclose account lifecycle state

**Severity: Low** — Provisional CVSS 3.1: 3.7 (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`)

### Title

Different authentication responses disclose CIMS account lifecycle state.

### Summary

CIMS returns distinguishable authentication responses according to an account's staff lifecycle state. A response for a departed or disabled staff record differs from the generic response used for an invalid login, allowing a requester to infer the account's business status.


### Affected Version

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified


### Vulnerability Type

Observable Response Discrepancy (CWE-203, CWE-204).

### Affected Code

CIMS login account-lifecycle decision path. Exact source files are not public.

### Root Cause

The lifecycle state is returned through a different external response branch. The server does not normalize the status, message, or response shape for failed logins.


### Steps to Reproduce

Run this only with synthetic accounts in staging.

1. Prepare three staging identities: an unknown username, an active account with valid synthetic credentials, and a disabled or departed synthetic staff account with valid synthetic credentials. Use an isolated staging identity database.
2. Load `GET /cims/Account/Login` for each test and collect fresh anti-forgery values and session cookies locally.
3. Submit the same login request shape for each case:

   ```text
   POST /cims/Account/Login
   __RequestVerificationToken=<STAGING_CSRF_TOKEN>
   Username=<SYNTHETIC_USERNAME>
   Password=<VALID_TEST_PASSWORD_FOR_CANARY>
   Fingerprint=
   Base64=
   ReturnUrl=
   ```

4. Record status, response class, and whether a session is created. Do not retain response bodies containing personal data.
5. Vulnerable result: the disabled/departed canary receives a stable, distinguishable lifecycle response; the unknown account receives the generic login failure.
6. Change only the synthetic canary's lifecycle state and repeat to confirm the response difference tracks that state. Restore the account and remove the canary.

The original test reached the lifecycle check after credential handling. Use valid synthetic credentials for the canary; an incorrect password may not reach that branch.


### Impact

The response difference can confirm that an account exists and disclose whether it is classified as departed or disabled. This information can support account lifecycle mapping, targeted phishing, or credential attacks, but it does not disclose the password or create a session by itself. In the recorded path, the lifecycle check was reached after credential handling, which limits its standalone exploitation value.


### CVSS

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` — 3.7 Low, provisional.

## Status

Published on 2026-10-24 as a low-severity CIMS information-disclosure defect. No CVE request has been made.

## Preconditions

- The requester can reach the login function.
- The requester has a candidate username or a source of candidate usernames.
- The application exposes a stable difference between lifecycle states.

The observed path handled credentials before the lifecycle response, so the issue does not provide a direct password bypass. Its value is account discovery and lifecycle information.

## Verification matrix

| Test case | Account state | Desired external result |
| --- | --- | --- |
| Unknown synthetic username | Unknown | Generic authentication failure |
| Synthetic account with wrong password | Active | Same generic failure |
| Synthetic disabled account | Disabled | Same generic failure |
| Synthetic departed account | Departed | Same generic failure |
| Locked or expired account | Policy-specific | Same generic failure, with detail in server logs only |

The application may keep different internal audit reasons. The difference should not be returned to the requester.

## Fix acceptance criteria

- The external status, message class, body shape, and timing class are consistent for all failed logins.
- The server records the real denial reason in protected logs.
- Rate limiting and lockout controls apply equally to unknown and known usernames.
- A lifecycle change invalidates existing sessions and refresh tokens.
- Account provisioning and deprovisioning events are auditable.

## Suggested vendor triage questions

1. Which lifecycle states currently produce a distinct external response?
2. Is the difference visible before or after password validation?
3. Does the same oracle appear in password recovery, SSO, or MFA enrollment?
4. Can the response be normalized without breaking administrative audit requirements?

## Recommended remediation

- Return one generic authentication-failure response for unknown, disabled, departed, locked, and invalid-password accounts.
- Record the exact denial reason only in protected server-side audit logs.
- Synchronize account disablement across CIMS and connected identity systems.
- Invalidate existing sessions when an account enters a disabled or departed state.

## Evidence scope

The response difference was confirmed in one authorized deployment. The report omits usernames, employee records, state values, database identifiers, and original response bodies.

## Timeline

- 2026-10-22: Duplicate observations consolidated into one root cause.
- 2026-10-24: Public TTA report published.
