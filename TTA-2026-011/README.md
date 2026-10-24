# TTA-2026-011: CIMS authentication responses disclose account lifecycle state

## Status

Published on 2026-10-24 as a low-severity CIMS information-disclosure defect. No CVE request has been made.

## Summary

CIMS returns distinguishable authentication responses according to an account's staff lifecycle state. A response for a departed or disabled staff record differs from the generic response used for an invalid login, allowing a requester to infer the account's business status.

## Affected application

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Vendor, source repository, version, and build: not publicly identified

## Security impact

The response difference can confirm that an account exists and disclose whether it is classified as departed or disabled. This information can support targeted credential attacks or social engineering, but it does not by itself grant access. In the recorded path, the lifecycle check was reached after credential handling, which limits its standalone exploitation value.

## Expected result

Authentication failures should use the same external status, message, timing class, and response structure regardless of whether the username is unknown, the password is wrong, or the account is disabled.

## Observed result

The response changed according to the staff lifecycle state, making that state externally distinguishable.

## Affected decision path

The observable difference is created by the account-state gate in the login pipeline:

1. The requester submits a username and password.
2. CIMS resolves the supplied identity and evaluates its lifecycle state.
3. A disabled or departed staff record takes a different response branch from an unknown or ordinary invalid account.
4. The requester can compare the result across candidate usernames.

The exact message, status code, response length, and timing are omitted from this public report. Any one of those differences can act as an oracle when it is stable and externally visible.

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

## Security impact boundary

The information can support password spraying, targeted phishing, or account lifecycle mapping. It does not disclose the password and does not create a session by itself. The low CVSS score reflects that the assessment did not show a direct confidentiality or integrity breach from this response difference alone.

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

## Classification

- CWE-203: Observable Discrepancy
- CWE-204: Observable Response Discrepancy
- Provisional CVSS 3.1: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` (3.7)

## Evidence scope

The response difference was confirmed in one authorized deployment. The report omits usernames, employee records, state values, database identifiers, and original response bodies.

## Timeline

- 2026-10-22: Duplicate observations consolidated into one root cause.
- 2026-10-24: Public TTA report published.
