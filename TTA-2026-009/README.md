# TTA-2026-009: CIMS password recovery does not enforce OTP completion before password reset

## Status

Published on 2026-10-24. Product owner, vendor, version, and build are not yet confirmed. CVE eligibility is pending product attribution.

## Summary

The assessed CIMS password-recovery workflow authorizes the final password change without requiring the server-side recovery transaction to record successful OTP verification. An unauthenticated requester can obtain a recovery transaction reference and use it to set a new password before completing the intended identity challenge.

The behavior was verified end to end: a synthetic account accepted the new password and obtained an authenticated session. An invalid recovery reference was rejected as a negative control.

## Security impact

An attacker who knows a valid username can take over the corresponding CIMS account without knowing its existing password or completing the OTP challenge. The affected deployment also linked some CIMS identities to an enterprise directory, so the same root cause could change a linked directory password. That directory impact depends on the deployment's identity mapping and service permissions.

## Finding mapping

- `#78`: core password-recovery state-machine flaw.
- `#79`: distinguishable recovery responses that assist username enumeration.
- `#81`: duplicate record of the directory-linked impact.
- `#85`: confirmation that the same recovery path affected a linked directory identity.

These records are grouped into one report because they concern the same recovery surface. `#81` and `#85` are duplicate or downstream impact records rather than separate vulnerabilities.

## Expected result

The server should permit the password change only after the same recovery transaction has completed OTP verification for the same account. The transaction must then be consumed exactly once.

## Observed result

The final password-change step accepted a recovery transaction that had not completed OTP verification. The synthetic account could then authenticate with the new password.

## Affected workflow

The affected flow has four logical stages:

1. A requester starts password recovery for a known account identifier.
2. The application creates a recovery transaction and returns a reference that is intended to be usable only after the challenge is completed.
3. The requester is expected to complete an OTP or equivalent identity challenge.
4. The application accepts the recovery transaction at the final password-change stage and changes the account password.

The defect is in the transition between stages 3 and 4. The final operation checks that a recovery reference exists and is usable, but does not require a server-side record showing that the challenge for the same account and transaction has succeeded.

The public report intentionally omits the real route names, parameter names, transaction identifiers, response bodies, and account values. Those details are unnecessary to understand the defect and would make the report directly reusable against the assessed deployment.

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

## Why the directory impact is conditional

The assessment recorded CIMS identities linked to an enterprise directory. If the CIMS reset service is allowed to change the linked directory password, the same missing state check can affect that directory identity. The scope depends on the service account permissions, account mapping, password-change connector, and whether the target is an application-only identity or a directory-backed identity. The public report therefore treats directory takeover as a deployment-specific impact of the same root cause.

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

## Classification

- CWE-640: Weak Password Recovery Mechanism for Forgotten Password
- CWE-287: Improper Authentication
- Provisional CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8)

## Evidence scope

The issue was reproduced in one authorized deployment using controlled identities. The report omits deployment identifiers, account values, recovery values, session material, directory details, and original requests.

## Timeline

- 2026-10-22: Findings consolidated from the assessment record.
- 2026-10-24: Public TTA report published.
