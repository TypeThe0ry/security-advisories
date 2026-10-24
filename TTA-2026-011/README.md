# TTA-2026-011: CIMS authentication responses disclose account lifecycle state

## Status

Published on 2026-10-24 as a low-severity CIMS information-disclosure defect. No CVE request has been made.

## Summary

CIMS returns distinguishable authentication responses according to an account's staff lifecycle state. A response for a departed or disabled staff record differs from the generic response used for an invalid login, allowing a requester to infer the account's business status.

## Security impact

The response difference can confirm that an account exists and disclose whether it is classified as departed or disabled. This information can support targeted credential attacks or social engineering, but it does not by itself grant access. In the recorded path, the lifecycle check was reached after credential handling, which limits its standalone exploitation value.

## Finding mapping

- `#83`: lifecycle-state response difference.
- `#87`: duplicate confirmation after a controlled state change.

## Expected result

Authentication failures should use the same external status, message, timing class, and response structure regardless of whether the username is unknown, the password is wrong, or the account is disabled.

## Observed result

The response changed according to the staff lifecycle state, making that state externally distinguishable.

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
