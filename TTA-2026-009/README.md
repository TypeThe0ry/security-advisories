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
