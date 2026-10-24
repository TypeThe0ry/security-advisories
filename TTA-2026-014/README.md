# TTA-2026-014: CIMS authentication cookies can be forged after ASP.NET machine-key compromise

## Status

Published on 2026-10-24 as a post-compromise CIMS impact report. This is not a CVE request.

## Summary

CIMS relies on ASP.NET machine-key material to protect its authentication ticket. In a controlled test performed after obtaining authorized host-level key access, a synthetic authentication ticket was accepted by CIMS and produced an administrator session without repeating password or MFA authentication.

## Security impact

Disclosure of the machine-key material allows offline creation of authentication tickets for identities trusted by the application. Rotating account passwords alone does not invalidate tickets forged with the compromised key.

This report documents the consequence of key compromise. It does not identify a separate remote path that exposes the key.

## Finding mapping

- `#97`: machine-key recovery under host-level access and acceptance of a synthetic CIMS authentication ticket.

## Expected result

Authentication-signing keys should be protected as high-value secrets, rotated after suspected host compromise, and coupled with a session-revocation mechanism. Privileged access should also require a current MFA assurance state rather than trusting only a locally signed ticket.

## Observed result

After the key material was available, a synthetic ticket was accepted as an authenticated CIMS administrator session.

## Recommended remediation

- Generate a dedicated high-entropy key for CIMS and store it in an approved secret-management system.
- Limit key access to the minimum application identity and deployment process.
- Rotate the key after host, backup, deployment-package, or secret-store exposure.
- Force all existing sessions to expire after rotation and verify that tickets signed with the old key are rejected.
- Avoid sharing the same authentication key across unrelated applications or environments.
- Require a current MFA assurance marker for privileged operations.

## Classification

- Post-compromise credential and key-management impact.
- No independent CVSS score is assigned because the observed path required prior host-level key access.

## Evidence scope

The result was confirmed in one authorized deployment with a synthetic ticket. The report omits keys, storage locations, ticket format, claims, cookies, account identifiers, code, and internal management endpoints.

## Timeline

- 2026-10-22: Post-compromise impact documented during the assessment.
- 2026-10-24: Public TTA report published.
