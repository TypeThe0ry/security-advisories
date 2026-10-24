# TTA-2026-014: CIMS authentication cookies can be forged after ASP.NET machine-key compromise

**Severity: Informational** — No independent CVSS score assigned; the observed path requires prior host-level key access

## Status

Published on 2026-10-24 as a post-compromise CIMS impact report. This is not a CVE request.

## Summary

CIMS relies on ASP.NET machine-key material to protect its authentication ticket. In a controlled test performed after obtaining authorized host-level key access, a synthetic authentication ticket was accepted by CIMS and produced an administrator session without repeating password or MFA authentication.

## Affected application

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified

## Security impact

Disclosure of the machine-key material allows offline creation of authentication tickets for identities trusted by the application. Rotating account passwords alone does not invalidate tickets forged with the compromised key.

This report documents the consequence of key compromise. It does not identify a separate remote path that exposes the key.

## Expected result

Authentication-signing keys should be protected as high-value secrets, rotated after suspected host compromise, and coupled with a session-revocation mechanism. Privileged access should also require a current MFA assurance state rather than trusting only a locally signed ticket.

## Observed result

After the key material was available, a synthetic ticket was accepted as an authenticated CIMS administrator session.

## Trust model

ASP.NET authentication tickets are designed to be accepted by every application node that has the same signing and validation configuration. That makes the key material a trust anchor for the CIMS session layer. If the key is copied from a host, backup, deployment package, or secret store, the holder can create tickets offline without contacting the identity provider.

The observed result is a consequence of that trust model after key access was already obtained. It does not establish that the public login page exposes the key or that a low-privilege account can read it.

## Preconditions

- The attacker has already obtained host-level, application-process, backup, deployment, or equivalent secret-read access.
- The CIMS application uses the exposed key material to validate its authentication ticket.
- The forged ticket targets an identity that the application accepts for the requested operation.

The assessment used a synthetic ticket and did not use a real account, real cookie, or real key in the public evidence.

## Verification matrix

| Test case | Key state | Session result required after remediation |
| --- | --- | --- |
| Synthetic ticket signed with current key | Current | Accepted only when claims and assurance are valid |
| Synthetic ticket signed with old key | Rotated | Rejected after key rotation |
| Ticket with missing MFA assurance | Any | Privileged operation rejected |
| Ticket with modified identity claims | Any | Rejected by signature and claim validation |
| Existing session after suspected host compromise | Key rotated | Expired and forced to reauthenticate |

## Response steps

1. Treat the key as compromised if the host, backup, deployment package, or secret store was readable by an unauthorized principal.
2. Rotate the key on every CIMS node that validates the same ticket.
3. Expire all sessions and refresh tokens issued under the old key.
4. Review privileged logins and configuration changes during the exposure window.
5. Check whether the same key was reused by another application or environment.
6. Re-test old-ticket rejection and privileged MFA enforcement before restoring normal access.

## Design requirements

- Keep signing material in an approved secret-management system.
- Grant read access only to the application identity and controlled deployment process.
- Separate keys between applications, environments, and trust domains.
- Rotate keys after host compromise, backup exposure, or unauthorized deployment access.
- Require a current MFA assurance result for privileged operations even when the ticket signature is valid.
- Make key rotation a documented, tested incident-response procedure.

## Suggested vendor triage questions

1. Which CIMS nodes and environments share the ticket validation key?
2. Which storage locations and deployment artifacts can contain a copy?
3. Does rotating the key invalidate all existing tickets and refresh tokens?
4. Are privileged operations gated on a current MFA assurance claim?
5. Can the product support key versioning during rotation without accepting old tickets indefinitely?

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
