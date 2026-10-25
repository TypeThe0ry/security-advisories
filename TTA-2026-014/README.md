# TTA-2026-014: CIMS authentication cookies can be forged after ASP.NET machine-key compromise

**Severity: Informational** — No independent CVSS score assigned; the observed path requires prior host-level key access

### Title

Compromised ASP.NET machine-key material allows offline creation of CIMS authentication tickets.

### Summary

CIMS relies on ASP.NET machine-key material to protect its authentication ticket. In a controlled test performed after obtaining authorized host-level key access, a synthetic authentication ticket was accepted by CIMS and produced an administrator session without repeating password or MFA authentication.


### Affected Version

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified


### Vulnerability Type

Post-compromise key-management impact. No standalone remote vulnerability is claimed.

### Affected Code

ASP.NET authentication-ticket validation and machine-key configuration. Exact key locations, ticket purposes, claims, and cookie values are omitted.

### Root Cause

The application accepts tickets signed with the shared machine-key material. Once that material is readable after host or deployment compromise, an attacker can create tickets offline.


### Steps to Reproduce

This is a post-compromise validation. Run it only in a disposable staging copy using a synthetic administrator identity and test-only key material.

1. Establish a controlled staging scenario where the test operator can retrieve the staging-only signing material. Do not collect key material from production.
2. Record the staging application's key purpose and validation settings in the private test log. Do not place the key, cookie name, claims, or ticket bytes in the public report.
3. Use an approved internal test harness to create a synthetic ticket for the lab administrator. Keep the ticket and generated cookie only in the isolated lab.
4. Send the synthetic ticket to a harmless authenticated staging page and record whether it is accepted.
5. Rotate the staging key and invalidate existing test sessions.
6. Replay the same synthetic ticket. Secure result: the application rejects it and requires a fresh login.
7. Record only boolean results for pre-rotation acceptance and post-rotation rejection. Do not publish the key, ticket-generation code, ticket bytes, claims, or cookie.


### Impact

Disclosure of the machine-key material allows offline creation of authentication tickets for identities trusted by the application. Rotating account passwords alone does not invalidate tickets forged with the compromised key.

This report documents the consequence of key compromise. It does not identify a separate remote path that exposes the key.


### CVSS

No independent CVSS score is assigned because the observed path requires prior host-level key access.

## Status

Published on 2026-10-24 as a post-compromise CIMS impact report. This is not a CVE request.

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

## Evidence scope

The result was confirmed in one authorized deployment with a synthetic ticket. The report omits keys, storage locations, ticket format, claims, cookies, account identifiers, code, and internal management endpoints.

## Timeline

- 2026-10-22: Post-compromise impact documented during the assessment.
- 2026-10-24: Public TTA report published.
