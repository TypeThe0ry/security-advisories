# TTA-2026-010: CIMS authentication fails for identities without a linked person record

**Severity: Medium** — Provisional CVSS 3.1: 4.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`)

### Title

Missing identity relationships cause an unhandled exception and authentication failure in CIMS.

### Summary

The login pipeline assumes that every accepted identity has a linked person or entity record. A synthetic identity without that relationship reaches a null-reference path, returns HTTP 500, and receives no session.

### Affected Version

UWCSEA College Information Management System (CIMS), public ASP.NET MVC 5 deployment. Vendor, version, and build are not publicly identified.

### Vulnerability Type

Improper Exception Handling / NULL Pointer Dereference (CWE-476, CWE-754).

### Affected Code

CIMS login identity-resolution and person/entity mapping path. Exact source files are not public.

### Root Cause

The application dereferences the expected person or entity object without validating that the relationship exists and is complete.

### Steps to Reproduce

1. In staging, create a synthetic system or service identity without the expected person/entity relationship.
2. Submit valid test credentials through the normal login flow.
3. Observe the HTTP 500 response and confirm that no session is created.
4. Repeat with a complete synthetic user as a control.

### Impact

Affected system or service identities cannot log in. If external responses differ from ordinary login failures, the error can also disclose account data relationships.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` — 4.3 Medium, provisional.

## Status

Published on 2026-10-24 as a deployment-level CIMS defect. No CVE request has been made.

## Summary

The CIMS login pipeline assumes that every authenticated identity has a linked person or entity record. When an otherwise valid system identity lacks that relationship, the pipeline dereferences a missing object, returns an HTTP 500 response, and does not establish a session.

## Affected application

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified

## Security impact

Affected system or service identities cannot complete interactive login. The exceptional response also distinguishes these identities from ordinary invalid usernames, exposing information about account type and data relationships.

No authentication bypass or unauthorized session was observed for this issue.

## Expected result

The application should handle an identity without a linked person record explicitly. It should either authorize the supported system-account workflow or return the same controlled authentication failure used for other denied logins.

## Observed result

The affected identity reached an unhandled null-reference path and received an HTTP 500 response. No authenticated session was created.

## Affected login sequence

The failure occurs after the identity provider or local credential check has identified a system or service identity, but before CIMS has finished building its application user context:

1. The login request is accepted for normal authentication processing.
2. CIMS resolves the identity to an internal account.
3. The login pipeline expects a related person or entity record.
4. The relationship is absent or incomplete.
5. The application dereferences the missing object instead of returning a controlled result.

The exception terminates the request with HTTP 500. Because the session is not committed, the result is denial of service for that identity rather than authentication bypass.

## Preconditions and affected identities

- The identity must be accepted far enough into the login pipeline to reach account-context construction.
- The internal account must lack the person or entity relationship expected by the application.
- The affected identity is typically a service, system, imported, or partially provisioned account rather than an ordinary complete user record.

The report does not assume that every service account is affected. The relationship and account lifecycle rules need to be checked against the product's supported data model.

## Verification matrix

| Test case | Relationship state | Result before remediation |
| --- | --- | --- |
| Complete synthetic user | Present and valid | Normal login path can continue |
| Synthetic system identity | Missing | HTTP 500 and no session |
| Synthetic identity | Relationship points to incomplete record | Must return a controlled result after remediation |
| Disabled identity | Disabled before session creation | Must be rejected without an exception |

The last two rows are acceptance cases for the fix and do not claim that the original deployment was tested with every malformed record shape.

## Information exposed by the failure

The HTTP 500 response is an availability problem first. If the external response, timing, status, or body differs from the generic invalid-login path, a requester can also infer that the username reached a valid internal account and that the account has a particular data relationship. Detailed exception information must remain server-side.

## Fix acceptance criteria

- Missing relationships are handled before any dereference.
- The application has an explicit policy for service and system identities.
- A missing or incomplete relationship cannot create a partial authenticated session.
- External responses are uniform for unknown, invalid, disabled, and malformed identities.
- Server logs retain a correlation ID and internal cause without returning stack traces or record values to the client.
- Tests cover imported users, deleted people, disabled users, duplicate mappings, and concurrent provisioning.

## Suggested vendor triage questions

1. Is a person or entity relationship mandatory for every supported CIMS account type?
2. Which account provisioning path can create an identity without that relationship?
3. Does the same exception occur in password login, SSO, password recovery, and administrative impersonation flows?
4. Which release contains the null check and the uniform error response?

## Recommended remediation

- Validate required identity relationships before dereferencing person or entity data.
- Define a supported authentication policy for service and system identities.
- Return a uniform external failure response and log the detailed cause only on the server.
- Add regression tests for missing, disabled, incomplete, and mismatched identity records.

## Classification

- CWE-476: NULL Pointer Dereference
- CWE-754: Improper Check for Unusual or Exceptional Conditions
- Provisional CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` (4.3)

## Evidence scope

The behavior was observed in one authorized deployment. The report omits account names, record identifiers, database values, exception pages, and deployment details.

## Timeline

- 2026-10-22: Duplicate observations consolidated into one root cause.
- 2026-10-24: Public TTA report published.
