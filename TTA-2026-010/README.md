# TTA-2026-010: CIMS authentication fails for identities without a linked person record

## Status

Published on 2026-10-24 as a deployment-level CIMS defect. No CVE request has been made.

## Summary

The CIMS login pipeline assumes that every authenticated identity has a linked person or entity record. When an otherwise valid system identity lacks that relationship, the pipeline dereferences a missing object, returns an HTTP 500 response, and does not establish a session.

## Security impact

Affected system or service identities cannot complete interactive login. The exceptional response also distinguishes these identities from ordinary invalid usernames, exposing information about account type and data relationships.

No authentication bypass or unauthorized session was observed for this issue.

## Finding mapping

- `#82`: login failure for a system identity without the expected relationship.
- `#86`: duplicate confirmation of the same null-reference path.

## Expected result

The application should handle an identity without a linked person record explicitly. It should either authorize the supported system-account workflow or return the same controlled authentication failure used for other denied logins.

## Observed result

The affected identity reached an unhandled null-reference path and received an HTTP 500 response. No authenticated session was created.

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
