# TTA-2026-012: CIMS adaptive-authentication workflow prevents MFA-protected accounts from completing login

## Status

Published on 2026-10-24 as a CIMS identity-integration defect. No CVE request has been made.

## Summary

CIMS routes accounts that require MFA into an adaptive-authentication workflow that the assessed deployment cannot complete. The workflow returns an unsupported-flow error and never establishes a session, leaving affected staff and administrator accounts unable to log in through the required MFA path.

## Security impact

Accounts protected by the affected MFA policy can be locked out of CIMS. Administrators may be tempted to disable MFA to restore access, which removes the intended authentication control instead of fixing the workflow.

The test did not show an MFA bypass while the policy remained enabled.

## Finding mapping

- `#84`: adaptive-authentication workflow failure.
- `#88`: duplicate confirmation of the same failed workflow.
- `#93`: disabling the MFA requirement allowed login to proceed and confirmed that the failed workflow was the blocking stage; that configuration change is documented separately in TTA-2026-013.

## Expected result

Every account class that requires MFA should enter a supported workflow and either complete the challenge or fail with a controlled denial. A workflow error must not issue an authenticated session.

## Observed result

The assessed MFA-protected account entered an unsupported workflow and could not complete login. No authenticated session was created in that path.

## Recommended remediation

- Correct the mapping between CIMS account classes and supported adaptive-authentication workflows.
- Test administrator, staff, student, and service-account paths for success, denial, timeout, and unavailable-provider cases.
- Fail closed without issuing a session when the MFA provider or workflow is unavailable.
- Provide an audited break-glass recovery process instead of disabling MFA in the normal deployment configuration.

## Classification

- CWE-841: Improper Enforcement of Behavioral Workflow
- CWE-754: Improper Check for Unusual or Exceptional Conditions
- Provisional CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` (4.3)

## Evidence scope

The workflow failure was observed in one authorized deployment. The report omits configuration keys, identity mappings, account values, internal routes, provider identifiers, and original responses.

## Timeline

- 2026-10-22: Duplicate observations consolidated into one root cause.
- 2026-10-24: Public TTA report published.
