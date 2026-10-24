# TTA-2026-012: CIMS adaptive-authentication workflow prevents MFA-protected accounts from completing login

**Severity: Medium** — Provisional CVSS 3.1: 4.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`)

### Title

An unsupported adaptive-authentication workflow prevents MFA-protected CIMS accounts from completing login.

### Summary

CIMS routes accounts that require MFA into an adaptive-authentication workflow that the assessed deployment cannot complete. The workflow returns an unsupported-flow error and never establishes a session, leaving affected staff and administrator accounts unable to log in through the required MFA path.


### Affected Version

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified


### Vulnerability Type

Improper Workflow Enforcement / Authentication Integration Failure (CWE-841, CWE-754).

### Affected Code

CIMS account-assurance decision and SecureAuth adaptive-authentication handoff. Exact source files and provider configuration are not public.

### Root Cause

The account class requiring MFA is mapped to an unavailable or unsupported workflow. The application cannot complete the handoff and does not provide a working recovery path for the affected account class.


### Steps to Reproduce

The integration is expected to make a decision about the account's required assurance level and then hand the login to a supported MFA workflow. The observed sequence stopped at the handoff:

1. The account is identified as requiring MFA.
2. CIMS selects the adaptive-authentication path for that account class.
3. The selected workflow is not available or is not mapped for the deployment.
4. The provider returns an unsupported-workflow result.
5. CIMS does not complete the login and does not create an authenticated session.

The failure is therefore a login availability defect. The application did not treat the error as a successful authentication result.


### Impact

Accounts protected by the affected MFA policy can be locked out of CIMS. Administrators may be tempted to disable MFA to restore access, which removes the intended authentication control instead of fixing the workflow.

The test did not show an MFA bypass while the policy remained enabled.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` — 4.3 Medium, provisional.

## Status

Published on 2026-10-24 as a CIMS identity-integration defect. No CVE request has been made.

## Preconditions

- The account is assigned to a policy that requires MFA.
- CIMS must use the adaptive-authentication integration for that account class.
- The selected workflow is missing, unsupported, incorrectly mapped, or unavailable to the deployed provider.

Accounts that do not enter the affected MFA policy may continue through a different path. That difference is why testing must cover every supported account class.

## Verification matrix

| Test case | MFA policy | Provider/workflow state | Expected result |
| --- | --- | --- | --- |
| Synthetic staff account | Required | Supported | MFA challenge and successful session |
| Synthetic administrator account | Required | Unsupported mapping | Controlled denial; no session |
| Synthetic account | Required | Provider unavailable | Controlled denial; no session |
| Synthetic account | Not required | Supported non-MFA path | Login follows the configured policy |
| Synthetic account | Required | Challenge rejected or timed out | Denial; no session |

The observed behavior confirms the unsupported workflow. The remaining rows are the regression cases needed to validate a fix.

## Failure handling requirements

The provider error must not be converted into a password-only login, a partially authenticated session, or a session with an ambiguous assurance level. A failed handoff should be recorded with a correlation identifier and should not expose internal workflow names or provider configuration to the browser.

## Fix acceptance criteria

- Every supported CIMS account class maps to a documented workflow.
- MFA success is required before a privileged session is issued.
- Provider errors, timeouts, and missing workflows fail closed.
- A session records the assurance level that was actually achieved.
- Configuration changes are tested in a non-production environment before deployment.
- Login monitoring reports spikes in workflow errors and provider timeouts.

## Suggested vendor triage questions

1. Which account classes are expected to use adaptive authentication?
2. Which workflow identifiers are supported by the deployed provider version?
3. Is the failure caused by a product defect, a removed workflow, or a deployment mapping error?
4. Does a workflow error ever reach a session-creation branch?
5. Which configuration and regression tests should be included in the fixed release?

## Recommended remediation

- Correct the mapping between CIMS account classes and supported adaptive-authentication workflows.
- Test administrator, staff, student, and service-account paths for success, denial, timeout, and unavailable-provider cases.
- Fail closed without issuing a session when the MFA provider or workflow is unavailable.
- Provide an audited break-glass recovery process instead of disabling MFA in the normal deployment configuration.

## Evidence scope

The workflow failure was observed in one authorized deployment. The report omits configuration keys, identity mappings, account values, internal routes, provider identifiers, and original responses.

## Timeline

- 2026-10-22: Duplicate observations consolidated into one root cause.
- 2026-10-24: Public TTA report published.
