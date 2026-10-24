# TTA-2026-006: Insurance-Management-System unauthenticated administrator account creation (CVE-2026-114245)

**Severity: High** — CNA-assigned CVSS 3.1: 7.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`); CNA-reported CVSS 4.0: 6.9 (Medium)

### Title

Missing authorization in the administrator-registration handler allows unauthenticated administrator account creation.

### Summary

The registration backend inserts a new administrator record when the submit field is present. It does not require an existing administrator session or check whether the caller is authorized to create administrators.

### Affected Version

Commit: `125362cc21dca20d74091a4913a5096bb58dd837`.

### Vulnerability Type

Missing Authorization / Improper Access Control (CWE-862).

### Affected Code

File: `Admin/includes/Admin-Register-inc.php`.

The handler processes `submit`, `Admin_id`, `password`, and the remaining registration fields before inserting into the `admin` table.

### Root Cause

The application assumes that only the administrative form will reach the handler. The backend does not start or validate an administrator session and treats direct POST access as sufficient authority.

### Steps to Reproduce

1. Deploy the vulnerable commit in an isolated PHP/MySQL test environment.
2. Ensure the test browser has no administrator session.
3. Submit the registration form directly to the backend using a unique synthetic administrator ID and test password.
4. Verify that the handler returns its success path and creates the synthetic row.
5. Confirm in the isolated database that the row exists, then remove it after testing.

### Impact

An unauthenticated remote caller can create an administrator account and use the normal administrator login path. This crosses the application's primary privilege boundary.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` — 7.3 High, assigned by VulDB. VulDB also reported CVSS 4.0 6.9 Medium.

## Status

TTA-2026-006 was published by the VulDB CNA on 2026-10-21 as CVE-2026-114245. The vulnerability was originally reported publicly to the upstream project on 2026-10-07. The upstream issue remains open, and no fixed version is known at the time of publication.

- Local advisory: `TTA-2026-006`
- CVE: `CVE-2026-114245`
- CVE state: `PUBLISHED`
- VulDB submission: `1018588`
- VulDB entry: `VDB-424679`
- Reporter: TypeThe0ry (VulDB User)

## Summary

`Insurance_Management_System/Admin/includes/Admin-Register-inc.php` performs the privileged administrator-registration operation without checking for an authenticated session or verifying that the caller is authorized to create administrators. Although the registration form is linked from the administrative interface, any remote client can submit directly to the backend handler and create an administrator account.

## Affected product

- Vendor: dhikshitha29
- Product: Insurance-Management-System
- Affected component: `Admin/includes/Admin-Register-inc.php`
- Affected parameters: `submit`, `Admin_id`, `password` and the remaining registration fields
- Confirmed vulnerable code commit: `125362cc21dca20d74091a4913a5096bb58dd837`
- Fixed version: none known

The official CVE record lists both `91de5edda5baa109ad8e9baf03ce6a3ceda84183` and `125362cc21dca20d74091a4913a5096bb58dd837` as affected. The first SHA is an initial commit containing only `README.md`; the vulnerable application code first appears in the second SHA. This advisory preserves the CNA metadata while identifying the commit that actually contains the affected file.

## Security impact

An unauthenticated remote user can create an administrator account with attacker-chosen credentials. The public login handler authenticates against the same `admin` table, so the created record is on the normal administrator authentication path. This crosses the application's primary privilege boundary and makes unauthorized administrative access possible.

## Prerequisites

- Network access to a deployed affected application.
- No authenticated session or existing administrator privilege is required.
- The submitted `Admin_id` must not already exist.

## Vulnerable behavior

The handler begins processing solely on the presence of the `submit` POST parameter. It reads the registration fields and inserts a new row into the `admin` table, but it never starts or validates an administrator session and performs no authorization check before the insert.

The use of a prepared statement and password hashing protects against separate classes of vulnerability, but it does not authorize the privileged account-creation operation.

## Reproduction

The following validation uses only synthetic data in an isolated laboratory deployment of commit `125362cc21dca20d74091a4913a5096bb58dd837`.

1. Choose an unused synthetic `Admin_id` and canary values for the remaining administrator fields.
2. Without any session cookie, submit a POST request directly to `/Admin/includes/Admin-Register-inc.php` with `submit=1`, matching `password` and `confirmPassword` values, and the required registration fields.
3. Observe a redirect containing `success=registered`.
4. Verify that the canary administrator row was created.
5. Remove the canary account after the test.

The original public report records the successful redirect and database row creation. It also supplies a follow-up login request, but does not preserve the login response; this advisory therefore treats unauthorized account creation as the directly reproduced effect and the subsequent administrator login as a code-path-supported impact. No production host, account, or data is required to reproduce the issue.

## Expected result

The backend handler should require an authenticated administrator session and an explicit privilege permitting administrator account creation. An unauthenticated direct request should be rejected without changing the database.

## Observed result

The handler accepts a direct unauthenticated POST and inserts a new administrator row. The application's login handler uses this same table for administrator authentication; the original public reproduction did not preserve the final login response.

## Root cause

Authorization is enforced only by where the registration form is linked in the user interface. The server-side handler trusts direct requests and does not independently authenticate or authorize the caller before performing a privileged state change.

## Recommended remediation

- Require a valid administrator session at the start of the backend handler.
- Check an explicit account-management privilege before accepting registration data.
- Return an authorization error and terminate processing before any database access when the check fails.
- Add CSRF protection to the authorized administrator-registration workflow.
- Audit existing administrator rows and invalidate accounts that were not created through an authorized workflow.
- Log and alert on administrator creation, including the authenticated actor.
- Add negative tests for unauthenticated and non-administrator direct POST requests.

## Classification

- CWE-285: Improper Authorization
- CWE-266: Incorrect Privilege Assignment
- CNA CVSS 3.1: 7.3 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:X/RC:C`
- CNA-reported CVSS 4.0: 6.9 Medium — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P`

The CNA's CVSS 3.1 score is used as the primary severity value here. Consumers should recalculate the CVSS 4.0 vector with their chosen scoring implementation rather than treating the CNA-reported numeric value as independently verified.

## Timeline

- 2026-10-07: Public upstream issue opened with reproduction details.
- 2026-10-21: VulDB published VDB-424679 and CVE-2026-114245.
- 2026-10-24: This repository advisory was published as TTA-2026-006.

## References

- [CVE Program record](https://www.cve.org/CVERecord?id=CVE-2026-114245)
- [CVE List V5 record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/114xxx/CVE-2026-114245.json)
- [VulDB entry VDB-424679](https://vuldb.com/vuln/424679)
- [VulDB submission 1018588](https://vuldb.com/submit/1018588)
- [Original upstream report and public proof of concept](https://github.com/dhikshitha29/Insurance-Management-System/issues/4)
- [Affected source at the confirmed code commit](https://github.com/dhikshitha29/Insurance-Management-System/blob/125362cc21dca20d74091a4913a5096bb58dd837/Insurance_Management_System/Admin/includes/Admin-Register-inc.php)
- [Administrator login handler at the confirmed code commit](https://github.com/dhikshitha29/Insurance-Management-System/blob/125362cc21dca20d74091a4913a5096bb58dd837/Insurance_Management_System/Admin/includes/Admin-Login-inc.php)

## Evidence boundary

The published reproduction uses an isolated local deployment and synthetic database records. This advisory contains no production hostname, IP address, credential, session value, or real personal data.
