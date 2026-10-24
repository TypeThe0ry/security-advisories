# TTA-2026-005: Insurance-Management-System unauthenticated SQL injection in EditPolicyHolder.php (CVE-2026-114243)

## Status

TTA-2026-005 was published by the VulDB CNA on 2026-10-21 as CVE-2026-114243. The vulnerability was originally reported publicly to the upstream project on 2026-10-07. The upstream issue remains open, and no fixed version is known at the time of publication.

- Local advisory: `TTA-2026-005`
- CVE: `CVE-2026-114243`
- CVE state: `PUBLISHED`
- VulDB submission: `1018587`
- VulDB entry: `VDB-424678`
- Reporter: TypeThe0ry (VulDB User)

## Summary

`Insurance_Management_System/Agent/ManagePolicy/EditPolicyHolder.php` concatenates the user-controlled `Policy_no` and `Name` GET parameters directly into a SQL query passed to `mysqli_query()`. The page includes `Agent/header.php`, but that header only sends a redirect when an agent session is absent; it does not terminate request processing. As a result, an unauthenticated remote user can still reach and manipulate the vulnerable query.

## Affected product

- Vendor: dhikshitha29
- Product: Insurance-Management-System
- Affected component: `Agent/ManagePolicy/EditPolicyHolder.php`
- Affected parameters: `Policy_no`, `Name`
- Confirmed vulnerable code commit: `125362cc21dca20d74091a4913a5096bb58dd837`
- Fixed version: none known

The official CVE record lists both `91de5edda5baa109ad8e9baf03ce6a3ceda84183` and `125362cc21dca20d74091a4913a5096bb58dd837` as affected. The first SHA is an initial commit containing only `README.md`; the vulnerable application code first appears in the second SHA. This advisory preserves the CNA metadata while identifying the commit that actually contains the affected file.

## Security impact

An unauthenticated attacker can alter the intended database query and access policy-holder records outside the application's authorization boundary. Depending on the database account's privileges and server configuration, SQL injection may also permit broader disclosure or modification of application data.

The CNA-assigned CVSS v3.1 score models partial confidentiality, integrity, and availability impact. This advisory does not claim a higher impact without separate verification.

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

## Reproduction

The following validation uses only synthetic data in an isolated laboratory deployment of commit `125362cc21dca20d74091a4913a5096bb58dd837`.

1. Create a synthetic `Policy_holder` row and note its numeric `Policy_no`.
2. Without an authenticated agent session, request `EditPolicyHolder.php` with the correct `Policy_no` and a deliberately incorrect `Name`. Confirm that the application reports that the record does not exist.
3. Repeat the request with a harmless boolean expression appended to `Policy_no`, while keeping the deliberately incorrect `Name`.
4. Observe that the update form is rendered with the synthetic row despite the mismatched name and the absence of an authenticated session.
5. Repeat using a harmless boolean predicate in the string-valued `Name` parameter and a nonexistent `Policy_no`; observe the same authorization and query-control failure.

The original public report contains the full laboratory setup and request examples. No production host, account, or data is required to reproduce the issue.

## Expected result

The endpoint should reject unauthenticated requests before performing any database query. Authenticated requests should use parameterized SQL so that both parameters are treated only as data.

## Observed result

The redirect does not stop PHP execution, and attacker-controlled values alter the SQL statement. A true injected predicate causes a synthetic record to be returned even when the other selector is intentionally incorrect.

## Root cause

Two flaws make the endpoint remotely exploitable without authentication:

- user input is concatenated directly into SQL rather than bound through a prepared statement; and
- the authentication guard sends a redirect but does not terminate execution.

## Recommended remediation

- Replace the interpolated query with a prepared statement and bound parameters.
- Validate `Policy_no` as an integer before database access.
- Enforce authentication and authorization before loading any policy-holder record.
- Terminate request processing after an authentication redirect; preferably centralize the guard so protected handlers cannot continue accidentally.
- Limit the database account to the minimum permissions required by the application.
- Add negative tests for unauthenticated access and SQL metacharacters in both parameters.

## Classification

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
- CNA CVSS 3.1: 7.3 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:X/RC:C`
- CNA-reported CVSS 4.0: 6.9 Medium — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P`

The CNA's CVSS 3.1 score is used as the primary severity value here. Consumers should recalculate the CVSS 4.0 vector with their chosen scoring implementation rather than treating the CNA-reported numeric value as independently verified.

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
