# TTA-2026-008: Request Tracker 5.0.5 DBI ExternalAuth exception-path authentication bypass candidate

**Severity: Medium** — Provisional CVSS 3.1: 4.8 (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`)

### Title

DBI ExternalAuth exception handling can leave an externally identified user in the session after password verification fails.

### Summary

Request Tracker 5.0.5 with DBI ExternalAuth may retain an externally identified user in the web session when password verification raises an exception. `RT::Authen::ExternalAuth::DoAuth` loads or creates the RT user in `CurrentUser` before calling the DBI password check. A `NULL` or length-mismatched password value can cause `RT::Util::constant_time_eq` to throw before the normal authentication-failure cleanup resets the session.

In an isolated test configuration, a login request using the affected external record returned an error but left the same session authenticated as the selected RT user. A control record containing a normal password hash combined with an incorrect password remained anonymous.


### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed tested version: 5.0.5
- Authentication mode: DBI ExternalAuth
- Components:
  - `lib/RT/Authen/ExternalAuth.pm`
  - `lib/RT/Authen/ExternalAuth/DBI.pm`
  - `lib/RT/Util.pm`
  - `share/html/Elements/DoAuth`

Only the recorded RT 5.0.5 laboratory configuration was dynamically tested. The exact ExternalAuth packaging/build and the affected release range require vendor confirmation.


### Vulnerability Type

Improper Authentication / Improper Exception Handling (CWE-287; related to CWE-755).

### Affected Code

Files: `lib/RT/Authen/ExternalAuth.pm`, `lib/RT/Authen/ExternalAuth/DBI.pm`, `lib/RT/Util.pm`, and `share/html/Elements/DoAuth`.

### Root Cause

The external-authentication state machine loads or creates the RT user before it verifies the password. In the [RT 5.0.5 `ExternalAuth.pm` implementation](https://github.com/bestpractical/rt/blob/rt-5.0.5/lib/RT/Authen/ExternalAuth.pm#L413-L485), `CurrentUser` is populated at lines 421-446 and the password check occurs later at line 461. Normal false returns are cleaned up at lines 482-485.

The [DBI password path](https://github.com/bestpractical/rt/blob/rt-5.0.5/lib/RT/Authen/ExternalAuth/DBI.pm#L295-L329) passes the derived password and database value to `RT::Util::constant_time_eq`. The [comparison helper](https://github.com/bestpractical/rt/blob/rt-5.0.5/lib/RT/Util.pm#L183-L191) throws when either value is undefined or their lengths differ.

That exception bypasses the ordinary false-result cleanup in `DoAuth`. The web authentication component invokes `DoAuth` after first checking whether `CurrentUser` is already populated, as shown in [`share/html/Elements/DoAuth`](https://github.com/bestpractical/rt/blob/rt-5.0.5/share/html/Elements/DoAuth#L48-L69). The result is an authentication state committed before the authentication decision is final.


### Steps to Reproduce

The isolated test compared a synthetic malformed external-user record with a normal-format control record. The malformed-record attempt returned an error after the external identity had been loaded, while a subsequent harmless access check showed that the same session retained that identity. The normal-format record combined with an incorrect password remained anonymous.

The exact laboratory harness, HTTP requests, session material, and operational proof of concept are intentionally withheld while vendor confirmation and remediation remain pending.


### Impact

An unauthenticated attacker who knows the username of an affected external record may obtain an authenticated RT session without a valid password. The resulting access is limited to the permissions of the corresponding RT user, or to the permissions assigned by `UserAutocreateDefaultsOnLogin` if the deployment automatically creates the user.

This report does not claim that RT grants administrator or operating-system privileges by default. Impact depends on the target account and local auto-creation policy.


### CVSS

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` — 4.8 Medium, provisional.

## Status

Public CVE candidate; vendor confirmation is pending. This report was published on 2026-10-24 after isolated laboratory reproduction. No advisory-specific vendor notice, fix confirmation, or CVE assignment had been recorded before publication. At the researcher's direction, this candidate was published after evidence review and data sanitization instead of entering a new private embargo; it is a documented exception to the repository's normal private-notice timeline.

The vendor still needs to confirm the supported status and exact version of the DBI ExternalAuth component, the affected release range, and whether this issue is distinct from an existing private fix or authentication advisory.

## Prerequisites

- RT is configured to use DBI ExternalAuth.
- The external data source contains a user whose password field is `NULL` or otherwise produces a length mismatch during the configured comparison.
- The attacker knows that user's login name.
- A corresponding RT user exists, or RT is configured to auto-create one during external login.

Because the malformed external record is not normally attacker-controlled, attack complexity is assessed as high.

## Relationship to existing CVEs

[CVE-2026-41076](https://www.cve.org/CVERecord?id=CVE-2026-41076) describes an authentication bypass in RT installations using LDAP/AD under server configurations that permit unauthenticated binds. This candidate concerns DBI authentication, malformed password data, an exception, and uncleared session state.

The different backend and failure mechanism support a vendor scope inquiry, but do not by themselves prove that a separate CVE must be assigned.

## Recommended remediation

- Do not assign an identified user to the live web session until all authentication checks succeed.
- Use a temporary user object during lookup and auto-creation, then commit it to `CurrentUser` only after successful verification.
- Wrap external authentication in a fail-closed exception boundary that resets `CurrentUser` on every failure, exception, and timeout.
- Reject `NULL`, malformed, incorrectly encoded, and unexpected-length password fields without throwing through the session state machine.
- Add negative tests that verify anonymous session state after wrong passwords, malformed records, backend exceptions, and timeouts.
- Review `UserAutocreateDefaultsOnLogin` so auto-created users receive only the intended minimum permissions.

## Evidence boundary

The behavior was reproduced only in an isolated RT 5.0.5 laboratory instance using a synthetic external database and synthetic canary user. The evidence did not demonstrate administrator, `SuperUser`, or operating-system privileges; RT access still depends on the mapped user and auto-creation policy. This report contains no customer hostname, IP address, credential, cookie, account name, database contents, internal path, production request, or exploit against a live system.

## Timeline

- 2026-10-22: Candidate documented from isolated RT 5.0.5 testing.
- 2026-10-24: Public TTA report published; vendor support status, duplicate status, affected range, fix status, and CVE eligibility remain unconfirmed.
