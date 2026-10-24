# TTA-2026-013: CIMS MFA enforcement depends on a mutable deployment flag

**Severity: Informational** — No independent CVSS score assigned; the observed path requires configuration-write access and valid credentials

## Status

Published on 2026-10-24 as a CIMS configuration and architecture report. This is not a CVE request.

## Summary

CIMS MFA enforcement for the assessed administrator workflow depends on a single mutable deployment setting. When that setting was disabled in a controlled test, the account no longer entered the adaptive-authentication stage and could establish a normal authenticated session with its existing password.

## Affected application

- Application: UWCSEA College Information Management System (CIMS)
- Public login: <https://webapps.uwcsea.edu.sg/cims/Account/Login>
- Observable technology: ASP.NET MVC 5 on Microsoft IIS
- Visible identity integration: SecureAuth script loaded by the public login page
- Vendor, source repository, version, and build: not publicly identified

## Security impact

A person who can modify the application configuration can remove the MFA requirement without changing the account or identity-provider policy. This creates a single control point for a high-value authentication requirement and makes configuration integrity critical to administrator access.

The test required existing configuration-write access and a valid account password. It did not demonstrate a remote unauthenticated MFA bypass.

## Expected result

MFA requirements for privileged accounts should be enforced by a centrally managed policy and represented in the authenticated session's assurance state. A local application setting should not silently downgrade a privileged login to password-only authentication.

## Observed result

Disabling the deployment setting removed the adaptive-authentication step and allowed the existing credentials to establish an administrator session.

## Control dependency

The assessed login path makes the MFA decision from an application deployment setting. The setting is read before the account is issued its final session. When the setting requires MFA, the account is sent to the adaptive-authentication path described in TTA-2026-012. When the setting is disabled, the same account can complete password authentication without that additional assurance step.

The problem is the trust placed in one mutable application value for a privileged security decision. The setting can be useful as a configuration input, but it should not be the only authority that determines whether a privileged session is allowed.

## Preconditions

- The requester already has permission to modify the application deployment configuration or its backing configuration store.
- The requester has valid credentials for the target account.
- The application is restarted or reloads configuration after the change.

The assessment did not demonstrate that an ordinary remote user can modify the setting. The observed result describes the security consequence of configuration compromise and the need for a second policy enforcement point.

## Verification matrix

| Test case | Configuration state | Required result |
| --- | --- | --- |
| Privileged account | MFA required | MFA challenge is required before session creation |
| Privileged account | MFA setting changed | Change is logged, alerted, and subject to deployment approval |
| Privileged account | Missing or malformed setting | Fail closed; do not silently downgrade to password-only |
| Privileged session | MFA assurance absent | Privileged operation is rejected |
| Policy restored | MFA required again | Existing downgraded sessions are expired |

## Design requirements

- Store the privileged MFA policy in a centrally managed identity policy where possible.
- Verify an MFA assurance claim or equivalent server-side result before allowing privileged actions.
- Treat a missing, invalid, or conflicting policy value as deny for privileged operations.
- Protect configuration changes with deployment review, integrity monitoring, and audit logs.
- Alert when a change lowers the required authentication assurance.
- Expire sessions created under a weaker policy when the stronger policy is restored.

## Suggested vendor triage questions

1. Which component is authoritative for privileged-account MFA?
2. Can the application issue a privileged session when the MFA assurance is absent?
3. Does configuration reload immediately, on restart, or through a separate service?
4. Are policy changes logged with the actor, reason, approval, and affected sessions?
5. Can the fixed implementation reject a missing or malformed policy value safely?

## Recommended remediation

- Enforce privileged-account MFA in the identity provider and verify the resulting assurance claim in CIMS.
- Protect authentication-policy configuration with controlled deployment, review, and change auditing.
- Alert on any change that lowers the required authentication assurance.
- Reject privileged sessions that do not contain the required MFA assurance marker.
- Use an audited break-glass process for recovery rather than changing the normal MFA policy.

## Classification

- CWE-16: Configuration
- CWE-693: Protection Mechanism Failure
- No independent CVSS score is assigned because the observed path already required configuration-write access and valid credentials.

## Evidence scope

The behavior was confirmed through a reversible change in one authorized deployment. The report omits the setting name, configuration location, account details, session data, and management paths.

## Timeline

- 2026-10-22: Configuration dependency documented during the assessment.
- 2026-10-24: Public TTA report published.
