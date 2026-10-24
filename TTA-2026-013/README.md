# TTA-2026-013: CIMS MFA enforcement depends on a mutable deployment flag

## Status

Published on 2026-10-24 as a CIMS configuration and architecture report. This is not a CVE request.

## Summary

CIMS MFA enforcement for the assessed administrator workflow depends on a single mutable deployment setting. When that setting was disabled in a controlled test, the account no longer entered the adaptive-authentication stage and could establish a normal authenticated session with its existing password.

## Security impact

A person who can modify the application configuration can remove the MFA requirement without changing the account or identity-provider policy. This creates a single control point for a high-value authentication requirement and makes configuration integrity critical to administrator access.

The test required existing configuration-write access and a valid account password. It did not demonstrate a remote unauthenticated MFA bypass.

## Finding mapping

- `#93`: controlled change to the MFA enforcement setting and confirmation of the resulting login behavior.

## Expected result

MFA requirements for privileged accounts should be enforced by a centrally managed policy and represented in the authenticated session's assurance state. A local application setting should not silently downgrade a privileged login to password-only authentication.

## Observed result

Disabling the deployment setting removed the adaptive-authentication step and allowed the existing credentials to establish an administrator session.

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
