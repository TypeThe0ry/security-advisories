# TTA-2026-002: Request Tracker 5.0.5 CustomFieldValue download omits parent-object authorization

**Status update (2026-11-10):** **Already addressed** under vendor-announced [CVE-2026-108274](https://www.cve.org/CVERecord?id=CVE-2026-108274); fixed in RT **5.0.11** and **6.0.4**. The original RT 5.0.5 reproduction is retained below as historical evidence.

**Severity: Medium** — Suggested CVSS 3.1: 6.5 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)

### Title

Missing parent-object authorization in `CustomFieldValue` downloads exposes content from tickets and other objects the caller cannot view.

### Summary

The Request Tracker 5.0.5 `/Download/CustomFieldValue/<id>/<filename>` handler checks whether the current user can see the CustomField definition but does not verify whether the user can view the ticket, asset, article, or other parent object that owns the requested value.

When `SeeCustomField` is granted at a broader scope than the parent object's visibility permission, an authenticated user can retrieve a value from an otherwise inaccessible object by supplying an enumerable `ObjectCustomFieldValue` identifier.


### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Component: `share/html/Download/CustomFieldValue/dhandler`
- Endpoint: `/Download/CustomFieldValue/<id>/<filename>`

Only RT 5.0.5 was dynamically tested. Other versions have not been claimed as affected without separate verification.


### Vulnerability Type

Missing Authorization / IDOR (CWE-862; related to CWE-639).

### Affected Code

File: `share/html/Download/CustomFieldValue/dhandler`

Affected operation: `GET /Download/CustomFieldValue/<synthetic-value-id>/<filename>`.

### Root Cause

The download handler evaluates `ObjectCustomFieldValue->CurrentUserCanSee`, which resolves the CustomField visibility check, and then emits `LargeContent`. It does not load and authorize the value's parent ticket, asset, article, or other object before returning the content.


### Steps to Reproduce

The following procedure uses synthetic values in an isolated RT 5.0.5 instance.

1. Deploy RT 5.0.5 in a disposable lab instance and set `RT_BASE` to the lab URL.
2. Create a restricted synthetic queue and ticket. Create two custom fields on the ticket: one Binary field containing `SYNTHETIC-BINARY-CANARY`, and one long-text field containing `SYNTHETIC-LONGTEXT-CANARY`.
3. Record the synthetic `ObjectCustomFieldValue` IDs from the lab database or the supported administration UI. Do not use production IDs.
4. Create three test users:
   - `attacker`: has `SeeCustomField` at a broad lab scope, but no `ShowTicket` or `SeeQueue` for the restricted queue;
   - `reader`: has both `SeeCustomField` and parent-object visibility;
   - `creator`: has neither permission.
5. Log in to the RT lab UI as each synthetic user and export separate lab-only sessions to `attacker.jar`, `reader.jar`, and `creator.jar`. Confirm the parent-object boundary for `attacker`:

   ```bash
   curl -sS -b attacker.jar -o /dev/null -w '%{http_code}\n' \
     "$RT_BASE/Ticket/Display.html?id=<SYNTHETIC_TICKET_ID>"
   curl -sS -b attacker.jar -o /dev/null -w '%{http_code}\n' \
     "$RT_BASE/REST/2.0/ticket/<SYNTHETIC_TICKET_ID>"
   # Expected control: 403 for both requests
   ```

6. Request the Binary custom-field value using the same lab session:

   ```bash
   curl -sS -b attacker.jar -D binary.headers \
     "$RT_BASE/Download/CustomFieldValue/<SYNTHETIC_BINARY_OCFV_ID>/canary.bin" \
     -o binary.body
   ```

7. Vulnerable result: HTTP 200 and `binary.body` contains the synthetic canary even though the parent ticket is not visible.
8. Repeat with the long-text value:

   ```bash
   curl -sS -b attacker.jar -D text.headers \
     "$RT_BASE/Download/CustomFieldValue/<SYNTHETIC_TEXT_OCFV_ID>/canary.txt" \
     -o text.body
   ```

9. Compare the controls using their own lab sessions:
   - `reader` should receive 200 for both values;
   - `creator` should receive 403;
   - an anonymous request should redirect to the login page;
   - `attacker` receives 200 in the vulnerable implementation despite the 403 parent-object checks.
10. Verify the database row after the test and remove the synthetic ticket and values.


### Impact

An authenticated user with `SeeCustomField` can read long-text or binary custom-field content from a parent object the user cannot otherwise view. Depending on local use of custom fields, disclosed data may include attachments, internal notes, identifiers, workflow data, or other sensitive ticket, asset, or article content.

The condition is most relevant where `SeeCustomField` is granted at the system or another broad scope while `ShowTicket`, `ShowAsset`, or equivalent parent-object permissions are narrower.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — 6.5 Medium.

## Status

**Already addressed; covered by [CVE-2026-108274](https://www.cve.org/CVERecord?id=CVE-2026-108274).** The [RT 5.0.11 release notes](https://docs.bestpractical.com/release-notes/rt/5.0.11) and [RT 6.0.4 release notes](https://docs.bestpractical.com/release-notes/rt/6.0.4), together with the [matching upstream fix](https://github.com/bestpractical/rt/commit/9f8964c07442233053029f867594a27550be6c19), support this mapping. Fixed releases are RT **5.0.11** and **6.0.4**.

This issue was privately reported to Best Practical on 2026-10-23 and publicly disclosed on 2026-10-24. On 2026-10-27, Best Practical replied that the issue had already been reported and would be addressed in the next RT 5 release, and requested testing on the latest release and encrypted reports. The earlier absence of a response at publication time is historical, not the current status.

A VulDB receipt dated 2026-10-24 records a CVE request. Its current processing status has not been verified, and this GitHub update does not change or withdraw that submission. This report now references the existing vendor-announced CVE rather than presenting the same finding as a new-CVE claim. Vendor or CNA credit for TypeThe0ry as an independent co-discoverer has not been confirmed.

Only RT 5.0.5 was dynamically tested for this report. The fixed-version conclusion is based on vendor documentation and source changes, not a completed dynamic regression test of this finding on the fixed releases.

## Prerequisites

- A valid authenticated RT account.
- `SeeCustomField` permission for the relevant CustomField definition.
- No visibility permission for the target parent object.
- Knowledge or enumeration of an `ObjectCustomFieldValue` identifier.

## Recommended remediation

- Upgrade to RT **5.0.11** or **6.0.4**, or a later supported release containing the fix. The following checks describe the authorization requirements, not additional unconfirmed defects in the fixed release.
- Resolve the parent object from the `ObjectCustomFieldValue` record.
- Require the corresponding object visibility permission before emitting either short or large content.
- Reject values whose parent object cannot be loaded or whose object type is not explicitly supported.
- Add positive and negative tests covering tickets, assets, articles, binary values, and long-text values.
- Avoid relying on non-sequential identifiers as the authorization control.

## Evidence boundary

The vulnerability was dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using synthetic accounts and data. No customer hostname, IP address, credential, cookie, ticket, attachment, or production value is included in this advisory.

## Timeline

- 2026-10-23: Privately reported to Best Practical.
- 2026-10-24: Public TTA report published; VulDB acknowledged the CVE request.
- 2026-10-27: Best Practical replied that the issue was already known and the next RT 5 release would address it.
- 2026-10-29: Vendor release notes announced the fix under CVE-2026-108274.
- 2026-11-10: Confirmed existing-CVE coverage in an encrypted follow-up to Best Practical; updated this report to already addressed. Independent-discovery credit remains unconfirmed. No VulDB status change was made by this documentation update.
