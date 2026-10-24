# TTA-2026-002: Request Tracker 5.0.5 CustomFieldValue download omits parent-object authorization

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
5. Confirm the parent-object boundary for `attacker`:

   ```bash
   curl -sS -b attacker.jar -o /dev/null -w '%{http_code}\n' \
     "$RT_BASE/Ticket/Display.html?id=<SYNTHETIC_TICKET_ID>"
   curl -sS -b attacker.jar -o /dev/null -w '%{http_code}\n' \
     "$RT_BASE/REST/2.0/ticket/<SYNTHETIC_TICKET_ID>"
   # Expected control: 403 for both requests
   ```

6. Request the Binary custom-field value:

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

9. Compare the controls:
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

Privately reported to Best Practical on 2026-10-23 and publicly disclosed on 2026-10-24. No vendor response or CVE assignment had been received at the time of publication.

## Prerequisites

- A valid authenticated RT account.
- `SeeCustomField` permission for the relevant CustomField definition.
- No visibility permission for the target parent object.
- Knowledge or enumeration of an `ObjectCustomFieldValue` identifier.

## Recommended remediation

- Resolve the parent object from the `ObjectCustomFieldValue` record.
- Require the corresponding object visibility permission before emitting either short or large content.
- Reject values whose parent object cannot be loaded or whose object type is not explicitly supported.
- Add positive and negative tests covering tickets, assets, articles, binary values, and long-text values.
- Avoid relying on non-sequential identifiers as the authorization control.

## Evidence boundary

The vulnerability was dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using synthetic accounts and data. No customer hostname, IP address, credential, cookie, ticket, attachment, or production value is included in this advisory.
