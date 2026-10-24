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

1. Create a restricted queue and a canary ticket that the test account cannot view.
2. Add a synthetic user to one of the ticket's role groups, such as AdminCc.
3. Verify that the test account cannot display the ticket.
4. As that same account, request:

   ```text
   GET /REST/1.0/group/<ROLE_GROUP_ID>?fields=id,Name,Members
   ```

5. Observe that the response includes the canary role-group member despite the caller lacking access to the ticket and group.
6. Request the same group through REST 2.0 and the administrative web interface. Those paths reject the same account.


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
