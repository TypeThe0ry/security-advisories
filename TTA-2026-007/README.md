# TTA-2026-007: Request Tracker 5.0.5 stored XSS candidate through a calendar attachment filename

**Status update (2026-11-10):** **Reported filename sink addressed in RT 5.0.11 and 6.0.4, verified by source review.** The specific CVE mapping remains unconfirmed. The historical test demonstrated unsafe HTML output, not separately preserved browser-side script execution.

**Severity: Medium** — Provisional CVSS 3.1: 6.1 (`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`), conditional on supported unauthenticated mail ingress

### Title

Unescaped `text/calendar` attachment filenames create a stored XSS candidate in Request Tracker.

### Summary

Request Tracker 5.0.5 renders the filename of a `text/calendar` MIME attachment in the ticket history without HTML-escaping it. If an attacker-controlled calendar attachment can enter RT through a supported mail-ingress path, injected markup in the filename is stored with the ticket and interpreted when an RT user views the affected transaction.

A synthetic markup-bearing filename was emitted without escaping in an isolated RT 5.0.5 instance. No production system or real user data was used. Browser-side script execution was not separately preserved as evidence, so this report describes the reproduced unsafe HTML sink and the resulting stored-XSS candidate without overstating the test record.


### Affected Version

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Component: `share/html/Elements/ShowTransactionAttachments`
- Content type: `text/calendar`

Only RT 5.0.5 was dynamically tested. Static review found the same raw filename concatenation in the `rt-5.0.10` and `rt-6.0.3` tags, but those versions were not dynamically tested and are not claimed as affected by this report.


### Vulnerability Type

Stored Cross-Site Scripting (CWE-79).

### Affected Code

File: `share/html/Elements/ShowTransactionAttachments`, calendar branch.

The filename is concatenated into the `downloadfilename` span without HTML escaping.

### Root Cause

The calendar branch reads the attachment filename into `$name` and concatenates it directly into an HTML string:

```perl
$m->out('<span class="downloadfilename">' . ( $name || 'meeting.ics' ) . '</span>');
```

The value is not HTML-escaped before it is passed to `$m->out`. The relevant source is visible in the [RT 5.0.5 `ShowTransactionAttachments` implementation](https://github.com/bestpractical/rt/blob/rt-5.0.5/share/html/Elements/ShowTransactionAttachments#L150-L182).

For scope comparison only, the same concatenation is statically visible in the [`rt-5.0.10` tag](https://github.com/bestpractical/rt/blob/rt-5.0.10/share/html/Elements/ShowTransactionAttachments#L168-L183) and the [`rt-6.0.3` tag](https://github.com/bestpractical/rt/blob/rt-6.0.3/share/html/Elements/ShowTransactionAttachments#L162-L177). This source observation does not replace dynamic validation of those releases.


### Steps to Reproduce

The following procedure uses only an inert markup canary in an isolated RT 5.0.5 instance. It does not require executable JavaScript.

1. Configure a disposable RT 5.0.5 instance with its supported mail gateway and create a synthetic ticket.
2. Prepare a MIME message with a harmless calendar part. Use a test-only filename containing an inert tag, for example `meeting-<b>CANARY</b>.ics`; do not use a script or event-handler attribute:

   ```text
   From: lab-sender@example.test
   To: lab-ticket@example.test
   Subject: synthetic calendar canary
   MIME-Version: 1.0
   Content-Type: multipart/mixed; boundary="LAB"

   --LAB
   Content-Type: text/calendar; name="meeting-<b>CANARY</b>.ics"
   Content-Disposition: attachment; filename="meeting-<b>CANARY</b>.ics"

   BEGIN:VCALENDAR
   VERSION:2.0
   PRODID:-//Example//Lab//EN
   BEGIN:VEVENT
   UID:synthetic-canary@example.test
   DTSTART:20300101T120000Z
   DTEND:20300101T123000Z
   SUMMARY:Synthetic calendar canary
   END:VEVENT
   END:VCALENDAR
   --LAB--
   ```

3. Deliver the message through the lab mail gateway and record the synthetic ticket ID.
4. Open the ticket history as a separate synthetic RT user and inspect the calendar attachment label in the DOM.
5. Vulnerable result: the `CANARY` text appears inside a created `<b>` element instead of as escaped text such as `&lt;b&gt;CANARY&lt;/b&gt;`.
6. Repeat with a plain filename such as `meeting-plain.ics` as a negative control.
7. Stop at DOM confirmation. Do not send executable JavaScript or test the public mail gateway.


### Impact

Under a configuration where untrusted senders can submit calendar attachments through the normal RT mail workflow, an attacker can persist attacker-controlled HTML in a ticket transaction. When an RT user views the transaction, the browser may interpret that content in the RT origin, creating a stored cross-site scripting condition.

Successful exploitation could allow actions available to the victim's browser session. The exact impact depends on the browser, RT configuration, the victim's permissions, and whether the standard mail-ingress path accepts the crafted MIME filename.


### CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — 6.1 Medium, conditional on supported unauthenticated mail ingress.

## Status

**Reported sink addressed; CVE mapping unconfirmed.** The [upstream filename-escaping fix](https://github.com/bestpractical/rt/commit/05d21b5c0c22491e7c34bc570331df150c7c28f8) HTML-escapes the exact calendar attachment filename sink described here. That escaping is present in both the [RT 5.0.11 source](https://github.com/bestpractical/rt/blob/rt-5.0.11/share/html/Elements/ShowTransactionAttachments) and [RT 6.0.4 source](https://github.com/bestpractical/rt/blob/rt-6.0.4/share/html/Elements/ShowTransactionAttachments). This is a source-level fix confirmation, not a completed browser regression test or proof of the full original XSS exploit chain.

The report was published on 2026-10-24 after isolated RT 5.0.5 testing, without a recorded advisory-specific private notice before publication. At the researcher's direction, it was published after evidence review and data sanitization instead of entering a new private embargo. An encrypted follow-up sent to Best Practical on 2026-11-10 included this report link and the bounded fix conclusion. No advisory-specific vendor confirmation or independent-discovery credit has been recorded.

CVE-2026-108342 is a possible umbrella mapping, but the public release notes do not identify this filename sink specifically. This report does not claim that mapping is confirmed or that a new CVE is required.

## Prerequisites

- An attacker-controlled `text/calendar` MIME part must reach RT through a supported mail-ingress path.
- The MIME filename must be preserved into the RT attachment record.
- An authenticated RT user must view the affected ticket transaction.

If the attachment can be introduced only through a customer-specific, incorrectly exposed `NoAuth` route or an otherwise unsupported mail configuration, that condition is deployment-specific and the CVE eligibility and CVSS assessment must be reconsidered.

## Relationship to existing CVEs

- [CVE-2026-108342](https://www.cve.org/CVERecord?id=CVE-2026-108342) covers multiple HTML-escaping issues in the [RT 5.0.11](https://docs.bestpractical.com/release-notes/rt/5.0.11) and [RT 6.0.4](https://docs.bestpractical.com/release-notes/rt/6.0.4) release notes, including ticket history. The [exact calendar filename fix](https://github.com/bestpractical/rt/commit/05d21b5c0c22491e7c34bc570331df150c7c28f8) is verified, but its specific association with that aggregate CVE remains unconfirmed.
- [CVE-2025-9158](https://www.cve.org/CVERecord?id=CVE-2025-9158) concerns calendar invitation parsing; [CVE-2026-44229](https://www.cve.org/CVERecord?id=CVE-2026-44229) concerns uploaded content served inline. Neither relationship, by itself, resolves the identifier for this filename sink.

The finding is not presented as an unfixed current-release sink or as an established new-CVE claim.

## Recommended remediation

- Upgrade to RT **5.0.11** or **6.0.4**, or a later supported release containing the filename-escaping fix.
- HTML-escape the filename before rendering it in every attachment-display branch.
- Use a shared text-rendering helper instead of assembling HTML with untrusted attachment metadata.
- Add regression tests with markup-bearing MIME filenames for calendar and non-calendar attachments.
- Verify the end-to-end mail-ingress path and ensure unauthenticated web routes are not exposed as a substitute for a trusted MTA configuration.

## Evidence boundary

The unsafe sink was dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using a synthetic ticket, test account, and synthetic markup-bearing filename. The original test value is intentionally omitted. This report contains no customer hostname, IP address, credential, cookie, email address, ticket content, production payload, or executable exploit.

## Timeline

- 2026-10-22: Candidate documented from isolated RT 5.0.5 testing.
- 2026-10-24: Public TTA report published; vendor scope, duplicate status, affected range, fix status, and CVE eligibility were unconfirmed at publication.
- 2026-10-29: RT 5.0.11 and 6.0.4 released with the calendar filename escaping change.
- 2026-11-10: Verified the exact sink is escaped in both release tags and updated the status. Sent the report link and bounded conclusion to Best Practical in an encrypted follow-up. Specific CVE mapping and vendor credit remain unconfirmed.
