# TTA-2026-007: Request Tracker 5.0.5 stored XSS candidate through a calendar attachment filename

**Severity: Medium** — Provisional CVSS 3.1: 6.1 (`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`), conditional on supported unauthenticated mail ingress

## Status

Public CVE candidate; vendor confirmation is pending. This report was published on 2026-10-24 after isolated laboratory reproduction. No advisory-specific vendor notice, fix confirmation, or CVE assignment had been recorded before publication. At the researcher's direction, this candidate was published after evidence review and data sanitization instead of entering a new private embargo; it is a documented exception to the repository's normal private-notice timeline.

The assigning CNA or vendor still needs to determine whether this is a distinct vulnerability, an incomplete fix, or already within the scope of CVE-2025-9158 or CVE-2026-44229.

## Summary

Request Tracker 5.0.5 renders the filename of a `text/calendar` MIME attachment in the ticket history without HTML-escaping it. If an attacker-controlled calendar attachment can enter RT through a supported mail-ingress path, injected markup in the filename is stored with the ticket and interpreted when an RT user views the affected transaction.

A synthetic markup-bearing filename was emitted without escaping in an isolated RT 5.0.5 instance. No production system or real user data was used. Browser-side script execution was not separately preserved as evidence, so this report describes the reproduced unsafe HTML sink and the resulting stored-XSS candidate without overstating the test record.

## Affected product

- Vendor: Best Practical Solutions, LLC
- Product: Request Tracker
- Confirmed affected version: 5.0.5
- Component: `share/html/Elements/ShowTransactionAttachments`
- Content type: `text/calendar`

Only RT 5.0.5 was dynamically tested. Static review found the same raw filename concatenation in the `rt-5.0.10` and `rt-6.0.3` tags, but those versions were not dynamically tested and are not claimed as affected by this report.

## Security impact

Under a configuration where untrusted senders can submit calendar attachments through the normal RT mail workflow, an attacker can persist attacker-controlled HTML in a ticket transaction. When an RT user views the transaction, the browser may interpret that content in the RT origin, creating a stored cross-site scripting condition.

Successful exploitation could allow actions available to the victim's browser session. The exact impact depends on the browser, RT configuration, the victim's permissions, and whether the standard mail-ingress path accepts the crafted MIME filename.

## Prerequisites

- An attacker-controlled `text/calendar` MIME part must reach RT through a supported mail-ingress path.
- The MIME filename must be preserved into the RT attachment record.
- An authenticated RT user must view the affected ticket transaction.

If the attachment can be introduced only through a customer-specific, incorrectly exposed `NoAuth` route or an otherwise unsupported mail configuration, that condition is deployment-specific and the CVE eligibility and CVSS assessment must be reconsidered.

## Safe reproduction

The following procedure uses only an inert markup canary in an isolated RT 5.0.5 instance. It does not require executable JavaScript.

1. Configure the laboratory instance's supported mail gateway to create or update a synthetic ticket.
2. Submit a message containing a `text/calendar` MIME part whose filename is an inert HTML canary, such as a unique empty formatting element.
3. Open the synthetic ticket's transaction history as a test user.
4. Inspect the filename element in the rendered DOM.
5. Observe whether the canary is represented as a DOM element instead of escaped text.
6. Repeat with an ordinary filename as a negative control.

## Expected result

The calendar attachment filename should be encoded as text for the HTML context. Markup characters should appear literally and must not create DOM elements.

## Observed result

In the isolated RT 5.0.5 test, a synthetic markup-bearing filename was emitted unescaped inside the calendar download label. Browser-side execution was not separately preserved in the evidence record.

## Root cause

The calendar branch reads the attachment filename into `$name` and concatenates it directly into an HTML string:

```perl
$m->out('<span class="downloadfilename">' . ( $name || 'meeting.ics' ) . '</span>');
```

The value is not HTML-escaped before it is passed to `$m->out`. The relevant source is visible in the [RT 5.0.5 `ShowTransactionAttachments` implementation](https://github.com/bestpractical/rt/blob/rt-5.0.5/share/html/Elements/ShowTransactionAttachments#L150-L182).

For scope comparison only, the same concatenation is statically visible in the [`rt-5.0.10` tag](https://github.com/bestpractical/rt/blob/rt-5.0.10/share/html/Elements/ShowTransactionAttachments#L168-L183) and the [`rt-6.0.3` tag](https://github.com/bestpractical/rt/blob/rt-6.0.3/share/html/Elements/ShowTransactionAttachments#L162-L177). This source observation does not replace dynamic validation of those releases.

## Relationship to existing CVEs

- [CVE-2025-9158](https://www.cve.org/CVERecord?id=CVE-2025-9158) covers stored XSS in calendar invitation parsing for RT 5.0.4 through 5.0.8 and RT 6.0.0 through 6.0.1. The public fix context concerns displayed invitation data, while this candidate concerns the MIME attachment filename sink.
- [CVE-2026-44229](https://www.cve.org/CVERecord?id=CVE-2026-44229) covers uploaded content served inline before RT 5.0.10 and 6.0.3.

The different source sink is a reason to request scope review, not proof that a new CVE is required. Best Practical or the assigning CNA should decide whether this report is distinct, an incomplete fix, or already covered.

## Recommended remediation

- HTML-escape the filename before rendering it in every attachment-display branch.
- Use a shared text-rendering helper instead of assembling HTML with untrusted attachment metadata.
- Add regression tests with markup-bearing MIME filenames for calendar and non-calendar attachments.
- Verify the end-to-end mail-ingress path and ensure unauthenticated web routes are not exposed as a substitute for a trusted MTA configuration.

## Classification

- CWE-79: Improper Neutralization of Input During Web Page Generation
- Provisional CVSS 3.1, only if unauthenticated delivery through supported mail ingress is confirmed: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1)

The score is provisional. It must be recalculated if introducing the attachment requires authentication, non-default configuration, or a separate security-boundary failure.

## Evidence boundary

The unsafe sink was dynamically reproduced only in an isolated RT 5.0.5 laboratory instance using a synthetic ticket, test account, and synthetic markup-bearing filename. The original test value is intentionally omitted. This report contains no customer hostname, IP address, credential, cookie, email address, ticket content, production payload, or executable exploit.

## Timeline

- 2026-10-22: Candidate documented from isolated RT 5.0.5 testing.
- 2026-10-24: Public TTA report published; vendor scope, duplicate status, affected range, fix status, and CVE eligibility remain unconfirmed.
