# Token Cache Key v2 — Follow-up Shared Contract & Rollout Index

This is the authoritative cross-driver contract for the **second PR** in the token cache
key redesign. Read this file before making any changes in a per-repo prompt.

---

## 0. Background: what the first PR implemented

The first round of changes (already landed or in review under the branches below) fixed
the original `{host}:{username}:{type}` key by implementing a v2 format:

```
SnowflakeTokenCache.v2.<sha256hex(canonical_json(keyData))>
```

where `keyData` was a **5-field** JSON object — compact, keys sorted lexicographically:

```json
{"idp":"…","role":"…","snowflake":"…","token_type":"…","username":"…"}
```

That first PR also:
- Added `normalize_url` (strips scheme/userinfo/query/fragment, uppercases remainder) and
  `normalize_identifier` (uppercases outside `"…"` segments, preserves inside verbatim).
- Applied SHA-256 uniformly — one hash before dispatch, no per-backend hashing.
- Wired the same final key string to both OS keystore and JSON file backends.
- Removed legacy separator-injection guards (`;` / `:` in inputs).

---

## 0.1 What this follow-up PR changes (three surgical fixes)

### Fix 1 — Token type moves from `keyData` into the key prefix

Old key: `SnowflakeTokenCache.v2.<sha256({…, "token_type":"MFA_TOKEN", …})>`
New key: `SnowflakeTokenCache.v2.MFA_TOKEN.<sha256({… no token_type …})>`

Putting the token type in the readable prefix lets keystore/keyring tooling identify
and remove specific token classes without decoding the opaque hash.

### Fix 2 — MFA and ID token keys use only `snowflake` + `username`

For MFA and ID token flows, `idp` and `role` are removed from `keyData`:
- `role` is absent because role is **not** embedded in MFA or external-browser
  authentication calls. Including it would cause misses every time.
- `idp` is absent because MFA/ID token authentication always targets the Snowflake
  host directly — there is no separate identity provider endpoint.

OAuth flows are unaffected: they keep `idp`, `role`, `snowflake`, and `username`.

### Fix 3 — Golden test updated to prove lowercase preservation inside quotes

The previous golden test used all-uppercase strings inside double quotes
(e.g., `"FIRST LAST"`), which failed to exercise the quote-preservation branch of
`normalize_identifier`. The new test uses mixed case (e.g., `"First Last"`) and
asserts the quoted portion is preserved verbatim after normalization.

---

## 1. Repositories, tickets, and follow-up branches

The `<user>` segment is your local git user handle
(`git config user.email | cut -d'@' -f1` or `git config user.name`).

For each repo: **branch from the first PR's branch** (if it has not yet merged); or
**from the default branch** (if the first PR already merged).

| # | Repo | Local path | Public remote | Default branch | Ticket | Follow-up branch |
|---|------|-----------|---------------|----------------|--------|-----------------|
| 01 | libsnowflakeclient (C++) | `/Users/mhofman/Projects/libsnowflakeclient` | `ssh://git@github.com/snowflakedb/libsnowflakeclient` | `master` | [SNOW-3784428](https://snowflakecomputing.atlassian.net/browse/SNOW-3784428) | `<user>/SNOW-3784428-token-cache-key-v2-fixup` |
| 02 | snowflake-connector-net (C#) | `/Users/mhofman/Projects/snowflake-connector-net` | `git@github.com:snowflakedb/snowflake-connector-net.git` | `master` | [SNOW-3784414](https://snowflakecomputing.atlassian.net/browse/SNOW-3784414) | `<user>/SNOW-3784414-token-cache-key-v2-fixup` |
| 03 | snowflake-jdbc (Java) | `/Users/mhofman/Projects/snowflake-jdbc` | `ssh://git@github.com/snowflakedb/snowflake-jdbc` | `master` | [SNOW-3784426](https://snowflakecomputing.atlassian.net/browse/SNOW-3784426) | `<user>/SNOW-3784426-token-cache-key-v2-fixup` |
| 04 | snowflake-connector-nodejs (JS/TS) | `/Users/mhofman/Projects/snowflake-connector-nodejs` | `git@github.com:snowflakedb/snowflake-connector-nodejs.git` | `master` | [SNOW-3784415](https://snowflakecomputing.atlassian.net/browse/SNOW-3784415) | `<user>/SNOW-3784415-token-cache-key-v2-fixup` |
| 05 | gosnowflake (Go) | `/Users/mhofman/Projects/gosnowflake` | `ssh://git@github.com/snowflakedb/gosnowflake.git` | `master` | [SNOW-3784429](https://snowflakecomputing.atlassian.net/browse/SNOW-3784429) | `<user>/SNOW-3784429-token-cache-key-v2-fixup` |
| 06 | pdo_snowflake (PHP) | `/Users/mhofman/Projects/pdo_snowflake` | `ssh://git@github.com/snowflakedb/pdo_snowflake` | `master` | [SNOW-3784428](https://snowflakecomputing.atlassian.net/browse/SNOW-3784428) | `<user>/SNOW-3784428-token-cache-key-v2-fixup` |
| 07 | snowflake-connector-python (Python) | `/Users/mhofman/Projects/snowflake-connector-python` | `git@github.com:snowflakedb/snowflake-connector-python.git` | **`main`** | [SNOW-3784431](https://snowflakecomputing.atlassian.net/browse/SNOW-3784431) | `<user>/SNOW-3784431-token-cache-key-v2-fixup` |
| 08 | universal-driver (Rust) | `/Users/mhofman/Projects/universal-driver` | `git@github.com:snowflake-eng/universal-driver.git` | `main` | SNOW-TBD | `<user>/SNOW-TBD-token-cache-key-v2-fixup` |

**Not the targets** (wrong clones — never touch these):
- Any `/Users/mhofman/Projects/*-private` mirror
- `snowflake-connector-net-playground`, `snowflake-jdbc-playground`
- `pdo_snowflake/libsnowflakeclient/` (vendored tree inside pdo — changes go to repo 01 only)
- Any `/Users/mhofman/Projects/snowdrivers-analysis/drivers/*` copy

**Rollout order**: (01, 08 in parallel) → (02–05, 07 in parallel) → 06.
Repo 06 (pdo) is blocked on 01 landing first (it vendors a prebuilt `libsnowflakeclient.a`).
Repo 08 (universal-driver) is the Rust reference implementation and can run in parallel with 01.

---

## 2. The final v2 key contract

### 2.1 Key format

```
SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256hex(canonical_json(keyData))>
```

- Prefix: `SnowflakeTokenCache` (not `Snowflake`)
- Version: `v2`
- Token type: canonical uppercase string, e.g. `MFA_TOKEN`, `OAUTH_ACCESS_TOKEN`
- Hash: **lowercase** hex SHA-256 of the canonical JSON bytes of `keyData`

The **identical** key string is used for both the OS keystore backend and the JSON file
fallback. Hashing happens **exactly once** when the key is built; backends store verbatim.

### 2.2 `keyData` fields — differ by flow

`keyData` does **not** contain `token_type`; the token type appears in the key prefix.

**OAuth flows** (`OAUTH_ACCESS_TOKEN`, `OAUTH_REFRESH_TOKEN`, `DPOP_BUNDLED_ACCESS_TOKEN`, …):

| Field | Value |
|-------|-------|
| `idp` | Normalized IdP/token-endpoint URL |
| `role` | Normalized role |
| `snowflake` | Normalized Snowflake server URL |
| `username` | Normalized Snowflake username |

Sorted field order in canonical JSON: **`idp`, `role`, `snowflake`, `username`**.

**MFA and ID token flows** (`MFA_TOKEN`, `ID_TOKEN`):

| Field | Value |
|-------|-------|
| `snowflake` | Normalized Snowflake server URL |
| `username` | Normalized Snowflake username |

Sorted field order in canonical JSON: **`snowflake`, `username`**.

`role` is absent for MFA/ID because role is not embedded in those authentication calls.
`idp` is absent because MFA/ID authentication always targets the Snowflake host directly.

### 2.3 Canonical JSON serialization

The JSON hashed **must** be byte-for-byte identical across all drivers:

- **Compact**: no spaces after `:` or `,`, no newlines, no indentation.
- **Keys sorted lexicographically** (Unicode code-point ascending).
- **Standard JSON string escaping**: `"` → `\"`, `\` → `\\`, control chars escaped.
- Serialize to UTF-8 bytes → SHA-256 → **lowercase** hex.

Idiomatic per language:
- **C++**: emit manually (picojson does not sort keys — do not use it for key serialization).
- **C# / .NET**: `JsonConvert.SerializeObject(new SortedDictionary<string,string>{…}, Formatting.None)`.
- **Java**: `new ObjectMapper().writeValueAsString(new TreeMap<>(map))`.
- **Node.js**: build the object, then sort keys explicitly — `JSON.stringify` does NOT sort.
- **Go**: `json.Marshal(map[string]string{…})` — Go maps are marshaled in sorted key order.
- **Python**: `json.dumps(keyData, sort_keys=True, separators=(",", ":"))`.

### 2.4 Normalization rules

#### `normalize_url` — applies to `idp` and `snowflake`
1. Strip scheme (`https://` or `http://`).
2. Strip optional userinfo (`user:pass@`).
3. Drop query string and fragment.
4. Trim a root-only trailing slash.
5. **Uppercase the entire remainder** (host + optional `:port` + optional `/path`).

```
https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0
  → LOGIN.MICROSOFTONLINE.COM:443/TENANT-ID/OAUTH2/V2.0

https://myorg-myaccount.privatelink.snowflakecomputing.com
  → MYORG-MYACCOUNT.PRIVATELINK.SNOWFLAKECOMPUTING.COM
```

#### `normalize_identifier` — applies to `username` and `role`
- Uppercase every character **outside** double-quoted segments.
- Preserve the **entire** `"…"` segment verbatim — surrounding `"`, spaces, and lowercase
  letters inside are all kept exactly as-is.

```
"First Last"@long-corporate-domain.example.com
  → "First Last"@LONG-CORPORATE-DOMAIN.EXAMPLE.COM
         ↑↑↑↑ lowercase preserved inside quotes

"Analyst Role With Spaces":north_america:prod:readonly
  → "Analyst Role With Spaces":NORTH_AMERICA:PROD:READONLY
```

### 2.5 Field wiring per flow

| Flow | `idp` | `snowflake` | `role` |
|------|-------|-------------|--------|
| OAuth (auth code / refresh / DPoP) | normalized token-endpoint URL | normalized Snowflake server URL | normalized role from login params |
| MFA | *(absent from keyData)* | normalized Snowflake server URL | *(absent from keyData)* |
| External-browser ID token | *(absent from keyData)* | normalized Snowflake server URL | *(absent from keyData)* |

### 2.6 Canonical token type strings

| Flow / enum member | Correct `token_type` in key prefix |
|--------------------|-------------------------------------|
| ID token / `ID_TOKEN` | `ID_TOKEN` |
| MFA token / `MFA_TOKEN` | `MFA_TOKEN` |
| OAuth access / `OAUTH_ACCESS_TOKEN` | `OAUTH_ACCESS_TOKEN` |
| OAuth refresh / `OAUTH_REFRESH_TOKEN` | `OAUTH_REFRESH_TOKEN` |
| DPoP bundled access | `DPOP_BUNDLED_ACCESS_TOKEN` |

Driver-specific mapping hazards (these were wrong before the first PR too — verify they
are fixed in the first PR branch, or fix them here):

- **JDBC**: `CachedCredentialType.MFA_TOKEN.getValue()` previously returned `"MFATOKEN"`
  (no underscore). Must be `"MFA_TOKEN"`.
- **.NET**: `TokenType.MFAToken.ToString()` returns `"MFAToken"`. Use the `StringAttr`
  wire value `"MFA_TOKEN"` instead.
- **Node.js**: production used `AuthenticationTypes` strings such as
  `USERNAME_PASSWORD_MFA` (for MFA) and `OAUTH_AUTHORIZATION_CODE_ACCESS_TOKEN` (for
  OAuth). Map to canonical: `"MFA_TOKEN"`, `"OAUTH_ACCESS_TOKEN"`, `"OAUTH_REFRESH_TOKEN"`.
- **Python**: `TokenType.MFA_TOKEN.value = "MFA_TOKEN"` is correct; double-check others.
- **Go**: existing constants `idToken = "ID_TOKEN"`, `mfaToken = "MFA_TOKEN"`,
  `oauthAccessToken = "OAUTH_ACCESS_TOKEN"`, `oauthRefreshToken = "OAUTH_REFRESH_TOKEN"` —
  all correct; verify they were not changed.

### 2.7 Validation

- Reject (error or return empty) if `username` or `snowflake` is empty.
- `role` may be an empty string for OAuth when no role is configured.
- Old separator-injection guards (rejecting `;` or `:` in inputs) must be removed.

---

## 3. Golden test vectors (LOCK — do not change)

Every driver must reproduce **both** of these exact outputs. Add unit tests asserting them.

### Vector A — OAuth flow

**Raw inputs** (pre-normalization):

```
token_type : DPOP_BUNDLED_ACCESS_TOKEN   (key prefix only — not in keyData)
idp        : https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0
snowflake  : https://myorg-myaccount.privatelink.snowflakecomputing.com
username   : "First Last"@long-corporate-domain.example.com
role       : "Analyst Role With Spaces":north_america:prod:readonly
```

**After normalization** (note: `First Last` and `Analyst Role With Spaces` preserved
verbatim because they are inside double quotes):

```
idp        : LOGIN.MICROSOFTONLINE.COM:443/TENANT-ID/OAUTH2/V2.0
snowflake  : MYORG-MYACCOUNT.PRIVATELINK.SNOWFLAKECOMPUTING.COM
username   : "First Last"@LONG-CORPORATE-DOMAIN.EXAMPLE.COM
role       : "Analyst Role With Spaces":NORTH_AMERICA:PROD:READONLY
```

**Canonical JSON** (compact, sorted keys, 4 OAuth fields — no `token_type`):

```
{"idp":"LOGIN.MICROSOFTONLINE.COM:443/TENANT-ID/OAUTH2/V2.0","role":"\"Analyst Role With Spaces\":NORTH_AMERICA:PROD:READONLY","snowflake":"MYORG-MYACCOUNT.PRIVATELINK.SNOWFLAKECOMPUTING.COM","username":"\"First Last\"@LONG-CORPORATE-DOMAIN.EXAMPLE.COM"}
```

**Expected final key**:

```
SnowflakeTokenCache.v2.DPOP_BUNDLED_ACCESS_TOKEN.be782aa7c9abf8698adc9e6de61b954ccec7d9202899b44c2eb4e1dfa4313d5f
```

### Vector B — MFA flow

**Raw inputs** (pre-normalization):

```
token_type : MFA_TOKEN   (key prefix only — not in keyData)
snowflake  : https://myorg-myaccount.privatelink.snowflakecomputing.com
username   : "First Last"@long-corporate-domain.example.com
```

**After normalization**:

```
snowflake  : MYORG-MYACCOUNT.PRIVATELINK.SNOWFLAKECOMPUTING.COM
username   : "First Last"@LONG-CORPORATE-DOMAIN.EXAMPLE.COM
```

**Canonical JSON** (compact, sorted keys, 2 MFA/ID fields — no `idp`, `role`, `token_type`):

```
{"snowflake":"MYORG-MYACCOUNT.PRIVATELINK.SNOWFLAKECOMPUTING.COM","username":"\"First Last\"@LONG-CORPORATE-DOMAIN.EXAMPLE.COM"}
```

**Expected final key**:

```
SnowflakeTokenCache.v2.MFA_TOKEN.a508fa2858a6e22e9fdbc90b4149a3ff666d1acbb286c85ff179499ac92d75c8
```

`DPOP_BUNDLED_ACCESS_TOKEN` in Vector A is used purely as a test literal. Do **not** add
DPoP flows to repos that don't have them today (only JDBC has this type). Pass the string
`"DPOP_BUNDLED_ACCESS_TOKEN"` directly in the golden test without a named constant.

---

## 4. Cross-cutting pitfalls

### 4.1 `token_type` must not appear in `keyData`

The first PR serialized `token_type` inside the JSON object. Remove it. The type goes in
the key prefix only. Double-check no serialization helper or sort utility accidentally
re-inserts it.

### 4.2 Two `keyData` shapes — flow-dispatch must be correct

OAuth uses 4 fields: `idp`, `role`, `snowflake`, `username`.
MFA/ID uses 2 fields: `snowflake`, `username`.

Common mistakes:
- Leaving `idp`/`role` in the MFA key (gives wrong hash).
- Omitting `idp`/`role` from an OAuth key (gives wrong hash).
- Treating ID token the same as OAuth (ID token = MFA path: snowflake + username only).

### 4.3 Lowercase hex

- **JDBC** `HexUtil.byteToHexString()` returns **UPPERCASE** → add `byteToHexStringLower`.
- **.NET** `StringUtils.ToSha256Hash()` calls `BitConverter.ToString(…).Replace("-","")` →
  **UPPERCASE** → add `ToSha256HashLower`.
- **Go** `hex.EncodeToString` → lowercase ✓
- **Python** `hashlib.sha256(…).hexdigest()` → lowercase ✓
- **C++** — verify `Sha256.cpp` output; add `tolower` transform if it produces uppercase.

### 4.4 Sorted JSON keys

- **Node.js**: `JSON.stringify` uses insertion order, **not** sorted. Sort keys explicitly
  before building the JSON string.
- **Java**: `ObjectMapper` + `TreeMap` sorts ✓
- **.NET**: `SortedDictionary` sorts ✓
- **Go**: `json.Marshal(map[string]string{…})` sorts ✓
- **Python**: `json.dumps(…, sort_keys=True)` sorts ✓
- **C++**: emit manually in sorted order — do **not** use picojson (it preserves insertion
  order, not lexicographic).

### 4.5 Single hashing point

The final key is built once. Remove any secondary hashing inside backends:
- **Node.js**: `JsonCredentialManager.hashKey(key)` applied SHA-256 inside the JSON
  file backend on top of whatever the caller passed. Remove `hashKey()` entirely.
- **Python**: `FileTokenCache` called `key.hash_key()` internally; `KeyringTokenCache`
  stored the raw `string_key()`. Both must call `build_cache_key(key)` to get the
  pre-built final key.
- **C++**: confirm no platform backend (Apple, Windows, Linux) calls `sha256()` again
  after receiving the key from `convertTarget()`.

### 4.6 OAuth idp must be the full token-endpoint URL, not just the host

Several first-PR implementations may have accidentally stored only the hostname in `idp`:
- **Python** `_oauth_base.py`: `_idp_host` was already just a hostname. Replace with
  `_token_request_url` (full URL). Key change: `"LOGIN.MICROSOFTONLINE.COM"` (hostname
  only) → `"LOGIN.MICROSOFTONLINE.COM:443/TENANT-ID/OAUTH2/V2.0"` (full path).
- **JDBC** `getHostForOAuthCacheKey()` returned `.getHost()` (bare hostname). Rename and
  return the full token-request URL.
- **Node.js**: `authorizationUrl.host` / `tokenUrl.host` (hostname-only) → use the full
  URL string.
- **Go**: `oa.tokenURL()` returns the full URL already — verify no caller truncates it.
- **.NET**: `new Uri(GetTokenEndpoint()).Host` (hostname-only) → pass `GetTokenEndpoint()`
  directly and let `NormalizeUrl` handle it.

### 4.7 Cache filename stays `credential_cache_v1.json`

Do not rename the JSON file. The `v2` in the key prefix is the key-format version,
independent of the filename.

---

## 5. Tests required (every repo)

- **Golden hash A** — assert `SnowflakeTokenCache.v2.DPOP_BUNDLED_ACCESS_TOKEN.be782aa7…` exactly.
- **Golden hash B** — assert `SnowflakeTokenCache.v2.MFA_TOKEN.a508fa28…` exactly.
- **`normalize_url`** — scheme stripping, port/path uppercasing, no trailing slash on bare host.
- **`normalize_identifier`** — unquoted uppercased; quoted segment preserved **verbatim including lowercase**; mixed-case input.
- **Dimension isolation**:
  - Same IdP + different Snowflake host → different OAuth keys.
  - Same host/user + different role → different OAuth keys.
  - MFA and OAuth for same user/host → different keys (different prefix + field set).
  - Different `token_type` prefix → different keys by construction.
- **File backend** — stored key equals `SnowflakeTokenCache.v2.<TOKEN_TYPE>.<hash>`; no double-hash; round-trip set/get/delete.
- **OS keystore** — multi-account no-collision, multi-role no-collision (OAuth; where applicable).
- **Integration/E2E** — update any test that seeds the cache; add multi-account (shared IdP) and multi-role OAuth scenarios.

---

## 6. Docs and changelog

- Update doc comments that still describe the old `{host}:{user}:{type}` format or the 5-field keyData format.
- Add a **Bug fixes:** changelog entry:
  > Fixed token cache key collisions for multi-account (shared IdP) and multi-role scenarios
  > by switching to a versioned, SHA256-hashed canonical-JSON key with the token type in the
  > key prefix, applied uniformly across OS keystore and file backends.
- Entry must end with the repo-appropriate PR link (see each driver prompt).

---

## 7. Migration and compatibility

- No reader looks up first-PR v2 keys (or original v1 keys). Old entries become orphaned;
  the next connect transparently re-authenticates and writes a fresh entry.
- Active cleanup of orphaned entries is out of scope.

---

## 8. Definition of done (per repo)

- [ ] Golden hash A (OAuth) passes byte-exact (§3 Vector A).
- [ ] Golden hash B (MFA) passes byte-exact (§3 Vector B).
- [ ] Both backends use the final key verbatim; hashing occurs exactly once.
- [ ] OAuth call sites thread `idp` (full token-endpoint URL) + `snowflake` + `username` + `role`.
- [ ] MFA/ID call sites thread only `snowflake` + `username`; no `idp` or `role`.
- [ ] `token_type` does NOT appear in `keyData`; it is the third segment of the key prefix.
- [ ] Normalization + dimension-isolation tests pass.
- [ ] Integration/E2E seed keys updated; multi-account + multi-role no-collision scenarios added.
- [ ] Docs updated; changelog bug-fix entry with PR link added.
- [ ] Repo's own lint/format/test gates pass.
- [ ] Self-review checklist completed.

---

## 9. Self-review checklist (run before committing)

- [ ] Key format is `SnowflakeTokenCache.v2.<TOKEN_TYPE>.<hash>` — four dot-separated segments.
- [ ] `token_type` is **not** present in any serialized `keyData` JSON.
- [ ] Hash is **lowercase** hex.
- [ ] OAuth `keyData` JSON emits exactly 4 keys in sorted order: `idp, role, snowflake, username`.
- [ ] MFA/ID `keyData` JSON emits exactly 2 keys in sorted order: `snowflake, username`.
- [ ] JSON is compact (no extra whitespace).
- [ ] Token type value in the key prefix is the canonical string (e.g., `MFA_TOKEN` not `MFATOKEN`).
- [ ] Hashing occurs exactly once — no leftover `hashKey` / `ToSha256Hash` / `sha256` inside backends.
- [ ] OAuth `idp` is the full token-endpoint URL (not hostname-only).
- [ ] Empty-`username` and empty-`snowflake` validation present.
- [ ] Old separator-injection guards removed.
- [ ] Lint/format/test gate passes.
