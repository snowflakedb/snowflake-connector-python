# Token Cache Key v2 Fixup — snowflake-connector-python (Python)

You are implementing a **follow-up PR** on top of the token-cache-key v2 change in
**snowflake-connector-python**. This is repo **07 of 07** and can run in parallel with
repos 02–05.

Read `00-INDEX-upd.md` (same directory as this file) before proceeding. This file
contains only the Python-specific implementation details.

---

## 1. Context: what the first PR already implemented

The first PR introduced:
- `TokenKey` dataclass (5 named fields): `token_type: TokenType`, `idp: str`,
  `snowflake: str`, `username: str`, `role: str`.
- `normalize_url(url: str) -> str` and `normalize_identifier(identifier: str) -> str`
  module-level functions in `token_cache.py`.
- `build_cache_key(key: TokenKey) -> str`: builds 5-field compact sorted JSON via
  `json.dumps(…, sort_keys=True, separators=(',', ':'))`, SHA-256-hashes it via
  `hashlib.sha256(…).hexdigest()` (lowercase), returns
  `SnowflakeTokenCache.v2.<lowercase_hex>`.
- `KeyringTokenCache.store/retrieve/remove` updated to call `build_cache_key(key)`.
- `FileTokenCache.store/retrieve/remove` updated to call `build_cache_key(key)` (no more
  `key.hash_key()` inside the backend).
- `_auth.py` call sites updated: `TokenKey` constructed with named fields for ID/MFA.
- `_oauth_base.py`: `_get_access_token_cache_key()` uses `_token_request_url` (full URL)
  instead of the old `_idp_host` (hostname only). `_token_request_url`, `_snowflake_host`,
  and `_role` threaded through `_OAuthTokensMixin.__init__`.
- No positional `TokenKey(a, b, c)` construction anywhere — all keyword arguments.

---

## 2. Repo setup — do this first

```bash
cd /Users/mhofman/Projects/snowflake-connector-python

REMOTE=$(git remote get-url origin)
echo "Remote: $REMOTE"
# Expected: git@github.com:snowflakedb/snowflake-connector-python.git
# The private mirror must NOT be used.

git fetch origin
git branch -r | grep "SNOW-3784431-token-cache-key-v2$" && \
  BASE="origin/$(git config user.email | cut -d'@' -f1)/SNOW-3784431-token-cache-key-v2" || \
  BASE="origin/main"
echo "Branching from: $BASE"

USER=$(git config user.email | cut -d'@' -f1)
git switch -c "${USER}/SNOW-3784431-token-cache-key-v2-fixup" --track $BASE
```

Ticket: [SNOW-3784431](https://snowflakecomputing.atlassian.net/browse/SNOW-3784431)

---

## 3. Pre-flight drift check

Verify the first PR's changes exist:

- `src/snowflake/connector/token_cache.py` — `TokenKey` has 5 named fields including
  `idp` and `role`; `build_cache_key`, `normalize_url`, `normalize_identifier` present.
- `KeyringTokenCache.store/retrieve/remove` call `build_cache_key`.
- `FileTokenCache.store/retrieve/remove` call `build_cache_key` (no `hash_key()` call).
- `auth/_auth.py` — `TokenKey` for ID/MFA uses named fields, `idp` and `role` threaded.
- `auth/_oauth_base.py` — `_token_request_url` field present; `_get_access_token_cache_key`
  uses it.
- Existing golden hash test asserting the 5-field format (will be replaced).

---

## 4. Implementation checklist

### 4.1 Update `build_cache_key` for flow-specific `keyData`

The new format is:
```
SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256(canonical_json(keyData))>
```

`keyData` is flow-dependent and **never contains `token_type`**:

```python
_OAUTH_TYPES = frozenset({
    'OAUTH_ACCESS_TOKEN',
    'OAUTH_REFRESH_TOKEN',
    'DPOP_BUNDLED_ACCESS_TOKEN',
})


def build_cache_key(key: TokenKey) -> str:
    """
    Build the versioned, uniformly-hashed v2 cache key.

    Format: SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256hex(canonical_json)>
    OAuth flows include idp/role; MFA and ID token flows include only
    snowflake/username.
    """
    if not key.snowflake:
        raise ValueError("snowflake URL must not be empty")
    if not key.username:
        raise ValueError("username must not be empty")

    token_type_value = key.token_type.value

    if token_type_value in _OAUTH_TYPES:
        key_data = {
            'idp':       normalize_url(key.idp or ''),
            'role':      normalize_identifier(key.role or ''),
            'snowflake': normalize_url(key.snowflake),
            'username':  normalize_identifier(key.username),
        }
    else:
        # MFA_TOKEN, ID_TOKEN — no idp or role
        key_data = {
            'snowflake': normalize_url(key.snowflake),
            'username':  normalize_identifier(key.username),
        }

    # sort_keys=True + no whitespace = canonical JSON required by spec
    canonical = json.dumps(key_data, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    return f'SnowflakeTokenCache.v2.{token_type_value}.{digest}'
```

Key changes from the first PR:
1. `token_type` removed from `key_data`.
2. MFA/ID path uses only `snowflake` + `username`.
3. `token_type_value` inserted between `v2.` and the hash.

### 4.2 Update MFA and ID token call sites — omit `idp` and `role`

In `auth/_auth.py`, `read_temporary_credentials`, `write_temporary_credentials`:

```python
# External browser / ID token
id_token_key = TokenKey(
    token_type=TokenType.ID_TOKEN,
    snowflake=self.host,
    username=self.user,
    # idp and role default to "" — omit them; build_cache_key will skip them
)

# MFA
mfa_key = TokenKey(
    token_type=TokenType.MFA_TOKEN,
    snowflake=self.host,
    username=self.user,
)
```

If `TokenKey` was defined with required positional fields for `idp` and `role` in the
first PR, change them to keyword-only with `""` defaults so MFA/ID call sites can omit them:

```python
@dataclass
class TokenKey:
    token_type: TokenType
    snowflake: str
    username: str
    idp: str = ""
    role: str = ""
```

### 4.3 Ensure OAuth `idp` is the full token-endpoint URL

If the first PR stored only the hostname in `_token_request_url` or `_idp_host`, correct
it. The full URL must be passed to `TokenKey.idp`:

```python
# _oauth_base.py
def _get_access_token_cache_key(self) -> TokenKey | None:
    if not (self._token_cache and self._user):
        return None
    return TokenKey(
        token_type=TokenType.OAUTH_ACCESS_TOKEN,
        snowflake=self._snowflake_host,
        username=self._user,
        idp=self._token_request_url,   # full URL, e.g. https://login.microsoftonline.com:443/…
        role=self._role or '',
    )
```

Eviction paths must build the same `TokenKey`. Verify they use `_token_request_url` (not
a hostname-only variant).

### 4.4 `TokenKey` field layout — no positional construction

All `TokenKey` construction must use keyword arguments. Grep for any remaining
positional `TokenKey(a, b, c)` patterns and convert them.

### 4.5 Update the golden test

Replace the old 5-field golden hash test with the two new vectors (see §5).

---

## 5. Test plan

- [ ] **Golden hash A (OAuth)** in `test/unit/test_token_cache_key.py`:
  ```python
  def test_oauth_golden_hash():
      # Build keyData manually to inject the DPOP literal as token_type prefix
      canonical = json.dumps({
          'idp':       normalize_url('https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0'),
          'role':      normalize_identifier('"Analyst Role With Spaces":north_america:prod:readonly'),
          'snowflake': normalize_url('https://myorg-myaccount.privatelink.snowflakecomputing.com'),
          'username':  normalize_identifier('"First Last"@long-corporate-domain.example.com'),
      }, sort_keys=True, separators=(',', ':'))
      digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
      assert f'SnowflakeTokenCache.v2.DPOP_BUNDLED_ACCESS_TOKEN.{digest}' == \
          'SnowflakeTokenCache.v2.DPOP_BUNDLED_ACCESS_TOKEN.be782aa7c9abf8698adc9e6de61b954ccec7d9202899b44c2eb4e1dfa4313d5f'
  ```
- [ ] **Golden hash B (MFA)**:
  ```python
  def test_mfa_golden_hash():
      key = TokenKey(
          token_type=TokenType.MFA_TOKEN,
          snowflake='https://myorg-myaccount.privatelink.snowflakecomputing.com',
          username='"First Last"@long-corporate-domain.example.com',
      )
      assert build_cache_key(key) == \
          'SnowflakeTokenCache.v2.MFA_TOKEN.a508fa2858a6e22e9fdbc90b4149a3ff666d1acbb286c85ff179499ac92d75c8'
  ```
- [ ] **`test_normalize_identifier`** — `'"First Last"@example.com'` →
      `'"First Last"@EXAMPLE.COM'` (lowercase inside quotes preserved, not uppercased).
- [ ] **`test_mfa_key_has_no_idp_or_role`** — assert MFA `key_data` JSON is
      `'{"snowflake":"…","username":"…"}'` (no `idp`, `role`, or `token_type`).
- [ ] **Dimension isolation**: different Snowflake URL → different OAuth keys; different role →
      different OAuth keys; MFA ≠ OAuth key for same user/host.
- [ ] **File backend** (`test_linux_local_file_cache.py`) — stored key equals
      `SnowflakeTokenCache.v2.<TOKEN_TYPE>.<hash>`; no double-hash; round-trip.
- [ ] **Keyring backend** — uses `build_cache_key`; multi-account no-collision.
- [ ] Update `test_oauth_token.py` and `test_auth_mfa.py`.

---

## 6. Build and test commands

```bash
cd /Users/mhofman/Projects/snowflake-connector-python
pip install -e ".[development]"
pytest test/unit/test_token_cache_key.py \
       test/unit/test_linux_local_file_cache.py \
       test/unit/test_oauth_token.py \
       test/unit/test_auth_mfa.py -v
pytest test/unit/ -v
```

---

## 7. Docs and changelog

- Update the module-level docstring in `token_cache.py` to describe the updated format.
- Update any docstring referencing `{host}:{user}:{type}`, `string_key()`, or `hash_key()`.
- Add a bug-fix entry to `DESCRIPTION.md`:

```markdown
- vX.Y(TBD)
    - Fixed token cache key collisions for multi-account (shared IdP) and multi-role
      scenarios by switching to a versioned, SHA256-hashed canonical-JSON key with the
      token type in the key prefix, applied uniformly across macOS/Windows keyring and
      the Linux file backend.
```

---

## 8. Self-review pass

Run through `00-INDEX-upd.md §9`, plus Python-specific items:

- [ ] `json.dumps(…, sort_keys=True, separators=(',', ':'))` — compact and sorted.
- [ ] `hashlib.sha256(…).hexdigest()` → lowercase hex (Python default).
- [ ] `KeyringTokenCache` calls `build_cache_key` — raw key not stored in keyring.
- [ ] `FileTokenCache` stores `build_cache_key` result (no `hash_key()` call).
- [ ] `token_type` NOT a key in `key_data` dict.
- [ ] MFA/ID `key_data` has exactly 2 keys (`snowflake`, `username`).
- [ ] OAuth `key_data` has exactly 4 keys (`idp`, `role`, `snowflake`, `username`).
- [ ] No positional `TokenKey(a, b, c)` construction — all keyword arguments.
- [ ] `_idp_host` (hostname only) no longer used to build cache keys.
- [ ] `mypy` / `ruff` / `flake8` checks pass.

---

## 9. Commit and report back

```bash
cd /Users/mhofman/Projects/snowflake-connector-python
git add -A
git commit -m "SNOW-3784431: token cache key v2 fixup — type in prefix, flow-specific keyData"
git log --oneline -3
```

Reply with:
1. Branch name.
2. One-paragraph change summary.
3. Golden test A and B results (pass/fail + actual output if fail).
4. Self-review verdict.
5. Deviations from spec.
