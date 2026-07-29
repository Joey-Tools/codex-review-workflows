# Placeholder-Only Fixture Templates

First capture the parent skill's skill-relative active-release binding. Require
the same `binding_sha256` in each resolver transaction envelope and require the
CLI result's `pool_version` to equal the binding. Use resolver actions
`validate`, `list`, and single-ID `get <id>`; those actions execute the bound
`synthetic-tokens validate`, metadata-only `synthetic-tokens list --json`, and
single-ID `synthetic-tokens get <id> --json` surfaces from validated snapshots.
Pass `--expect-binding-sha256` with the captured digest to every one of those
three actions; the option may be omitted only for the initial `bind`.
Never execute the returned interpreter or CLI pathname. Replace the complete
placeholder with the returned value. Do not concatenate, transform, encode, or
partially substitute a value.

## Single OAuth Session

```json
{
  "access_token": "<SYNTHETIC_ACCESS_TOKEN>",
  "refresh_token": "<SYNTHETIC_REFRESH_TOKEN>",
  "id_token": "<SYNTHETIC_ID_TOKEN>",
  "fixture_state": "active"
}
```

## Lifecycle Transition

```python
session = TokenSession(
    active_access_token="<SYNTHETIC_ACTIVE_ACCESS_TOKEN>",
    expired_access_token="<SYNTHETIC_EXPIRED_ACCESS_TOKEN>",
    active_refresh_token="<SYNTHETIC_ACTIVE_REFRESH_TOKEN>",
    consumed_refresh_token="<SYNTHETIC_CONSUMED_REFRESH_TOKEN>",
    fixture_state="active",
)
```

## Independent Credentials

```yaml
service_api_key: "<SYNTHETIC_API_KEY>"
bearer_token: "<SYNTHETIC_BEARER_TOKEN>"
fixture_state: "active"
```

Choose different catalog IDs for placeholders that model different credentials. Reuse one ID only when the fixture intentionally models the same credential appearing more than once.
