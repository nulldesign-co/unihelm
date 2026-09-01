# Error codes

Every error the API returns carries a stable code and slug. Clients should branch on the **slug**; the message is free to change with translations.

This file is generated from `unihelm_core::error::ErrorCode`. Regenerate it with:

```
cargo run -p unihelm-core --bin gen-error-docs > docs/api/errors.md
```

| Code | Slug | HTTP | Area |
|------|------|------|------|
| `UNI-1000` | `internal` | 500 | generic |
| `UNI-1001` | `not_implemented` | 501 | generic |
| `UNI-1002` | `service_unavailable` | 503 | generic |
| `UNI-1003` | `rate_limited` | 429 | generic |
| `UNI-1100` | `invalid_credentials` | 401 | authentication |
| `UNI-1101` | `session_expired` | 401 | authentication |
| `UNI-1102` | `session_invalid` | 401 | authentication |
| `UNI-1103` | `totp_required` | 401 | authentication |
| `UNI-1104` | `totp_invalid` | 401 | authentication |
| `UNI-1105` | `account_suspended` | 403 | authentication |
| `UNI-1106` | `account_locked` | 403 | authentication |
| `UNI-1107` | `csrf_invalid` | 403 | authentication |
| `UNI-1200` | `invalid_input` | 400 | validation |
| `UNI-1201` | `invalid_domain` | 400 | validation |
| `UNI-1202` | `invalid_db_name` | 400 | validation |
| `UNI-1203` | `invalid_username` | 400 | validation |
| `UNI-1204` | `invalid_path` | 400 | validation |
| `UNI-1205` | `invalid_php_version` | 400 | validation |
| `UNI-1206` | `invalid_port` | 400 | validation |
| `UNI-1207` | `password_too_weak` | 400 | validation |
| `UNI-1300` | `permission_denied` | 403 | authorization |
| `UNI-1301` | `tenant_scope_violation` | 403 | authorization |
| `UNI-1302` | `quota_exceeded` | 402 | authorization |
| `UNI-1303` | `plan_feature_disabled` | 403 | authorization |
| `UNI-1304` | `reseller_allocation_exceeded` | 402 | authorization |
| `UNI-1400` | `not_found` | 404 | resource state |
| `UNI-1401` | `already_exists` | 409 | resource state |
| `UNI-1402` | `domain_already_exists` | 409 | resource state |
| `UNI-1403` | `conflict` | 409 | resource state |
| `UNI-1404` | `dependents_exist` | 409 | resource state |
| `UNI-1500` | `agent_unavailable` | 503 | agent IPC |
| `UNI-1501` | `agent_protocol` | 400 | agent IPC |
| `UNI-1502` | `agent_timeout` | 504 | agent IPC |
| `UNI-1503` | `peer_credential_rejected` | 403 | agent IPC |
| `UNI-1504` | `unknown_operation` | 404 | agent IPC |
| `UNI-1600` | `unsupported_distro` | 400 | system |
| `UNI-1601` | `package_backend_failed` | 500 | system |
| `UNI-1602` | `service_action_failed` | 500 | system |
| `UNI-1603` | `command_failed` | 500 | system |
| `UNI-1700` | `task_not_found` | 404 | tasks |
| `UNI-1701` | `task_not_cancellable` | 409 | tasks |
| `UNI-1702` | `task_failed` | 500 | tasks |
| `UNI-1800` | `config_drift` | 409 | config management |
| `UNI-1801` | `config_validation_failed` | 400 | config management |
| `UNI-1802` | `config_rollback` | 500 | config management |
