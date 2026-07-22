# Aera Cloud Internal Admin API 与真实跨仓库 E2E 设计

- 日期：2026-07-22
- 状态：已由用户批准，待实施
- 涉及仓库：`bignormal/aera-cloud`、`bignormal/aera-admin`

## 1. 背景

`aera-admin` 已完成独立员工认证、密码加 TOTP、六类固定角色 RBAC、管理员生命周期、双人审批、Admin Outbox、幂等操作和不可变审计，并已实现 Aera Cloud 用户、设备、会话管理的 BFF 与页面。

当前端到端测试仍由 `aera-admin/e2e/cloud-stub` 模拟 Cloud 行为。`aera-cloud` 只有受限命令行管理能力，没有真实 Internal Admin HTTP API。因此现状只能证明 Admin 侧工作流和消费契约，不能证明真实 Cloud 数据、处置事务和 Cloud 审计已经闭环。

本设计实现真实 Cloud Internal Admin API，并用真实 `aera-cloud` 替换 Stub 完成跨仓库 E2E。

## 2. 目标

本次必须完成：

1. 在 `aera-cloud` 同一进程中增加独立 TLS Internal Admin Listener。
2. 同时要求受信 mTLS 客户端身份和短期 Ed25519 服务 JWT。
3. 实现当前 `aera-admin/api/openapi/cloud-admin-client.yaml` 中的完整消费契约。
4. 使用 Cloud 真实身份加密/HMAC 索引完成精确邮箱或手机号查询，并只返回脱敏身份。
5. 实现用户、设备、会话读取和单设备、单 session family、账号禁用/恢复操作。
6. 通过 `administrative_revision`、持久化 `admin_operations` 和 Cloud 审计实现并发控制、幂等重放和结果对账。
7. 删除 Admin E2E Cloud Stub，使用真实 Cloud 二进制、真实 PostgreSQL、真实 Redis 和真实 TLS 服务身份完成 Playwright E2E。
8. 两个仓库分别保有可独立执行的测试与构建，并提供一条可复现的本地跨仓库验收命令。

## 3. 明确不在本次范围

- Admin 审计查询页面或新的审计查询 BFF。
- `/system/settings` 页面或在线修改安全配置。
- Official Managed Agent 管理。
- 财务、充值、运营活动或内容管理。
- 桌面端、`aera-runtime`、`aera-api`、官网改动。
- 生产部署、证书签发系统或云网络策略实际发布。
- 普通用户完整身份导出、模糊搜索或批量处置。
- Hermes Profile、Memory、会话内容、技能、凭据或本地学习数据读取。

## 4. 已批准的关键决策

### 4.1 部署模型

采用一个 `aera-cloud` 进程、两个独立监听器：

- 公网监听器继续使用现有 `httpapi.New` Router。
- Internal Admin Listener 使用独立 Router、独立 TLS 配置和独立认证中间件。
- Internal Admin 路由永远不注册到公网 Router。
- 两个监听器共享 Cloud PostgreSQL、Redis 和领域服务，但不共享外部 HTTP 路由或用户认证逻辑。
- 任一监听器非预期退出时取消进程根 context，并统一优雅关闭，避免只剩一个监听器的半可用状态。

不新增独立 `aera-cloud-admin-api` 部署进程，也不在 Cloud 内再增加一层异步 Worker。Admin Outbox 已承担至少一次投递；Cloud 命令在一次数据库事务内同步完成。

### 4.2 范围边界

本次严格闭合已有用户、设备、会话、账号处置和 operation 查询契约。Cloud 审计必须写入，但审计查询 API 与 Admin 审计页面留到后续阶段。

## 5. 请求链路与信任边界

```text
员工浏览器
    -> Aera Admin 同源 BFF
    -> Admin PostgreSQL Outbox
    -> mTLS + service JWT
    -> Cloud Internal Admin Listener
    -> Cloud PostgreSQL transaction
```

- 浏览器永远不直接访问 Cloud Internal Admin API。
- 员工密码、TOTP、恢复码、Admin Cookie 和 CSRF Token 不跨越 Admin BFF。
- Cloud 不连接 Admin 数据库，也不把 `actor_admin_id` 当作请求认证依据。
- Cloud 以 mTLS 客户端和服务 JWT 认证调用方；`actor_admin_id`、`approval_id` 与 `request_id` 只作为授权后的业务与审计上下文。
- Admin 负责员工 RBAC、step-up 与双人审批。Cloud 对账号禁用/恢复额外要求非空 `approval_id`，用于防止消费方绕过既定命令形态。
- 设备与会话单项撤销不要求 `approval_id`。

## 6. Internal Admin 配置

在 Cloud `config.Config` 中新增独立配置组。建议环境变量如下：

```text
AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED
AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR
AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE
AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE
AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE
AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE
AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER
AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT
AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID
AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS
```

约束：

- 默认关闭；关闭时不读取密钥文件，也不建立内部监听器。
- 启用时上述配置全部必填，缺失或无效将阻止 Cloud 启动。
- Internal Admin 地址不得与公网监听地址相同。
- 证书、私钥、客户端 CA 和 JWT 公钥只从运行时文件读取，不进入仓库、镜像层或结构化日志。
- JWT 公钥文件只接受 Ed25519 PKIX public key PEM；不得接受私钥或其他算法。
- HMAC key ring 使用与现有 Cloud key ring 相同的 active key 加多历史 key 模式，每个 key 解码后必须恰好 32 字节。
- 幂等键、请求 fingerprint 和 cursor 使用带版本前缀的不同 HMAC domain，禁止直接复用同一无前缀消息格式。
- 新写入使用 active HMAC key；查询历史幂等记录时依次使用仍受信的 key，以支持无中断轮换。
- 生产网络仍必须通过私有子网、安全组或服务网格限制内部端口；应用层双认证不能替代网络隔离。

配置或密钥错误只返回稳定启动错误，不输出文件内容、完整路径、证书 subject、连接串或解析细节。

## 7. TLS 与服务 JWT

### 7.1 mTLS

- Internal Admin Listener 只启用 TLS 1.3。
- `ClientAuth` 必须使用 `RequireAndVerifyClientCert`。
- 客户端信任根只来自配置的 Internal Admin Client CA，不使用系统根代替。
- 不信任 `X-Client-Cert`、`X-Forwarded-Client-Cert` 等 HTTP Header。
- 无证书、未知 CA、用途不匹配或过期证书在 HTTP Handler 前终止握手。

### 7.2 服务 JWT

JWT 必须满足：

- 三段紧凑 JWS，header 固定 `alg=EdDSA`、`typ=JWT`。
- 使用配置的 Ed25519 公钥验证签名。
- `iss` 和 `sub` 与 Cloud 配置完全匹配。
- `aud` 固定为 `aera-cloud-admin`。
- `iat`、`nbf`、`exp` 必须存在；有效期不超过 5 分钟，只允许有限时钟偏差。
- `jti` 必须为 Admin 生成的高熵非空值。
- `scope` 必须是非空、无重复且全部属于固定允许集合的字符串数组。
- 拒绝未知 claim、错误类型、`alg=none`、非 Ed25519 算法、过期令牌和过长令牌。

服务 JWT 通过后，再检查路由所需最小 scope：

| 路由组 | 必需 scope |
|---|---|
| health、用户、设备和会话读取 | `users:read` |
| 设备撤销 | `devices:write` |
| session family 撤销 | `sessions:write` |
| 用户禁用/恢复 | `accounts:write` |
| operation 查询 | `operations:read` |

- mTLS 失败不会进入 HTTP 层。
- JWT 缺失或无效返回统一 `401`。
- JWT 有效但缺少 scope 返回统一 `403`。
- 响应不说明具体是签名、claim、scope、证书还是密钥失败。

## 8. HTTP API

独立 Router 只挂载：

```text
GET  /internal/admin/v1/health
GET  /internal/admin/v1/users
POST /internal/admin/v1/users/lookup
GET  /internal/admin/v1/users/{userID}
GET  /internal/admin/v1/users/{userID}/devices
GET  /internal/admin/v1/users/{userID}/sessions
POST /internal/admin/v1/devices/{deviceID}/revoke
POST /internal/admin/v1/sessions/{sessionID}/revoke
POST /internal/admin/v1/users/{userID}/disable
POST /internal/admin/v1/users/{userID}/enable
GET  /internal/admin/v1/operations/{operationID}
```

通用要求：

- JSON UTF-8，时间使用 UTC RFC3339。
- 成功与错误响应都设置 `Content-Type: application/json` 和 `Cache-Control: no-store`。
- 只接受契约声明的方法与 Content-Type；JSON decoder 拒绝未知字段和尾随值。
- 请求体设置较小硬上限；lookup 和 command 不允许无界读取。
- UUID、limit、cursor、reason、ticket、note 和 request ID 在进入 repository 前验证。
- 服务端生成或清洗 request ID；不回显危险控制字符。
- 不跟随或生成重定向。
- 稳定错误响应只含机器错误码和安全 request ID；不返回 SQL、加密、TLS 或依赖错误。

内部 health 同时检查 PostgreSQL 与 Redis，但只返回：

```json
{"status":"ok"}
```

## 9. 查询、脱敏与分页

### 9.1 精确身份查询

- 只接受 `type=email|phone` 和 POST body 中的完整 `value`。
- 复用现有 Cloud 身份规范化与每个 lookup key 的 HMAC 索引。
- 查询命中后只在本次请求内解密对应 identity，并立即生成脱敏值。
- 邮箱输出固定为首个允许字符加 `***@domain`，例如 `a***@example.com`。
- 中国大陆手机号输出为前三位加 `****` 加后四位，例如 `138****1234`。
- 原始输入不得进入 URL、cursor、日志、审计、operation、缓存、指标 label 或响应。
- 找不到时返回 `404 USER_NOT_FOUND`，不得泄露另一种 identity 是否存在。

### 9.2 用户聚合

用户响应只包含消费契约允许的字段：

- user ID、脱敏邮箱/手机号；
- Cloud status、`administratively_disabled`、删除完成时间；
- `administrative_revision`；
- 设备总数、活动设备数、活动 session 数；
- 创建时间和可选最后 Cloud 活动时间。

活动 session 定义为 `revoked_at IS NULL`、`replaced_at IS NULL` 且尚未过期。

### 9.3 设备与会话状态

- Device 只返回 ID、用户 ID、展示名、平台、客户端版本、状态和可选最后在线时间，不返回 installation ID、公钥或密钥摘要。
- Session 只返回 session ID、用户 ID、device ID、派生状态、签发/过期/撤销时间，不返回 refresh token hash 或 family ID。
- Session 状态优先级为 replay detected、revoked、rotated、expired、active。

### 9.4 游标

- 用户、设备、会话列表使用稳定 keyset pagination，不使用高 offset。
- limit 默认 50，范围 1 到 100。
- cursor 使用 URL-safe base64，包含版本、排序键、稳定 ID 和 HMAC key ID，并由用途隔离的 HMAC 签名。
- cursor 不含完整身份、设备密钥、session family 或任意秘密。
- 无效、过期格式或 scope 不匹配的 cursor 返回稳定 `400 INVALID_CURSOR`。

## 10. 数据模型

新增迁移 `000015_internal_admin_api.sql`。

### 10.1 用户 revision

```text
users.administrative_revision BIGINT NOT NULL DEFAULT 1 CHECK (> 0)
```

revision 是 Cloud 后台处置的乐观并发版本。每个成功后台 mutation 只增加一次。读取详情、设备和会话时返回当前用户 revision；所有 mutation 必须携带大于零的 `expected_revision`。

### 10.2 admin_operations

表至少包含：

```text
operation_id UUID PRIMARY KEY
idempotency_key_id TEXT NOT NULL
idempotency_key_hmac BYTEA NOT NULL
request_fingerprint BYTEA NOT NULL
service_subject TEXT NOT NULL
actor_admin_id UUID NOT NULL
approval_id UUID
request_id TEXT NOT NULL
action TEXT NOT NULL
target_type TEXT NOT NULL
target_id UUID NOT NULL
expected_revision BIGINT NOT NULL
result_revision BIGINT
status TEXT NOT NULL
error_code TEXT
reason_code TEXT NOT NULL
ticket_reference TEXT
created_at TIMESTAMPTZ NOT NULL
updated_at TIMESTAMPTZ NOT NULL
completed_at TIMESTAMPTZ
```

约束：

- 唯一约束覆盖 HMAC key ID 和幂等键 HMAC。
- HMAC 与 fingerprint 固定 32 字节。
- action 只允许 `revoke_device`、`revoke_session`、`disable_user`、`enable_user`。
- target type 只允许 `device`、`session`、`user`，且必须与 action 匹配。
- status 只允许 `executing`、`succeeded`、`failed`、`conflict`。
- 成功必须有 result revision；失败或冲突必须有稳定 error code。
- 不保存原始 Idempotency-Key、完整身份、JWT、证书、搜索输入或 note。
- note 只参与 keyed request fingerprint，用于识别语义不同的重放，不能从数据库恢复。

## 11. 命令事务与幂等语义

### 11.1 通用流程

1. Handler 完成 TLS/JWT/scope、路径、header 和 command schema 校验。
2. `operation_id` 必须等于 `Idempotency-Key` UUID。
3. 以所有语义字段生成 canonical request fingerprint，包括 action、target、actor、approval、request、reason、ticket、note 和 expected revision。
4. 使用当前及历史 HMAC key 查找幂等记录。
5. 已存在且 fingerprint 相同：返回同一个 operation，不重复执行。
6. 已存在但 fingerprint 不同：返回 `409 IDEMPOTENCY_KEY_REUSED`。
7. 不存在：开始 PostgreSQL transaction，再次检查幂等记录并插入 `executing` operation。
8. 解析目标 owner；目标存在时获取用户统一生命周期锁、锁定用户行并比较 expected revision 与领域前置条件。目标不存在时把同一 operation 转为稳定 failed 终态。
9. 在同一 transaction 中写业务变更、revision、Cloud audit 和最终 operation 状态。
10. commit 后返回最终 operation。

### 11.2 冲突和失败

- revision 不一致：保存 `conflict/USER_STATE_CONFLICT`，不做业务变更，返回 HTTP `409`。
- 已撤销设备或 session：保存对应 conflict 状态和稳定错误码，返回 `409`。
- 用户状态不允许禁用或恢复：保存 conflict，返回 `409`。
- 目标不存在：保存 `failed/*_NOT_FOUND`，返回 `404`。
- 认证、scope、schema 或幂等 header 无效时不创建 operation。
- 数据库事务无法可靠提交时返回 `503`；Admin 进入 reconciling，并通过相同 operation ID 查询。
- `GET /operations/{id}` 找不到时返回 `404`，Admin 可把尚未被 Cloud 接受的任务重新排队。

如果第一次请求已提交但响应丢失，重试或 operation 查询必须返回已提交的终态，不能重复变更。

## 12. 领域处置语义

### 12.1 撤销设备

- 根据 device 找到 owner user，获取用户统一生命周期锁并比较 revision。
- 将设备置为 revoked。
- 撤销该设备的全部 session 和离线授权。
- 用户 revision 加一。
- 业务变更、operation 和 audit 同一事务提交。

### 12.2 撤销 session

- 根据 session 找到 owner user 和 family ID，获取统一锁并比较 revision。
- 撤销该 session 所属完整 refresh-token family，而不是只撤销单行。
- 用户 revision 加一。
- API 与审计不暴露 family ID。

### 12.3 禁用账号

- 必须提供 `approval_id`。
- 只允许当前 active 且未完成删除的用户。
- 禁用用户和个人空间。
- 撤销用户全部设备、session 和离线授权。
- 设置 `administratively_disabled=true`，revision 加一。

### 12.4 恢复账号

- 必须提供 `approval_id`。
- 只允许 `status=disabled`、`administratively_disabled=true` 且删除尚未完成的用户。
- 恢复用户和个人空间，清除后台禁用标志，revision 加一。
- 不恢复旧设备、session 或离线授权；用户必须重新授权设备并建立新 session。

### 12.5 Redis 一致性

PostgreSQL 是访问状态权威来源。现有 access authenticator 即使命中 active Redis cache 仍会回查 PostgreSQL，因此数据库撤销提交后立即阻止后续受保护访问。

Cloud 可在 commit 后尽力把已知 session cache 标为 revoked；Redis 写失败不能回滚已经提交的 PostgreSQL 事实，也不能把成功描述为未执行。后续访问仍通过数据库失败关闭并修正缓存。

## 13. Cloud 审计和日志

复用现有 `audit_events`，每个已认证且进入领域执行的命令记录：

- 稳定 event type 和 outcome；
- `operator_identity=service subject`；
- 可解析目标 owner 时写入 `subject_user_id`；
- object type 和 object ID；
- reason code、request ID；
- metadata 中的 operation ID、actor admin ID、approval ID、expected/result revision 和安全 ticket reference。

不写入：

- 完整邮箱、手机号或搜索输入；
- JWT、Authorization、证书、私钥或密钥路径；
- refresh token、session family、device public key；
- note、身份密文、lookup HMAC 或幂等键原文。

成功业务变更、audit 和 operation 必须同一事务提交。事务本身无法开始或提交时只能产生不含敏感数据的结构化错误日志，不能伪造已持久化审计。

服务日志只允许记录低敏字段，例如 request ID、action、稳定结果和耗时。默认 HTTP access log 不记录 body、query、Authorization、TLS subject、ticket、target identity 或完整 URL。

## 14. OpenAPI 所有权与漂移控制

- `aera-cloud/api/openapi/internal-admin.yaml` 是 provider 副本。
- `aera-admin/api/openapi/cloud-admin-client.yaml` 是 consumer 副本。
- 两个仓库需要独立 CI，因此各自保留一份规范。
- 本次把两份文件提升到同一版本、相同 schema 和相同字节内容。
- Cloud 单仓测试验证 provider 路由、security schemes、请求/响应 schema 和稳定字段。
- Admin 单仓测试继续验证严格消费白名单与脱敏格式。
- 跨仓库 E2E 在启动前比较规范；不一致立即失败，不启动服务。

任何新增响应字段都必须先更新双方契约。Admin 仍使用 `DisallowUnknownFields`，因此 Cloud 意外返回未批准字段会失败关闭。

## 15. 真实跨仓库 E2E

### 15.1 Stub 移除

- 删除 `aera-admin/e2e/cloud-stub`。
- Admin `Makefile`、格式检查和 E2E 构建不再引用 Stub。
- README 不再把独立 Stub 进程描述为 Cloud 验证证据。

### 15.2 仓库发现

`aera-admin/scripts/run-e2e.sh`：

- 默认从 `git rev-parse --git-common-dir` 找到 Admin 主检出的仓库目录，再解析其相邻 `../aera-cloud`；不能只按当前 worktree 目录做相对路径拼接。
- 允许 `AERA_ADMIN_E2E_CLOUD_REPO` 指向显式绝对路径。
- 启动前验证目录存在、Git worktree 可读且 `go.mod` module 为 `github.com/bignormal/aera-cloud`。
- 不自动 clone、pull、切换分支或修改 Cloud 工作树。

在隔离 worktree 开发时，运行命令将通过 `AERA_ADMIN_E2E_CLOUD_REPO` 显式指向本次 Cloud worktree，避免误用相邻主检出。

### 15.3 隔离服务

- Admin 与 Cloud 分别使用唯一 Compose project name。
- PostgreSQL 与 Redis 都绑定动态 loopback 端口。
- 创建独立临时数据库、Redis namespace、日志、PKI 和 Playwright artifact 目录。
- cleanup trap 只销毁本次已验证 project name、临时目录和子进程。
- 不连接或重置开发、生产或未知环境。

### 15.4 临时 PKI

每次 E2E 生成：

- 一次性 CA；
- 带 `IP:127.0.0.1` SAN 和 serverAuth 的 Cloud 证书；
- 带 clientAuth 的 Admin 客户端证书；
- 一次性 Ed25519 服务 JWT 私钥和 Cloud 公钥；
- 一次性 Cloud Internal Admin HMAC key ring。

文件权限限制在临时目录，测试结束删除。任何私钥、证书或生成的环境文件不得进入 Git。

### 15.5 Cloud fixture

在 `aera-cloud` 增加 `e2e` build tag 限制的 fixture 命令：

- 只在 `AGENTERA_CLOUD_ENVIRONMENT=test` 且数据库 host 为 loopback 时运行。
- 应用真实 migrations。
- 使用真实 identity codec 生成密文和 lookup HMAC。
- 创建一个确定身份但随机密钥材料的用户、设备和 session family。
- 输出只供测试使用的 user/device/session ID、脱敏身份和 fixture 路径。
- 原始精确查询 canary 只进入 Admin Playwright fixture 和敏感泄漏检测列表。
- fixture 命令不进入 release build 或生产镜像。

### 15.6 启动和验收顺序

1. 创建隔离 Admin 与 Cloud 依赖。
2. 生成 PKI 和所有一次性 key。
3. 构建真实 Cloud、Cloud e2e fixture、Admin 和 bootstrap 二进制。
4. 运行 Cloud fixture。
5. 启动 Cloud 公网与 Internal Admin Listener，确认进程和 TLS readiness。
6. 启动 Admin，确认 `/health/ready`。
7. 执行现有 10 项 Playwright E2E。
8. 运行 Cloud e2e 验证器，核对真实数据库 operation、revision、session/device/account 状态与 audit。
9. 扫描 Admin 和 Cloud 日志及持久化管理数据，确认敏感 canary 未泄漏。
10. 保留失败 artifact，销毁隔离服务和临时秘密。

## 16. 测试策略

### 16.1 Cloud 单元测试

- 配置默认关闭、启用必填、无效地址、密钥和 PEM。
- JWT header/claim/算法/时间/audience/issuer/subject/jti/scope 校验。
- scope middleware 与统一 401/403。
- JSON 限制、unknown fields、UUID、reason、note、ticket 和 cursor 校验。
- 邮箱/手机号脱敏和不得回显输入。
- 公网 Router 对所有 Internal Admin 路由返回 404。

### 16.2 Cloud PostgreSQL/Redis 集成测试

- 精确 identity HMAC 查询、用户聚合、游标分页。
- Device 与 session 派生状态。
- 设备撤销连带 session 与离线授权。
- Session family 撤销。
- 禁用与恢复的非恢复语义。
- revision 冲突和两个并发 mutation 只能成功一个。
- 相同幂等请求重放、不同语义复用冲突。
- operation、业务变更、audit 原子提交/回滚。
- operation 终态可查询。
- Redis 不可用时访问控制仍由 PostgreSQL 失败关闭。

### 16.3 TLS HTTP 集成测试

- 无证书握手失败。
- 受信证书加缺失/错误 JWT 返回 401。
- 有效 JWT 缺 scope 返回 403。
- 完整双认证返回契约响应。
- 错误响应和日志不包含底层错误或敏感输入。

### 16.4 Admin 与跨仓库测试

- 保留现有 Admin 单元、集成、race、前端、OpenAPI 和 build 检查。
- Playwright 现有 10 项必须全部通过真实 Cloud。
- 精确搜索输入不进入 URL、响应、浏览器存储、Admin log 或 Cloud log。
- session 撤销 exact replay 返回同一个 operation，并最终 succeeded。
- operator 申请与另一名 super admin 审批保持独立，Cloud 只在批准后执行。
- 未授权固定角色直接请求 Cloud mutation BFF 仍返回 403。
- E2E 后 Cloud 数据库必须存在对应 succeeded operations 和 audit，不能只依据页面文案。

## 17. 错误与故障恢复

- Cloud 不可用：Admin mutation 失败关闭，不显示成功。
- Cloud 已提交但响应丢失：Admin 以相同 operation ID 查询并恢复终态。
- Cloud 未收到请求：operation 查询 404 后 Admin 可重新排队并使用原 ID 投递。
- Cloud 返回 revision conflict：Admin operation 进入 conflict，不自动换 revision 重试。
- Admin 写回失败：Admin Outbox 保留 operation ID，后续对账恢复。
- Cloud audit 写入失败：同事务业务变更和 operation 回滚。
- Redis 写回失败：PostgreSQL 已提交状态仍为权威，后续访问回查数据库并修复缓存；不恢复已撤销凭据。
- Internal Admin 配置错误：Cloud 启动失败，不回退到公网 Router、无 mTLS 或仅 JWT 模式。

## 18. 部署与回滚边界

实施后先完成本地与 CI 验证，再分别提交两个仓库。推送成功不等同于部署。

生产发布顺序建议：

1. 应用向后兼容 migration。
2. 配置内部证书、服务 JWT 公钥和 HMAC key ring，但保持内部 listener 关闭。
3. 部署 Cloud，确认公网回归测试。
4. 建立私有网络策略并启用 Internal Admin Listener。
5. 部署配置真实 Cloud endpoint 的 Admin。
6. 运行内部 staging smoke 后开放员工入口。

回滚时可先关闭 Admin Cloud mutation，再关闭 Internal Admin Listener。新增表和 revision 列保留，不执行破坏性 down migration；这不会改变现有公网 API 数据语义。

## 19. 仓库改动归属

### `aera-cloud`

- Internal Admin 配置、TLS listener、JWT/scope middleware。
- Internal Admin OpenAPI、handler、service、repository、mask/cursor。
- migration、operation、revision、设备撤销和结构化 Cloud audit。
- Cloud unit/integration/TLS tests。
- e2e-tagged fixture 与验证工具。
- README、`.env.example` 和部署说明。

### `aera-admin`

- 同步 consumer OpenAPI 描述。
- 删除 Cloud Stub。
- 修改 E2E runner 使用真实 Cloud worktree 和隔离 Compose。
- 读取真实 Cloud fixture，而不是硬编码 Stub 状态。
- 保留并扩充 canary、Playwright 和 Cloud 数据库验收。
- README 更新真实能力与未部署边界。

## 20. 完成标准

只有同时满足下列条件，才可描述为“真实 Cloud 后台闭环已完成”：

1. 公网 Router 无法访问任意 Internal Admin 路由。
2. mTLS 与服务 JWT 任缺其一都无法调用内部 API。
3. 当前 consumer contract 全部由真实 Cloud 实现。
4. 精确完整身份可以命中，但所有输出、日志、审计和 operation 均保持脱敏或无身份值。
5. 单设备、session family、禁用和恢复具有正确事务语义。
6. 幂等重放不重复执行，语义冲突和 revision 冲突稳定可见。
7. 成功业务变更、Cloud audit 和 operation 原子提交。
8. Admin Stub 已删除，Playwright 10/10 使用真实 Cloud 通过。
9. E2E 数据库验收证明真实 operation、revision、处置和审计存在。
10. 两仓库单元、集成、race、OpenAPI 和 release build 通过。
11. 两仓库工作树干净、提交清晰；推送状态与部署状态分别报告。

审计查询页面、系统设置和 Official Managed Agent 仍需后续独立设计与实施，不因本设计完成而被视为已完成。
