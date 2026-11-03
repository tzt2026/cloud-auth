# GLN-013 前置 · Cloud Auth 服务凭证现状盘点与签发草案

- 状态：**只读盘点 + 草案，不包含产品代码改动，也未经 Guanlan 侧确认**
- 仓库基线：`uichat-mira/cloud-auth` `origin/dev` `481767ffe6faa9186693dad90ce4994980474517`
- Guanlan 对照基线：`uichat-mira/cloud-mcp-guanlan` `origin/dev` `fbaecaa16b535a19576c9db651a55739b777e2a9`
- 规范依据：组织 `AGENTS.md`（Policy `2026-09-16.2`）、`cloud-auth/AGENTS.md`、Issue #129（GLN-013 契约）、Issue #128（GLN-012 契约）、PR #130（GLN-012 open，未入 dev）
- 阅读方式：本文所有断言都带代码位置；标 **【事实】** 表示已在上述基线代码中核实；标 **【拟变更】** 表示 GLN-013 的实现方案（实现结果见 [gln-013-guanlan-credential.md](gln-013-guanlan-credential.md)）；标 **【待确认】** 表示已核实、但取值或语义须由 Guanlan 侧/维护者裁决；标 **【未验证】** 表示缺真实环境、本机无法核实，不得当作已成立。

> 本文是 GLN-013 的**前置盘点**，部分结论随后被实现取代（audience/scope/consumer_id/闸门已按维护者裁决实现）。实现与证据以 [gln-013-guanlan-credential.md](gln-013-guanlan-credential.md) 为准；本文保留原始缺口判断以便追溯。

> 本文不宣称任何 Guanlan 联调已完成。仓库内没有真实签发给 Guanlan 的令牌，也没有 Guanlan 部署环境；真实链路验收属于 GLN-014。

## 1. 结论摘要

1. **【事实】** Cloud Auth 已有一套完整的"服务凭证"签发机制：Ed25519 JWT、显式 audience、最小 scope、设备绑定、单一签发事务、公开 JWKS、离线验证。它当前只支持 `mira:cloud-shiyan` 与 `mira:cloud-relay-transport` 两个 audience，两者在 schema 与验证器层面互不通用。
2. **【事实】** 仓库里没有独立的 "Relay ticket" 或 "Shiyan 凭证" 实现——它们是同一个 service credential 的两个 audience 变体；Relay 变体额外带 `relay.room/role` 传输上下文与准入判断。
3. **【事实】** 现有 schema 是**封闭枚举**：audience 是 `z.enum` 两值、scope 是 `z.tuple` 单值、claims 是 `.strict()`。把 Guanlan 塞进现有 audience 是**契约变更**，不是加个字符串。
4. **【事实】** Cloud Auth 没有可复用的 consumer **归属模型**：`apps/api/src` 与 `packages/contracts/src` 中没有 `consumer` 表、字段或签发分支；`consumer` 一词只出现在产品注释（`apps/web/src/lib/auth/store.ts:30`）、测试注释（`apps/api/tests/unit/service-credential-keyring.test.ts:128`）与文档中。既有 `docs/service-credentials-v0.md` 的「Consumer checklist」小节（`docs/service-credentials-v0.md:279` 起）已经写明"消费者应共享 canonical literals 并显式配置 iss/aud/JWKS"——那里的 consumer 指**验证方服务**，不是 Guanlan 的 `consumer_id` 主体。因此这条缺口是"沿用既有验证方口径 + 新增一个消费者主体 claim"，不是重新设计验证模型。Guanlan 验证器强制要求 `consumer_id` claim（默认名），缺失即 401。
5. **【事实】** dev 上**不存在**服务间可信调用凭据（无 HMAC、无内部 token、无 introspection）。唯一的签发可信上下文是"已验证、且绑定未撤销设备的 Cloud Session"，它在 `BEGIN IMMEDIATE` 事务内复核。
6. **【事实】** 撤销只阻止**未来签发**。已签发 token 无 `jti`、无吊销表、无在线内省，只能等 `exp`（上限 600s）。Guanlan 侧另有 5s 时钟容差，实际最长多 5s。
7. **【事实】** Guanlan 不依赖 `@uichat-mira/cloud-auth-contracts`：它自带常量并直接用 `jose` 校验。两端靠"值对齐"，没有任何编译期共享，天然会漂移。
8. **【拟变更】** GLN-013 是"扩一个 audience + 一个 claim + 一组 scope"，不是新凭证体系。真正的新东西是 **consumer 归属语义** 与 **观澜空间可用性闸门**，这两项都跨仓库，必须裁决。
9. **【未验证】** 以下事项缺真实环境，本机/本仓无法核实，不能当作已成立：Guanlan 真实 `/mcp` 端点是否存在；Guanlan 能否取回本仓 JWKS 并按 300s 缓存/轮换；真实 D1 中 `guanlan_accounts`/`guanlan_consumers` 是否已有行；本仓签出的令牌是否被真实 Guanlan 接受。非生产环境准备见 [gln-013-nonprod-environment.md](gln-013-nonprod-environment.md)。

## 2. 现有凭证类型盘点

### 2.1 一览

| 凭证 | 是否 JWT | 签发入口 | audience | scope | 有效期 | 撤销语义 |
| --- | --- | --- | --- | --- | --- | --- |
| Cloud Session | 否，`mcs_v1.<id>.<secret>` 不透明 bearer | `POST /v1/auth/login`；`POST /v1/oauth/token` 兑换后签发 | 无（Cloud Auth 内部） | 无 | 默认 2 592 000s（30 天） | 行级 `revoked_at`，**每次校验即时生效** |
| OAuth authorization code | 否，不透明 + PKCE S256 | `POST /oauth/authorize`（密码 + CSRF 表单） | 无 | 无 | 默认 300s，上限 600s | 单次消费；改密时批量作废 |
| Service Credential（Shiyan 变体） | 是，EdDSA | `POST /v1/service-credentials` | `mira:cloud-shiyan` | `shiyan:authenticate` | 默认 300s，上限 600s | 仅阻止未来签发 |
| Service Credential（Relay 传输变体，即 "Relay ticket"） | 是，EdDSA + `relay` 上下文 | 同上（额外准入） | `mira:cloud-relay-transport` | `relay:transport` | 同上 | 同上 |
| Host grant snapshot | 否，服务端只读投影 | `GET` host-grant 路由（Cloud Session 鉴权） | 无 | 无（scopes 是业务数据） | 服务端计算的有效窗口，默认 300s | 每次读取重算 |
| Desktop Host 房间/在线租约 | 否，服务端记录 | `POST` host 路由（Cloud Session 鉴权） | 无 | 无 | 租约默认 120s | 租约到期/登出/设备撤销即失效 |

后两项**不是凭证**（没有令牌载体、不能离线验证、不能转交给别的服务）。盘点时若把它们算成"已有 Guanlan 可复用凭证"会误判。

### 2.2 Cloud Session

**【事实】**

- 载体：`mcs_v1.` + 22 字符 id + 43 字符 secret，仅存 `sha256("mira-cloud-session\0" + secret)`（`apps/api/src/security/session-token.ts:3-34`）。
- 签发：`apps/api/src/auth/auth-service.ts:51-116`（登录）、`apps/api/src/oauth/oauth-service.ts:77-111`（OAuth 兑换，产物**就是** Cloud Session，不是另一种 token）。
- 有效期：`MIRA_AUTH_SESSION_TTL_SECONDS` 默认 2 592 000、下限 3 600、上限 7 776 000（`apps/api/src/config.ts:41`）。
- 校验：`apps/api/src/auth/auth-service.ts:300-318`——会话存在、secret 哈希匹配、未撤销、未过期、账号 allowed 且未禁用、（若绑定）设备属于同账号且未撤销。
- 续期：`apps/api/src/auth/auth-service.ts:161-182` 轮换 secret 并延长 `expires_at`；旧 secret 因哈希被替换而立即失效（`apps/api/src/auth/auth-repository.ts:457-484`）。
- 撤销：登出 `auth-service.ts:184-187` → `auth-repository.ts:486-495`；设备撤销连带撤销该设备所有会话（`apps/api/src/devices/device-repository.ts:129-164`）；禁用账号 `auth-repository.ts:303-315`；拒绝账号 `auth-repository.ts:289-301`；改密/重置 `auth-repository.ts:142-162`。

**【事实】** Cloud Session 是"账号身份"，不是"服务凭证"。把它交给 Guanlan 是明确禁止的方向：服务凭证响应体必须不含任何会话材料，且已有测试断言（`apps/api/tests/contract/service-credential-issuance-contract.test.ts:42`）。

### 2.3 Service Credential（GLN-013 的真正落点）

**【事实】**

- 契约字面量：issuer `mira:cloud-auth`、audience `mira:cloud-shiyan` / `mira:cloud-relay-transport`、scope `shiyan:authenticate` / `relay:transport`（`packages/contracts/src/service-credential.ts:8-24`）。
- audience/scope 封闭：`serviceCredentialAudienceSchema` 是两值 `z.enum`（同文件 `:13-16`），`serviceCredentialScopeSchema` 是两值 `z.enum`（`:21-24`），claims 用 `z.tuple([z.literal(...)])` 固定单 scope，并对两个 audience 做 `discriminatedUnion`（`:92-114`）。
- claims 形状：`iss/sub/device_id/iat/nbf/exp` + audience 专属字段，全部 `.strict()`（`:60-114`）；`sub` 是账号 id，`device_id` 单独断言设备（`:68-69`）。**没有 `consumer_id`，也没有 `jti`。**
- 签发请求：客户端只能选 audience（Relay 另带 room/role），身份/issuer/kid/scope 全部服务端派生（`packages/contracts/src/service-credential.ts:116-133`；`apps/api/src/service-credentials/service.ts:24-28`）。
- HTTP 入口：`POST /v1/service-credentials`（`apps/api/src/service-credentials/routes.ts:41-66`），`GET /.well-known/jwks.json`（`routes.ts:68-75`）。
- 签名：Ed25519/`EdDSA`，`kid` 有界；TTL 默认 300、上限 600（`apps/api/src/service-credentials/signer.ts:16-17`、`:57-66`、`:93-116`）。
- 验证：显式注入 issuer/audience/公钥集，拒绝未知 `kid`、`iss` 不匹配、`aud` 不匹配、未来 `iat`、未到 `nbf`、已 `exp`、超 TTL（`apps/api/src/service-credentials/verifier.ts:143-217`）。
- JWKS：只含公钥，active 在前、retiring 在后，`cache-control: public, max-age=300`（`routes.ts:8`；`apps/api/src/service-credentials/keyring.ts:80-142`）。
- 签名材料缺失/非法时 fail-closed：签发与 JWKS 返回 503，但登录/`/health`/`/ready` 不受影响（`apps/api/src/config.ts:89-159`、`service.ts:38-45`、`:125-134`）。

### 2.4 Relay ticket 的准入不是通用能力

**【事实】** Relay 变体在签发事务内额外做准入：`ServiceCredentialService.issue` 在 `issueWithinActiveDeviceSession` 的回调里解析房间归属并判权（`apps/api/src/service-credentials/service.ts:59-92`），规则在 `apps/api/src/service-credentials/relay-admission.ts:21-41`（同账号、房间可用、host 必须是拥有该房间的 Desktop 设备、client 必须是 Mobile），房间归属来自 `HostService.resolveRoomOwnership`（`apps/api/src/hosts/host-service.ts:90`，`apps/api/src/server.ts:48-52` 注入）。

**【拟变更】** 这套准入**不可复用**给 Guanlan：它回答的是"这台设备能不能连这个房间"，与"这个账号能不能读/写自己的观澜消费者数据"无关。GLN-013 不应引入房间概念。

### 2.5 签发所需的可信上下文

**【事实】** 唯一路径：

1. `parseSessionToken`（`apps/api/src/security/session-token.ts:23-30`）→ 2. `AuthRepository.issueWithinActiveDeviceSession`（`apps/api/src/auth/auth-repository.ts:226-287`）在 `BEGIN IMMEDIATE` 内重查 `sessions ⋈ accounts ⟕ devices`，校验过期、secret 哈希、`revoked_at`、`is_allowed`、`disabled_at`（`:249-260`）→ 3. 无设备绑定返回 `device_required`（`:262-265`）→ 4. 设备必须属同账号、平台非空、未撤销（`:267-274`）→ 5. 回调里签发，再 `COMMIT`（`:276-282`）。

**【事实】** 该事务的意义是：登出、续期、设备撤销、账号禁用等写操作不能插在"最终鉴权"与"签名"之间。已有集成测试覆盖（`apps/api/tests/integration/service-credential-issuance.test.ts:336-386`、`:294-334`）。

**【事实】** dev 上**没有**第二种可信上下文：无服务间 HMAC 校验、无内部 token、无 introspection 端点（全仓库检索 `HMAC`/`introspect`/`jti` 无产品代码命中）。GLN-012 的 HMAC **发送端**属于 PR #130（未入 dev），且方向是 Cloud Auth → Guanlan 的注册投递，不能当"内部调用者凭证"。

**【拟变更】** GLN-013 继续只接受"已验证、设备绑定的 Cloud Session"。若 Desktop/Mobile 需要无感取票，它们已持有设备绑定会话，无需新机制；**不得**新增一条"内部调用即可签发"的旁路。

### 2.6 撤销/禁用后的实际失效时效

**【事实】**

| 事件 | 对"未来签发"的影响 | 对"已签发 token"的影响 | 代码位置 |
| --- | --- | --- | --- |
| 登出 | 立即拒绝（同一事务内查 `revoked_at`） | 无，等 `exp` | `auth-repository.ts:249-260` |
| 续期 | 旧 secret 立即失效 | 无 | `auth-repository.ts:457-484` |
| 设备撤销 | 立即拒绝；连带撤销该设备会话 | 无 | `device-repository.ts:129-164` |
| 账号禁用/拒绝 | 立即拒绝 | 无 | `auth-repository.ts:303-315`、`:289-301` |
| 改密/重置密码 | 立即拒绝 | 无 | `auth-repository.ts:142-162` |
| 密钥轮换 | 只影响新 token 的 `kid` | 旧 `kid` 在 JWKS 保留期内仍可验签 | `docs/service-credentials-v0.md:258-267` |

- **【事实】** 上限：token `exp` ≤ 600s；消费者 JWKS 缓存 300s；Guanlan 侧 `jose` 时钟容差 5s（`cloud-mcp-guanlan` `src/mcp/auth.ts:73`）。因此"撤销后仍可被 Guanlan 接受"的最坏窗口 ≈ 600s + 5s（不含部署与缓存传播）。
- **【事实】** 仓库自述同样结论并把它当已知 V0 限制（`docs/service-credentials-v0.md:252-256`）。
- **【事实】** 没有 `jti`、没有吊销列表、没有在线内省；`docs/service-credentials-v0.md:276` 明确把 introspection 列为未实现。

## 3. Guanlan 侧当前验证器合同（只读对照，权威盘点属 GLN 侧任务）

**【事实】** `cloud-mcp-guanlan` `origin/dev` `fbaecaa`：

- issuer 常量 `mira:cloud-auth`（`src/mcp/config.ts:23`）；audience 常量 `mira:cloud-guanlan`（`src/mcp/config.ts:24`），且配置层**拒绝**非 Guanlan audience（`src/mcp/config.ts` 中 `mcp_audience_not_guanlan` 分支）。
- 必需 scope `guanlan.read`（`src/mcp/config.ts:10`），写权限 scope `guanlan.write`（`src/mcp/config.ts:18`），写 scope 由工具自行检查，不在全局 bearer 网关。
- 校验参数：`jwtVerify(..., { issuer, audience, algorithms: ["EdDSA"], clockTolerance: 5, requiredClaims: ["iss","aud","exp","sub"] })`（`src/mcp/auth.ts:66-76`）。
- consumer claim 名可配置，默认 `consumer_id`（`src/mcp/config.ts:105`），缺失或非字符串即 401（`src/mcp/auth.ts:82-86`）。
- scope 解析：数组（必须全为非空字符串，否则拒绝整个 token）或空格分隔字符串（`src/mcp/auth.ts:45-54`）。
- 数据侧：`guanlan_accounts.account_id` 为主键（1–128、trim 相等）；`guanlan_consumers(account_id, consumer_id)` 复合主键，`consumer_id` 1–128、trim 相等（`migrations/0003_guanlan_accounts.sql`）。查不到账号/消费者时工具返回 `guanlan_principal_unavailable`，不泄漏他人存在性（`src/mcp/capabilities.ts` 错误常量）。
- **【事实】** Guanlan 不依赖 `@uichat-mira/cloud-auth-contracts`（`package.json` 只有 `jose`/`zod`/MCP SDK），也不复用 Cloud Auth 的 `verifyServiceCredential`。两端仅"值对齐"。

由此产生一个必须记住的差异：**Guanlan 要求 `consumer_id`，Cloud Auth 现有关闭式 claims 只有 `device_id`。** 这不是命名偏好，而是签发契约缺失。

## 4. 差距（Gap）清单

| # | 差距 | 证据 | 处置建议 |
| --- | --- | --- | --- |
| G1 | 无 `mira:cloud-guanlan` audience | `packages/contracts/src/service-credential.ts:10-16` | 【拟变更】新增 audience 字面量与 claims 变体 |
| G2 | 无 `guanlan.read` / `guanlan.write` scope | `service-credential.ts:18-24` | 【拟变更】新增两个 scope，读/写可分 |
| G3 | 无 `consumer_id` claim，且 schema `.strict()` 会拒绝额外 claim | `service-credential.ts:60-114` | 【拟变更】新增 claim；**语义【待确认】** |
| G4 | 现有 scope 用 `z.tuple` 固定单值，无法表达 read 或 read+write | `service-credential.ts:96`、`:105` | 【拟变更】Guanlan 变体改用受约束数组 + 顺序/去重校验 |
| G5 | 无"观澜空间是否存在/已注册"判定 | dev 无 outbox 表（`apps/api/migrations/` 仅 001–007）；`guanlan-registration.ts` 只在 PR #130 | 【待确认】以 GLN-012 投影为闸门（见 §6.3） |
| G6 | 撤销仅阻止未来签发 | `docs/service-credentials-v0.md:252-256` | 【待确认】接受 ≤600s 窗口，或另立在线撤销任务（不在本卡） |
| G7 | 无 consumer 归属数据 | 全仓库无 `consumer` 产品代码 | 【待确认】minimal 方案不新建归属表（见 §6.2） |
| G8 | 无内部可信调用凭证 | dev 无 HMAC/introspection | 【拟变更】不新增；原则上沿用设备绑定会话 |
| G9 | 两端常量靠复制，无共享包 | Guanlan `package.json` 无 contracts 依赖 | 【拟变更】把"字段对齐清单"（§5）作为跨仓库验收项，GLN-014 复核 |

## 5. 与 Guanlan 验证器待对齐字段清单（交 guanlan-dev / 维护者）

> 判据：**值必须一致**，不是"名字差不多"。任何一项不一致都会导致 401 `invalid_token`，且两端测试都不会互相发现。

| 字段 | Guanlan 现状要求 | Cloud Auth 现状 | GLN-013 拟值 | 状态 |
| --- | --- | --- | --- | --- |
| `iss` | `mira:cloud-auth`（`config.ts:23`） | 同值（`service-credential.ts:8`） | 不变 | **已一致** |
| `aud` | `mira:cloud-guanlan`（`config.ts:24`），配置层拒绝其他值 | 不支持 | 新增 `mira:cloud-guanlan` | **【待确认】**确认字面量后实现 |
| `alg` / `kid` | `EdDSA` + JWKS 内 `kid`（`auth.ts:72`） | 同（`signer.ts:75-82`） | 不变 | **已一致** |
| `exp` / `nbf` / `iat` | NumericDate；`clockTolerance` 5s（`auth.ts:73`） | `iat=nbf=now`、`exp=iat+TTL`，TTL ≤600s（`signer.ts:16-17`、`:93-103`） | 不变 | **兼容**；TTL 上限需确认 |
| `sub` | 非空字符串，用作 `guanlan_accounts.account_id`（`auth.ts:81`；`0003`） | Cloud Auth 账号 id（`signer.ts:96`） | 不变 | **已一致** |
| `consumer_id` | 必需，默认 claim 名 `consumer_id`（`config.ts:105`、`auth.ts:82`），须在 `guanlan_consumers` 存在 | **缺失** | 新增 | **【待确认】语义与供给方** |
| `scope` | 数组（全非空字符串）或空格分隔；读工具要求 `guanlan.read`，写工具要求 `guanlan.write`（`auth.ts:45-54`、`config.ts:10/18`） | 单值 tuple，两值枚举 | 新增 `guanlan.read`、`guanlan.write` | **【待确认】读写是否同 token** |
| `device_id` | Guanlan 不读、不要求 | 现有 schema 强制要求（`service-credential.ts:69`） | 保留（设备绑定证据） | **需 Guanlan 明确"可忽略额外 claim"** |
| 未知 claim | `jose` 默认不拒绝 | `.strict()` 会拒绝（签发侧自校验） | 新增 claim 必须同步 Cloud Auth schema | 实现注意项 |
| JWKS | `CLOUD_AUTH_JWKS_URL`（HTTPS），远程拉取 | `GET /.well-known/jwks.json`，`max-age=300`（`routes.ts:8`） | 不变 | **已一致**（部署需给真实 URL） |
| 撤销/内省 | 无（纯离线） | 无 `jti`、无吊销表 | 不变 | **对齐（同为已知限制）** |
| 错误语义 | 一律 401 `invalid_token`，不区分原因 | 无（签发侧） | 无关 | 记录：Guanlan 不会告诉调用方具体哪项不符 |

## 6. GLN-013 最小实施草案（**拟变更**，未实现）

### 6.1 模块改动面

| 文件 | 改动 | 风险 |
| --- | --- | --- |
| `packages/contracts/src/service-credential.ts` | 新增 `CLOUD_GUANLAN_AUDIENCE = "mira:cloud-guanlan"`、`GUANLAN_READ_SCOPE = "guanlan.read"`、`GUANLAN_WRITE_SCOPE = "guanlan.write"`；新增 `guanlanServiceCredentialClaimsSchema`（含 `consumer_id`，scope 用受约束数组）；并入 `serviceCredentialAudienceSchema` / `serviceCredentialScopeSchema` / `serviceCredentialClaimsSchema` / `serviceCredentialRequestSchema` | 契约面扩大；现有两 audience 的 strict 语义**必须保持不变** |
| `apps/api/src/service-credentials/service.ts` | Guanlan 分支：scope 派生（读/写）、注册状态闸门、`consumer_id` 注入 | 不得改动 Shiyan/Relay 分支行为 |
| `apps/api/src/service-credentials/signer.ts` | 无需改协议；`scope` 入参类型放宽为 `readonly ServiceCredentialScope[]`（已是数组） | 低 |
| `apps/api/src/service-credentials/routes.ts` | 预计无需改；如需新错误码再加映射 | 中（响应契约） |
| `apps/api/src/auth/auth-repository.ts` 或新增 repository | 读 GLN-012 outbox 注册状态（**仅在 PR #130 合并后存在**） | 中；跨卡依赖 |
| `docs/service-credentials-v0.md` | 增补 Guanlan audience/scope 与撤销窗口说明 | 低 |
| `apps/api/migrations/` | 若 consumer 归属需落库才新增；minimal 方案**不新增表** | 见 §6.2 |

**不改**：session、device、OAuth、host、host-grant 的现有语义；不改 signing key 配置；不引入 introspection。

### 6.2 consumer 语义（三个候选，必须裁决）

| 方案 | consumer_id 取值 | 数据归属 | 代价 | 风险 |
| --- | --- | --- | --- | --- |
| A（最小） | `= 当前账号 id` | 不新增；Guanlan 侧 `guanlan_consumers` 需存在 `(account_id, account_id)` 行 | 需 Guanlan 供应端按此约定建 consumer 行 | 语义上"消费者=账号"，与"稳定 consumer 区分多客户端"的产品意图可能不符 |
| B | `= 当前设备 id` | 不新增 | 无需 Guanlan 额外供应 | 多设备用户被拆成多个 consumer，决策记忆/订阅不共享；与 Issue #129 "稳定 consumer" 表述冲突 |
| C（最重） | Cloud Auth 新增 consumer 归属表并签发 | Cloud Auth 新增持久化 | 新表、新迁移、新管理面 | 与 AGENTS.md "Cloud Auth 不吸收观澜业务语义"存在张力；需维护者明确数据归属 |

本文**不替维护者选**。建议交 lead，与 Guanlan 供应侧（GLN-012 接收端 / 后续 provisioning）一并对齐后再实现。

### 6.3 空间可用性闸门（Issue #129 硬性要求）

**【事实】** Issue #129 Dependencies 明确："GLN-012 的账户注册状态需参与实际可用性判断；可先独立完成签发合同，但不能无空间时放行。"

**【拟变更】** 两个可选实现，都需要跨卡确认：

1. **前置闸门（推荐）**：签发前读 Cloud Auth 自己的 `guanlan_registration_outbox`（GLN-012，PR #130）状态；`delivered` 才签发。数据仍归 Cloud Auth（这是 Cloud Auth 的投递投影，不是观澜业务数据）。**硬依赖 PR #130 合并**。
2. **后置判定**：Cloud Auth 照常签发，Guanlan 侧对未注册空间返回 `guanlan_principal_unavailable`（`capabilities.ts` 已有）。实现简单，但不满足 Issue #129 "不放行"的字面要求，且把失败暴露给最终用户。

若选 1，则需要一个新的响应错误码（候选 `SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`，**【待确认】**），并同步 `serviceCredentialErrorCodeSchema`（`service-credential.ts:161-168`）与错误信封。

### 6.4 测试层次（沿用仓库既有分层与命令）

- **T1 `pnpm run test:unit`**
  - 契约：新字面量固定；Guanlan claims 必须含 `consumer_id`；`scope` 只接受 `guanlan.read` 或 `guanlan.read + guanlan.write`（顺序/去重）；缺 `consumer_id`、跨 audience scope、额外 claim 均被拒。参照现有 `apps/api/tests/unit/service-credential-contracts.test.ts:36`。
  - 签名：Guanlan claims 生成的 token header/claims 形状。参照 `apps/api/tests/unit/service-credential-signing.test.ts:42-135`。
  - 闸门判定：未注册/禁用/拒绝 → 拒绝签发（纯函数级）。
- **T2 `pnpm run test:contract`**
  - HTTP：`POST /v1/service-credentials` Guanlan 请求成功；响应 schema；错误信封；响应体不含会话材料。参照 `apps/api/tests/contract/service-credential-issuance-contract.test.ts:12-95`。
  - 反例：Guanlan token 在 Shiyan/Relay 配置下必须 `AUDIENCE_MISMATCH`；Shiyan/Relay token 在 Guanlan 配置下必须拒绝（三个 audience 两两不可互换）。参照 `apps/api/tests/contract/service-credential.test.ts:178-216`。
  - 读 token 不得被当作写：仅 `guanlan.read` 的 token 不携带 `guanlan.write`。
- **T3 `pnpm run test:integration`**
  - 真实 SQLite：设备绑定会话签发 Guanlan token；登出/续期/设备撤销/账号禁用/拒绝/会话过期全部拒绝签发；跨账号 consumer 不可获得（若 consumer 由服务端派生，用两账号正反例证明）。参照 `apps/api/tests/integration/service-credential-issuance.test.ts:110-410`。
  - 闸门：GLN-012 outbox 未 `delivered` 时 fail-closed；`delivered` 后可签发。
  - 兼容：Shiyan/Relay 既有用例全绿（回归）。
- **门禁**：`pnpm run check`（`typecheck` + `test`，`package.json:21`）。
- **不算验收的**：本地用 `jose` 复刻 Guanlan 校验参数只能证明"字段对齐假设"，不是 Guanlan 真机；真实联调属 GLN-014。

### 6.5 拟新增常量命名（**全部待 Guanlan 验证器确认**）

```ts
// packages/contracts/src/service-credential.ts（拟）
export const CLOUD_GUANLAN_AUDIENCE = "mira:cloud-guanlan" as const;
export const GUANLAN_READ_SCOPE = "guanlan.read" as const;
export const GUANLAN_WRITE_SCOPE = "guanlan.write" as const;
// claims 变体
export const guanlanServiceCredentialClaimsSchema = /* aud 字面量 + consumer_id + scope 数组 */;
```

命名依据是**值**而非拼写：Guanlan 侧已存在同名常量（`config.ts:10/18/24`）。改名不影响互操作，改**值**才影响，因此任何值变更都必须双边同批。

## 7. 未决事项（交 lead / 维护者裁决）

1. **consumer_id 语义与供给方**（§6.2 A/B/C）——阻塞实现，不阻塞文档。
2. **读写权限模型**：`guanlan.write` 是否允许客户端显式请求？现有机制从不信任客户端业务权限（`docs/service-credentials-v0.md:25`），但 Relay 的 role 也是客户端请求 + 服务端校验。建议：显式请求 + 服务端限定该 scope 只作用于"当前账号自己的消费者账本"，并请 Guanlan 确认写工具不存在跨账号写入面。
3. **空间闸门实现**（§6.3 前置 vs 后置）与是否新增错误码。
4. **TTL 是否维持 ≤600s**：600s 是当前审阅过的 V0 上限（`signer.ts:17`、`verifier.ts:81`），放宽是独立决策。
5. **撤销窗口接受度**：≤600s（+5s 容差）内旧 token 仍有效，是否可接受。
6. **GLN-012 合并顺序**：若选前置闸门，PR #130 未合并则 GLN-013 无法实现闸门（可先写契约与测试骨架，但不能宣称可用）。
7. **跨仓库字段对齐责任人**：§5 清单需 guanlan-dev 逐项确认，特别是 `device_id` 额外 claim 与 `consumer_id` 缺失即 401 的行为。

## 8. 明确的 Non-goals

- 不新增通用 OAuth/MCP 客户端注册或授权 UI。
- 不改 Guanlan 账本、订阅、Cron、D1 schema。
- 不把 Relay ticket 或 Shiyan 凭证"扩大"为 Guanlan audience。
- 不做在线内省/吊销列表（如需要，另立任务）。
- 不部署、不配置生产密钥、不签发真实 token。

## 9. 证据与复现

- 盘点基线 commit：`481767f`（cloud-auth `origin/dev`）、`fbaecaa`（cloud-mcp-guanlan `origin/dev`）。
- 复现读取方式：`git show origin/dev:<path>`（只读，不改工作树）。
- 本文未执行任何测试：本卡只读 + 文档，未改产品代码，因此没有可跑的"新证据"；引用的测试文件是现状覆盖证据，不是本卡的通过证据。
- 真实链路验证：**未进行**。缺 Guanlan 部署环境、JWKS URL、以及维护者的签发/联调凭证。
