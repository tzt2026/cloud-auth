# GLN-013 · Cloud Auth 为 Guanlan 签发内部消费者凭证

> 任务契约：Issue [#129](https://github.com/uichat-mira/cloud-auth/issues/129)（GLN-013）。
> 分支：`feat/gln-013-guanlan-consumer-credential`，基线 `origin/dev` = `481767f`。
> 前置输入：GLN-014 契约盘点（`uichat-mira/cloud-mcp-guanlan` PR #27，commit `5ff6bf5`）与 GLN-013 现状盘点
> （[gln-013-auth-readiness.md](gln-013-auth-readiness.md)）。
> 本文只描述本仓实现的签发合同与证据。**不宣称端到端可用**：Guanlan `/mcp` 真实端点、真实 JWKS 取回、
> GLN-012 注册投影均未就绪（见第 9、10 节）。

## 1. 结论摘要

1. 在既有 Service Credential 机制内新增第三个 audience `mira:cloud-guanlan`，没有新建身份系统，没有
   复用 Relay/Shiyan 凭证，没有扩大任何既有 audience 的权限。
2. 令牌 claims 与 Guanlan 验证器逐项对齐：`iss`=`mira:cloud-auth`、`aud`=`mira:cloud-guanlan`、
   `sub`=Cloud Account id、`consumer_id`=同一 Cloud Account id、`scope`=`guanlan.read`（必需）+
   `guanlan.write`（显式请求）、`iat`/`nbf`/`exp`、EdDSA + `kid`。
3. 签发的**前置闸门**是 GLN-012 的注册投影：只有 `delivered` 才签发，其余状态与表缺失一律 fail-closed。
   GLN-012 已合并进 `dev`（`931ae6c`，PR #130），因此闸门在部署后即有真实落点：建号即 `pending`，
   需真实投递把账号置 `delivered`；未投递的账号一律 409。
4. 既有 Session/Relay/Shiyan 行为未改变；全量 `pnpm run check` 真实通过（见第 8 节）。

## 2. 事实基线

| 项目 | 值 |
| --- | --- |
| 基线 commit | `origin/dev` `481767f` |
| 组织政策 | `uichat-mira/.github` `main` `AGENTS.md`（Policy `2026-09-16.2`） |
| 仓库规则 | `cloud-auth` `AGENTS.md`（`dev`） |
| Guanlan 验证器事实 | GLN-014 PR #27（`5ff6bf5`）第 2 节，逐项带 `path:line` |
| 本仓现状盘点 | `docs/engineering/gln-013-auth-readiness.md` |

Guanlan 验证器（`cloud-mcp-guanlan` `src/mcp/auth.ts:62-95`、`src/mcp/config.ts:23-24,105`）
使用 `jose.jwtVerify`，`algorithms: ["EdDSA"]`、`issuer: "mira:cloud-auth"`、
`audience: "mira:cloud-guanlan"`、`requiredClaims: ["iss","aud","exp","sub"]`、
`consumerClaim` 默认 `consumer_id`；`guanlan.read` 是全局读闸门，`guanlan.write` 由写工具独立检查。
这些值由 Cloud Auth 侧以同值常量对齐（Guanlan 不依赖本仓 contracts 包，属**按值对齐**，存在漂移风险，
见第 10 节）。

## 3. 令牌合同

### 3.1 请求

```json
{ "audience": "mira:cloud-guanlan" }
```

```json
{ "audience": "mira:cloud-guanlan", "scopes": ["guanlan.read", "guanlan.write"] }
```

- `scopes` 可省略，缺省即只读。
- 只接受 `guanlan.read` 与 `guanlan.write`；必须包含 `guanlan.read`；不得重复；unknown scope 拒绝。
  数组顺序不敏感，签名时归一化为 `[read]` 或 `[read, write]`。
- 请求体严格（`.strict()`）：`consumer_id`、`accountId`、`deviceId`、`relay` 等字段一律 400。

### 3.2 Claims（脱敏样例）

```json
{
  "iss": "mira:cloud-auth",
  "sub": "<account-id>",
  "device_id": "<device-id>",
  "aud": "mira:cloud-guanlan",
  "scope": ["guanlan.read", "guanlan.write"],
  "consumer_id": "<account-id>",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000300
}
```

- `consumer_id` 由服务端从**已验证、设备绑定**的 Cloud Session 派生，等于该会话所属 Cloud Account id。
  一个账号一个稳定消费者：跨设备、跨会话、跨续期都不变。
- `device_id` 保留（既有合同），Guanlan 忽略它，只用于事故取证。
- 严格 schema：缺 `consumer_id`、`consumer_id` 为空/含前后空白/超过 128、`scope` 为写优先或重复，
  都会被 canonical schema 拒绝（签发侧抛 `INVALID_INPUT`，验证侧 `INVALID_SIGNATURE` 之前就失败）。

### 3.3 scope 与写权限

| Scope | 语义 | 检查方 |
| --- | --- | --- |
| `guanlan.read` | 通过 MCP 资源读闸门 | Guanlan 全局 gate |
| `guanlan.write` | 决策写工具授权 | 各写工具独立检查 |

写权限只能由客户端**显式请求**，服务端不因"读到"而附加写，也不因"写"而省略读。写作用域只作用于
调用者自己账号的消费者账本——`consumer_id` 恒等于 `sub`，跨账号写入在 Guanlan 侧无主体可用。

## 4. 空间闸门 = 前置读 GLN-012 注册投影

`apps/api/src/service-credentials/guanlan-space-readiness.ts` 读取 GLN-012 outbox
（表 `guanlan_registration_outbox`，归 GLN-012 所有）：

| 投影状态 | 结果 |
| --- | --- |
| `delivered` | 允许签发 |
| `pending` / `delivering` / `withheld` / `failed` / 无该账号行 | `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY` |
| 表不存在 | 同样 `409`（未知 ≠ 允许） |

闸门与 session/device/account 权威检查在**同一个** `BEGIN IMMEDIATE` 事务里，禁用、撤销、注册状态
变更无法插到"判定"与"签名"之间。拒绝信息有界，不回显账号、consumer 或注册状态。

Cloud Auth 只读该投影：不创建 Guanlan 账号/消费者行，不存新闻、账本或空间业务数据。

## 5. 签发入口与信任边界

- 入口仍只有 `POST /v1/service-credentials`，需 device-bound Cloud Session；未登录/伪造/过期/撤销/登出/
  设备撤销/账号禁用/账号拒入，全部 `401 SERVICE_CREDENTIAL_REAUTH_REQUIRED`，不区分原因。
- account/device/issuer/kid/scope/consumer 全部服务端派生；客户端只能选 audience 与（可选）scope 集。
- 无空间（投影非 `delivered`）→ 409；未配置签名材料 → 503。两者都不签发、不泄漏。
- 错误码刻意不混用：**账号不可用**在权威检查阶段就失败为 `401`（GLN-012 会在同一事务把该账号置
  `withheld`），**注册未完成**才是 `409 PRINCIPAL_NOT_READY`。因此 409 只描述"注册进度"，不充当账号状态
  oracle；`withheld` 不作为单独的对外错误码，避免泄露"该账号被拒/被禁"。

## 6. 撤销语义

按维护者裁决：**短 TTL + 签发时复核**，不新增 `jti`、吊销表或在线内省。

- 撤销账号/设备/会话只阻止**后续签发**；已签发令牌在 `exp` 前仍可离线验证。
- Guanlan audience 建议 TTL ≤ 300s（实现上限 600s 不变，由
  `MIRA_AUTH_SERVICE_CREDENTIAL_TTL_SECONDS` 控制）。
- 残余暴露窗口 = 令牌剩余寿命 + Guanlan 5s clock tolerance。

## 7. HTTP 合同增量

| 状态 | code | 何时 |
| --- | --- | --- |
| 409 | `SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY` | 注册投影非 `delivered`（含 `pending`/`delivering`/`withheld`/`failed`/无行/表缺失） |
| 400 | `SERVICE_CREDENTIAL_INVALID_REQUEST` | scope 集合非法、客户端自报身份/consumer |
| 401 | `SERVICE_CREDENTIAL_REAUTH_REQUIRED` | 会话/设备/账号不可用（先于闸门判定，不区分原因） |

其余错误码与既有 audience 完全一致，未改动。

## 8. 测试与证据（本机实际执行）

| 层 | 文件 | 覆盖 |
| --- | --- | --- |
| T1 | `apps/api/tests/unit/service-credential-guanlan.test.ts` | 常量钉死、claims 正负例（缺/空/超长/带空白 consumer、写优先、重复、跨 audience）、请求 schema、签名 claims 精确值、非 Guanlan audience 拒绝 consumer |
| T2 | `apps/api/tests/contract/service-credential-guanlan.test.ts` | 未登录/伪造 bearer、客户端自报 consumer/account/device、写优先 scope、投影缺失时 409、读/写 scope 矩阵、跨 audience 验证互拒、响应不含 session |
| T3 | `apps/api/tests/integration/guanlan-credential-issuance.test.ts` | 真实 SQLite：`delivered` 才签发、pending/delivering/withheld/failed/无行 409、禁用/拒入/设备撤销/登出/会话过期 401、跨账号 consumer 隔离、只读不提权 |

命令与结果（本机，Node `v24.9.0`，pnpm `10.34.7`）：

```text
node node_modules/typescript/bin/tsc --noEmit        # apps/api，通过
node node_modules/vitest/vitest.mjs run tests/unit/service-credential-guanlan.test.ts \
  tests/contract/service-credential-guanlan.test.ts \
  tests/integration/guanlan-credential-issuance.test.ts
# Test Files 3 passed (3) / Tests 20 passed (20)

pnpm run check   # 仓库根：typecheck + 全量 test
# api: 41 files / 190 tests passed；web: 12 files / 136 tests passed
```

`pnpm run check` 的完整输出保留在本机 `check-output.log`（不提交，未进入版本库）。

## 9. 与 GLN-012 的职责边界

| 事项 | 归属 |
| --- | --- |
| `guanlan_registration_outbox` 表、投递、重试、admin CLI、`delivered` 判定 | GLN-012（PR #130，已合并 `931ae6c`） |
| 读该投影作为签发闸门 | GLN-013（本文） |
| `guanlan_accounts` / `guanlan_consumers` 行与 consumer 业务语义 | Guanlan（GLN-012 与之对接） |
| Cloud Auth 账号/设备/会话/凭证签发 | 本仓（既有） |

GLN-012 的 outbox **不是授权**，只是"注册是否已持久确认"的投影；本仓不把它当作用户权限来源。

## 10. 未验证与阻塞（不冒充真实链路）

1. **Guanlan 侧 consumer 行缺失**：即使令牌合法，`guanlan_consumers(account_id, consumer_id)` 无行时
   Guanlan 会返回 `guanlan_principal_unavailable`（GLN-014 已记录）。该行由 Guanlan provisioning 负责，
   尚未实现/执行。
2. **注册投影尚未 delivered**：建号自动写 `pending`，必须经 GLN-012 的真实投递（HTTPS 接收端 + HMAC）才会
   变成 `delivered`。接收端（GLN-015）与非生产 HTTPS 入口未就绪前，Guanlan 签发一律 409。老账号还需先跑
   `guanlan-backfill`，否则连行都没有（同样 409，不会默认放行）。
3. **无真实 `/mcp` 端点**：Guanlan `wrangler.jsonc` 为 `do-not-deploy`、D1 UUID 全 0、`workers_dev:false`。
4. **无真实 JWKS 取回/轮换观测**：本机无 Cloud Auth dev/test 实例（只有生产 `cloud-auth.tomzlab.cn`，
   test 非常驻），未向 Guanlan 提供真实 `CLOUD_AUTH_JWKS_URL`。
5. **按值对齐漂移风险**：Guanlan 不 import `@uichat-mira/cloud-auth-contracts`；任一名字变更必须双仓同步。
   本仓以 T1 常量断言固定这些值。
6. **写权限的产品语义**：`guanlan.write` 目前授权到"本账号消费者账本"。若未来需要运营/审核角色，
   应另立工作项，不在本任务内扩张。

## 11. 待确认项（维护者/下游）

- Guanlan provisioning 何时写入 `(account_id, account_id)` consumer 行（决定真实链路可读时间）。
- TTL 生产取值（建议 Guanlan ≤300s）。
- 本仓 PR 合并顺序：建议 GLN-012 先于或同时于 GLN-013，避免出现"有签发、无投影"的空窗。

非生产签发源（本机实例、测试账号、device-bound 会话、`pending → delivered` 的合法手段）见
[gln-013-nonprod-environment.md](gln-013-nonprod-environment.md)。
