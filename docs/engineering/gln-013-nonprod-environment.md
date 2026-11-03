# GLN-013 · 非生产 Cloud Auth 实例与签发源准备

> 用途：给 GLN-014/Guanlan 侧提供**非生产** Cloud Auth 签发源（本机或隔离实例），使 Guanlan 验证器与
> JWKS 可取回、令牌可签出。**禁止**用生产 `cloud-auth.tomzlab.cn` 做联调。
> 分支：`feat/gln-013-guanlan-consumer-credential`，基线 `origin/dev` `481767f`。
> 实现合同见 [gln-013-guanlan-credential.md](gln-013-guanlan-credential.md)。

## 0. 结论（先读这段）

| 问题 | 结论 |
| --- | --- |
| 能否本机起一个可用 Cloud Auth？ | **能**。`pnpm` + `node --import tsx src/server.ts`，SQLite 单文件，无外部依赖。 |
| 能否取到 JWKS？ | **能**。`GET /.well-known/jwks.json`，`Cache-Control: public, max-age=300`。 |
| 能否签发 Shiyan/Relay 令牌？ | **能**，且本机已实际签出一枚 Shiyan 令牌（见 §6）。 |
| 能否签发 Guanlan 令牌？ | **当前不能**：建号即写 `pending`，只有真实投递把投影置 `delivered` 后才签发；否则一律 `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`（本机已实测）。 |
| 本机能否驱动 outbox 到 `delivered`？ | **投递网络不行，状态机可以**。GLN-012 的投递传输**强制 https**（`createGuanlanRegistrationTransport` 校验 `u.protocol !== "https:"` 即拒绝），`http://127.0.0.1` 收不到投递；但 `deliverGuanlanRegistrations` 的状态机可在本机用注入 transport 跑通（T3 用例已覆盖 `pending → 未确认 → pending`、`pending → confirmed → delivered`）。 |
| 合法到达 `delivered` 的最小手段 | GLN-015 接收端 + 一个 **https** 非生产入口（临时隧道/隔离部署）+ 共享 HMAC secret（≥32 字符）；老账号先 `guanlan-backfill`，再 `guanlan-deliver`。**不得直接改库。** |

## 1. 本机实例启动

前置：Node ≥ 24（`node:sqlite`、`crypto.argon2`）、pnpm `10.34.7`。首次需 `pnpm install --frozen-lockfile`。

### 1.1 生成一次性本地签名密钥（不提交）

```bash
cd apps/api
mkdir -p data
node -e "const {generateKeyPairSync}=require('node:crypto');const fs=require('node:fs');const {privateKey,publicKey}=generateKeyPairSync('ed25519');fs.writeFileSync('data/gln013-local-signing.pem',privateKey.export({type:'pkcs8',format:'pem'}));fs.writeFileSync('data/gln013-local-signing.pub.pem',publicKey.export({type:'spki',format:'pem'}));"
```

`data/`、`*.sqlite`、`.env` 均在 `.gitignore` 内；私钥只留在本机。

### 1.2 启动（bash）

```bash
cd apps/api
MIRA_AUTH_DB_PATH=./data/gln013.sqlite \
PORT=8788 HOST=127.0.0.1 LOG_LEVEL=info \
MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_KID=gln013-local-1 \
MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_PRIVATE_KEY="$(cat data/gln013-local-signing.pem)" \
MIRA_AUTH_SERVICE_CREDENTIAL_TTL_SECONDS=300 \
MIRA_GUANLAN_REGISTRATION_URL="https://<non-prod-receiver>/<path>" \
MIRA_GUANLAN_REGISTRATION_SECRET="<shared secret, >=32 chars>" \
node --import tsx src/server.ts
```

投递相关两项只被 admin CLI 的 `guanlan-deliver` 使用（API 进程本身不需要它们，但同机运行时用同一份环境更省事）。

### 1.3 启动（Windows PowerShell）

```powershell
cd apps/api
$env:MIRA_AUTH_DB_PATH="data/gln013.sqlite"; $env:PORT="8788"; $env:HOST="127.0.0.1"
$env:MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_KID="gln013-local-1"
$env:MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_PRIVATE_KEY=(Get-Content data\gln013-local-signing.pem -Raw)
$env:MIRA_AUTH_SERVICE_CREDENTIAL_TTL_SECONDS="300"
node --import tsx src/server.ts
```

也可用 `pnpm run dev:api`（会读仓库根 `.env`，可用 `\n` 转义写单行 PEM）。签名材料缺失/非法时签发与 JWKS
返回 503，但登录、`/health`、`/ready` 不受影响。

### 1.4 对外地址

| 用途 | URL |
| --- | --- |
| API base | `http://127.0.0.1:8788` |
| JWKS（Guanlan 取公钥） | `http://127.0.0.1:8788/.well-known/jwks.json` |
| 健康检查 | `GET /health`、`GET /ready` |
| 默认端口 | 8788（与 test 环境同端口，**不要同时启动**） |

实测：`jwks_status=200`、`cache_control=public, max-age=300`、`/health` = `{"status":"ok","service":"mira-cloud-auth"}`、`/ready` = `{"status":"ready"}`。

## 2. 测试账号 + 设备绑定 Cloud Session（3 步）

密码只经 stdin 传给 `admin-cli`，**不要放在命令行参数**。注意：`readPasswordFromStdin()` 读的是原始
stdin，用 `echo "..." |` 会带上换行，导致入库密码与预期不一致；请用不追加换行的方式写入（Node `spawnSync`
`input`、bash `printf '%s'`）。

```bash
cd apps/api

# 2.1 建号（已存在则改密）；随后确保 allowed + enabled
printf '%s' "$MIRA_AUTH_SEED_PASSWORD" | node --import tsx src/admin-cli.ts provision gln013-tester
node --import tsx src/admin-cli.ts allow  gln013-tester
node --import tsx src/admin-cli.ts enable gln013-tester

# 2.2 登录（不要在此步带 device：device 绑定要求设备行已存在）
curl -sS -X POST http://127.0.0.1:8788/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"gln013-tester","password":"<REDACTED>"}'
# → {"account":{"id":"<account-id>","username":"gln013-tester"},"expiresAt":"...","sessionToken":"<SECRET>"}

# 2.3 注册 Mira Device，把该会话绑定到设备（返回 device.id）
curl -sS -X POST http://127.0.0.1:8788/v1/devices \
  -H "authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d '{"installationId":"<uuid4>","platform":"desktop","clientName":"GLN-014 local"}'
```

`sessionToken` 与密码都是凭证：只放 shell 变量，不写日志、不进 Issue/PR。OAuth 首方流程
（`/v1/oauth/authorize` + `/v1/oauth/token`）同样产出设备绑定会话，是 Desktop/Mobile 的真实路径。

## 3. 最小签发调用

```bash
curl -sS -X POST http://127.0.0.1:8788/v1/service-credentials \
  -H "authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d '{"audience":"mira:cloud-guanlan","scopes":["guanlan.read"]}'
```

令牌是可离线验证的 EdDSA JWS，**不需要**把整枚令牌贴到任何地方。取证只打印：

```js
// node 24，无第三方依赖
const token = process.env.TOKEN;                     // 不落盘、不回显
const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
const sha256_12 = require("node:crypto").createHash("sha256").update(token).digest("hex").slice(0, 12);
console.log({
  aud: payload.aud,
  scope: payload.scope,
  consumerIsAccount: payload.consumer_id === payload.sub,
  exp: payload.exp,
  ttlSeconds: payload.exp - payload.iat,
  sha256_12,
});
```

**当前实际结果**（本机，`dev` + 本分支，2026-11-04）：

```text
POST /v1/service-credentials {"audience":"mira:cloud-shiyan"}
  → 200 aud=mira:cloud-shiyan scope=shiyan:authenticate device_claim=<device-id> ttl=300 sha256_12=5f396749d48f

POST /v1/service-credentials {"audience":"mira:cloud-guanlan","scopes":["guanlan.read"]}
  → 409 {"error":{"code":"SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY","message":"The account is not registered for the requested service"}}

POST /v1/service-credentials {"audience":"mira:cloud-guanlan","consumer_id":"other-account"}
  → 400 {"error":{"code":"SERVICE_CREDENTIAL_INVALID_REQUEST","message":"Invalid service credential request"}}
```

即：签名链路本身可用（Shiyan 已签出），Guanlan 令牌被**空间闸门**挡住，客户端自报 consumer 被严格请求
schema 拒绝。Guanlan 令牌的字段正确性由 T1/T2/T3 覆盖（`tests/unit|contract|integration` 三个
`*guanlan*` 文件，22 条用例）；其中一条 T3 用 `dev` 自己的投递状态机把账号从 `pending` 推进到
`delivered`（transport 注入、不走网络），其余闸门负例直接构造 outbox 行——两者都不是真实投递。

## 4. 闸门与 `pending → delivered`

`dev` 现状（GLN-012 已合并，merge commit `931ae6c`）：

- 建号即在同一事务写入 `pending`；老账号需 `guanlan-backfill`（只补活跃账号，默认也是 `pending`）。
- 投影表缺失（未迁移）→ `GuanlanRegistrationOutboxReadiness.status()` 返回 `unavailable`
  → 一律 `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`（未知 ≠ 允许）。
- 只有真实投递成功才置 `delivered`。

GLN-012 的投递事实（只读核对，未接管该工作项）：

| 项目 | 事实 |
| --- | --- |
| 端点配置 | `MIRA_GUANLAN_REGISTRATION_URL` |
| 共享密钥 | `MIRA_GUANLAN_REGISTRATION_SECRET`（长度 < 32 直接拒绝） |
| 密钥精度 | **必须与 Worker 侧逐字节一致**：发送端用配置原值做 HMAC key，**不 trim**；接收端对"带首尾空白的 secret"直接回 `503 registration_not_configured`（不是 401）。从文件注入请用 `printf '%s'` / `Set-Content -NoNewline`，不要 `echo` / `cat <<EOF` 带换行。 |
| 传输要求 | **https only**：`new URL(endpoint)` 非 `https:` 即抛 `Guanlan delivery configuration is unsafe` |
| 签名 | `x-mira-signature: sha256=<hex HMAC(secret, timestamp + "." + body)>` |
| 触发 | `pnpm run admin guanlan-deliver`（另有 `guanlan-backfill` / `guanlan-status` / `guanlan-retry`） |
| 结果 | 只有确认成功才 `UPDATE ... SET status='delivered'`；未确认回落 `pending`/`failed` |
| 本机网络 | 若本机需经代理出网，`fetch` 默认不走代理：用 `node --use-env-proxy`（或 `NODE_USE_ENV_PROXY=1`）+ `HTTPS_PROXY`，否则表现为 `last_error=delivery_unconfirmed`（8s 超时）。 |

接收端归 GLN-015（`cloud-mcp-guanlan`，`POST /internal/guanlan-registrations`，校验 ±300s 时间窗 +
`x-mira-signature` 的 HMAC 并做幂等写入，只在持久化成功后返回 `{accountId, registered:true}`）。

2026-11-04 更新：隔离非生产接收端已部署并冒烟（`https://cloud-guanlan-gln014-3c872be6.dangjingtao.workers.dev`，
真实 D1）。真实 `pending → delivered` 的操作序列、实测输出、JWKS 临时暴露与销毁步骤见
[gln-013-nonprod-runbook.md](gln-013-nonprod-runbook.md)。

一旦有了 https 入口，完整命令是：

```bash
# 老账号先补投影（新账号建号即 pending，可跳过）
MIRA_GUANLAN_REGISTRATION_URL=https://<host>/internal/guanlan-registrations \
MIRA_GUANLAN_REGISTRATION_SECRET="<shared secret, >=32 chars>" \
pnpm run admin guanlan-backfill

MIRA_GUANLAN_REGISTRATION_URL=https://<host>/internal/guanlan-registrations \
MIRA_GUANLAN_REGISTRATION_SECRET="<shared secret, >=32 chars>" \
pnpm run admin guanlan-deliver          # 真实 HMAC 投递，确认后置 delivered
pnpm run admin guanlan-status gln013-tester   # 核对该账号已 delivered
```

因此：

1. **本机 loopback 无法产生网络投递**（http 被拒）。最小合法路径是给 GLN-015 接收端一个 **https**
   非生产入口（临时隧道或隔离部署），把 `MIRA_GUANLAN_REGISTRATION_URL` 指向它，先 `guanlan-backfill`
   （老账号），再跑 `guanlan-deliver`。
2. **禁止**用 `UPDATE ... SET status='delivered'` 或手写行来"造出"投递成功——那会把未注册的空间伪装成
   已注册，Guanlan 侧仍会 `guanlan_principal_unavailable`，属于伪造成功。T3 里构造 `delivered` 行是
   **测试夹具**，仅用于验证闸门的正/负分支，不是投递证据。
3. 真实联调里闸门的表现：未投递 → 409（不签发、不泄漏）；投递成功 → 正常签发；账号被 deny/disable →
   GLN-012 把记录置 `withheld` 且会话被撤销 → 请求在权威检查阶段就是 401（而不是 409）。
4. 投递失败会按 8 次上限 + 指数退避留在 `pending`/`failed`；`guanlan-retry <username>` 可重排，`failed`
   到顶后需人工确认，不会自动放行。

## 5. Guanlan Worker 侧的 JWKS 可达性

- **本地 `wrangler dev`（workerd 本机）**：可以 `fetch("http://127.0.0.1:8788/.well-known/jwks.json")`，
  两端都在本机 loopback，无需公网暴露。这是当前唯一不需要维护者提供公网入口的联调形态。
- **已部署的 Worker（Cloudflare 边缘）**：`127.0.0.1` 不可达，必须给公开 **https** base URL
  （隔离部署或隧道）。这属于环境授权范围，本次未做。
- JWKS 缓存 300s；轮换必须先预发布新公钥再切 active（见 `docs/service-credentials-v0.md` 的 key rotation）。

## 6. 本机实际执行的证据（脱敏）

环境：Windows，Node `v24.9.0`，pnpm `10.34.7`，本分支 worktree。

| 步骤 | 实际输出（脱敏） |
| --- | --- |
| 生成密钥 | `data/gln013-local-signing.pem`（Ed25519，仅本机，gitignored） |
| 启动 | `GET /health` → `{"status":"ok","service":"mira-cloud-auth"}`；`GET /ready` → `{"status":"ready"}` |
| JWKS | `200`，`kid=gln013-local-1`，`cache-control: public, max-age=300` |
| 建号 | `{"id":"ced71b61-…","username":"gln013-tester","allowed":true}` |
| 登录 + 绑定设备 | `account=ced71b61-… device=f24d4b56-… platform=desktop` |
| 签发 Shiyan | `aud=mira:cloud-shiyan scope=shiyan:authenticate ttl=300 sha256_12=5f396749d48f` |
| 签发 Guanlan | `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`（闸门，符合预期：建号后仍是 `pending`） |
| 自报 consumer | `400 SERVICE_CREDENTIAL_INVALID_REQUEST` |

未做（也不宣称）：真实 Guanlan `/mcp` 调用、真实 JWKS 取回、**真实网络投递**（`guanlan-deliver` 指向真实
GLN-015 接收端）、任何生产实例操作。真实投递的阻塞项是接收端与 https 入口，不是本仓代码。

## 7. 限制与残留风险

1. 本机实例只证明"能起、能签、能拒"，不证明"Guanlan 接受"。
2. GLN-012 已合并（`931ae6c`），但 GLN-015 接收端与 https 非生产入口未就绪前，Guanlan 联调仍会停在 409。
3. 本地签名密钥是**一次性非生产密钥**，绝不能复制到任何共享环境；生产密钥由维护者另行注入。
4. 端口 8788 与 test 环境默认值相同，同一台机器不要并行启动两个实例（SQLite 文件也不同，但端口会冲突）。
5. 老账号若未 `guanlan-backfill`，闸门表现为"无行 → 409"，与 `pending` 无法从响应区分（这是有意的）。
