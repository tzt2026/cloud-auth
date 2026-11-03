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
| 能否签发 Guanlan 令牌？ | **当前不能**：Guanlan 签发前置读 GLN-012 注册投影，`dev` 无该表 → 一律 `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`。这是**设计行为**，本机已实测。 |
| 本机能否驱动 outbox 到 `delivered`？ | **不能**。GLN-012 的投递传输**强制 https**（`createGuanlanRegistrationTransport` 校验 `u.protocol !== "https:"` 即拒绝），`http://127.0.0.1` 收不到投递。 |
| 合法到达 `delivered` 的最小手段 | GLN-012 合并 +（GLN-015 接收端 + 一个 **https** 非生产入口，如临时隧道/隔离部署）+ 共享 HMAC secret，然后跑 `guanlan-deliver`。**不得直接改库。** |

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
node --import tsx src/server.ts
```

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
`*guanlan*` 文件，20 条用例），其中 T3 用的是**测试专用**的投影表，不能当作真实投递。

## 4. 闸门与 `pending → delivered`

`dev` 现状（GLN-012 / PR #130 未合并）：

- 无 `guanlan_registration_outbox` 表 → `GuanlanRegistrationOutboxReadiness.status()` 返回 `unavailable`
  → 一律 `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`。
- 合并后：账号创建时 GLN-012 会写入 `pending`；只有真实投递成功才置 `delivered`。

GLN-012 的投递事实（只读核对，未接管该工作项）：

| 项目 | 事实 |
| --- | --- |
| 端点配置 | `MIRA_GUANLAN_REGISTRATION_URL` |
| 共享密钥 | `MIRA_GUANLAN_REGISTRATION_SECRET`（长度 < 32 直接拒绝） |
| 传输要求 | **https only**：`new URL(endpoint)` 非 `https:` 即抛 `Guanlan delivery configuration is unsafe` |
| 签名 | `x-mira-signature: sha256=<hex HMAC(secret, timestamp + "." + body)>` |
| 触发 | `pnpm run admin guanlan-deliver`（另有 `guanlan-backfill` / `guanlan-status` / `guanlan-retry`） |
| 结果 | 只有确认成功才 `UPDATE ... SET status='delivered'`；未确认回落 `pending`/`failed` |

因此：

1. **本机 loopback 无法产生 `delivered`**（http 被拒）。最小合法路径是给 GLN-015 接收端一个 **https**
   非生产入口（临时隧道或隔离部署），把 `MIRA_GUANLAN_REGISTRATION_URL` 指向它，再跑 `guanlan-deliver`。
2. **禁止**用 `UPDATE ... SET status='delivered'` 或手写行来"造出"投递成功——那会把未注册的空间伪装成
   已注册，Guanlan 侧仍会 `guanlan_principal_unavailable`，属于伪造成功。
3. 真实联调里闸门的表现：未投递 → 409（不签发、不泄漏）；投递成功 → 正常签发；账号被 deny/disable →
   GLN-012 会把记录置 `withheld` → 依然 409，即使会话仍有效。

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
| 签发 Guanlan | `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`（闸门，符合预期） |
| 自报 consumer | `400 SERVICE_CREDENTIAL_INVALID_REQUEST` |

未做（也不宣称）：真实 Guanlan `/mcp` 调用、真实 JWKS 取回、真实 outbox 投递、任何生产实例操作。

## 7. 限制与残留风险

1. 本机实例只证明"能起、能签、能拒"，不证明"Guanlan 接受"。
2. GLN-012 未合并前，任何 Guanlan 联调都会停在 409；合并后还需 GLN-015 接收端与 https 入口。
3. 本地签名密钥是**一次性非生产密钥**，绝不能复制到任何共享环境；生产密钥由维护者另行注入。
4. 端口 8788 与 test 环境默认值相同，同一台机器不要并行启动两个实例（SQLite 文件也不同，但端口会冲突）。
