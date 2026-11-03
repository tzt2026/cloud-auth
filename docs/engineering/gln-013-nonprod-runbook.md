# GLN-013 · 非生产联调前置 Runbook（t23 实测）

本文记录 2026-11-04 在本机把 **非生产 Cloud Auth → 真实隔离 Guanlan 接收端 → `delivered` → 签发 Guanlan
令牌 → 公网 JWKS** 跑通的完整步骤与实测输出，供 t10（GLN-014）直接复用。

- 真实的部分：本机 Cloud Auth 实例（真 HTTP + 真 SQLite + 真 Ed25519 签名）、隔离 Worker 的 HTTPS 接收端
  （真 Cloudflare + 真 D1）、真实 HMAC 投递、真实 `delivered`、真实令牌与真实 JWKS 内容。
- 不是生产：不涉及 `cloud-auth.tomzlab.cn`，不部署、不改生产权限、不合并 PR。
- 不是真实 Guanlan `/mcp` 验签：本仓令牌能否被隔离 Worker 的 `/mcp` 接受，归 t10。
- 全程没有把密钥、令牌原文、密码写进仓库或日志；本文只保留脱敏投影。

## 0. 结论（先读这段）

| 事项 | 结果 |
| --- | --- |
| 非生产 Cloud Auth（loopback） | ✅ `127.0.0.1:8788`，`/health`、`/ready`、`/.well-known/jwks.json` 全 200 |
| 测试账号 + device-bound 会话 | ✅ 账号 `<8 位前缀>`，设备绑定成功 |
| 真实 `pending → delivered` | ✅ 隔离 Worker + 真 D1；`attempts=2`（第 1 次因未走代理 8s 超时） |
| 签发 Guanlan 令牌 | ✅ 200，`aud=mira:cloud-guanlan`、`scope=guanlan.read`、`TTL=300`、`consumer_id == sub` |
| 公网 JWKS | ✅ 临时隧道 `https://<随机>.lhr.life/.well-known/jwks.json`，其它路径 404 |
| 销毁 | ✅ 见 §6（DB/私钥/令牌/密码只在 `%TEMP%`，已删） |

## 1. 起非生产实例（loopback）

工作目录 `apps/api`，SQLite 与密钥都放**仓库外**（本节用 `%TEMP%\gln013-t23`）。

```bash
# 1.1 一次性 Ed25519 签名密钥（不提交、不进仓库）
node -e "const {generateKeyPairSync}=require('node:crypto');const fs=require('node:fs');const p=process.argv[1];const {privateKey,publicKey}=generateKeyPairSync('ed25519');fs.writeFileSync(p+'/signing.pem',privateKey.export({type:'pkcs8',format:'pem'}));fs.writeFileSync(p+'/signing.pub.pem',publicKey.export({type:'spki',format:'pem'}));" "$TMPDIR/gln013-t23"

# 1.2 启动（TTL 300s）
MIRA_AUTH_DB_PATH="$TMPDIR/gln013-t23/auth.sqlite" \
HOST=127.0.0.1 PORT=8788 LOG_LEVEL=warn \
MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_KID=gln013-t23-1 \
MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_PRIVATE_KEY="$(cat "$TMPDIR/gln013-t23/signing.pem")" \
MIRA_AUTH_SERVICE_CREDENTIAL_TTL_SECONDS=300 \
node --import tsx src/server.ts
```

PowerShell 等价写法见 [gln-013-nonprod-environment.md](gln-013-nonprod-environment.md) §1.3；注意 `KID`
要与 JWKS 里的 `kid` 一致。

## 2. 测试账号 + 设备绑定（3 步）

```bash
# 2.1 建号（stdin 用 printf '%s'，绝不能带换行；echo 会静默存错密码）
printf '%s' "$PW" | node --import tsx src/admin-cli.ts provision gln013-e2e

# 2.2 登录（此步不要带 device）
curl -s -X POST http://127.0.0.1:8788/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"gln013-e2e","password":"<PW>"}'
# → {"account":{"id":"<account-id>",...},"sessionToken":"<SECRET>"}

# 2.3 注册设备并绑定该会话
curl -s -X POST http://127.0.0.1:8788/v1/devices \
  -H "authorization: Bearer <sessionToken>" -H 'content-type: application/json' \
  -d '{"installationId":"<uuid>","platform":"desktop","clientName":"GLN-014 E2E"}'
# → {"id":"<device-id>", ...}
```

建号会在同一事务写入 `guanlan_registration_outbox(status='pending')`；此时签发 Guanlan 令牌必定
`409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`。

## 3. 真实投递：`pending → delivered`

```bash
export MIRA_GUANLAN_REGISTRATION_URL="https://cloud-guanlan-gln014-3c872be6.dangjingtao.workers.dev/internal/guanlan-registrations"
# 从共享密钥文件读取“原值”，不 trim、不改写
export MIRA_GUANLAN_REGISTRATION_SECRET="$(sed -n 's/^MIRA_GUANLAN_REGISTRATION_SECRET=//p' "$SECRET_FILE")"

# 老账号才有必要；新账号已是 pending，可跳过
node --import tsx src/admin-cli.ts guanlan-backfill
# 本机需经代理出网时必须走 --use-env-proxy，否则 8s 超时
HTTPS_PROXY=http://127.0.0.1:1080 node --use-env-proxy --import tsx src/admin-cli.ts guanlan-deliver
node --import tsx src/admin-cli.ts guanlan-status gln013-e2e
```

实测（脱敏）：

```text
# 第 1 次（未走代理）
{"delivered":0,"failed":1,"pending":1}
# last_error=delivery_unconfirmed（8s AbortSignal 超时），status 仍为 pending，attempts=1

# 第 2 次（--use-env-proxy + HTTPS_PROXY）
{"delivered":1,"failed":0,"pending":0}

# guanlan-status
{"registrations":[{"accountId":"<account-id>","status":"delivered","attempts":2,
  "nextAttemptAt":"2026-11-03T17:31:42.789Z","leaseUntil":null,"lastError":null}]}
```

接收端（GLN-015）返回 `{accountId, registered:true}`，隔离 D1 同时建立 `accounts` / `consumers`
（`consumer_id == account_id`）/ `receipts` 行。**没有**用 SQL 直接改状态。

## 4. 签发 Guanlan 令牌（只打印摘要）

```bash
curl -s -X POST http://127.0.0.1:8788/v1/service-credentials \
  -H "authorization: Bearer <sessionToken>" -H 'content-type: application/json' \
  -d '{"audience":"mira:cloud-guanlan","scopes":["guanlan.read"]}'
```

实测摘要（令牌原文未落盘、未打印、已随临时目录删除）：

```text
aud=mira:cloud-guanlan  scope=guanlan.read  ttl=300  exp=1793727451
kid=gln013-t23-1  consumer_eq_sub=True  sub8=5728cbcd  consumer8=5728cbcd
sha256_12=16d0f84f9b97  expiresAt=2026-11-03T17:37:31.000Z
```

> TTL 只有 300s：t10 必须**现取现用**，不能缓存令牌跨用例复用。

## 5. 公网 JWKS（只暴露公钥路径）

Worker 取不到 `127.0.0.1`，需要公网 https。做法是**两层**：

1. **JWKS-only 代理**（本机 `8789`）：只对 `GET /.well-known/jwks.json` 反代到 `8788`，其余一律 `404`。
   签发端点始终留在 loopback，不暴露。
2. **临时隧道**指向 `8789`（不是 `8788`）：本次用 `ssh -R`（localhost.run），因为本机到
   `api.trycloudflare.com` 的 quick-tunnel POST 在 8–15s 内超时，cloudflared 直连/代理均失败；SSH 22/443
   可达且稳定。

```bash
# 5.1 JWKS-only 代理（仓库外临时脚本，逻辑即“只放行一条路径”）
node "$TMPDIR/gln013-t23/jwks-proxy.mjs"        # listens 127.0.0.1:8789

# 5.2 临时隧道（无账号，URL 随机、进程退出即失效）
ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=20 -R 80:127.0.0.1:8789 nokey@localhost.run
# → https://<random>.lhr.life
```

实测（本次实际 URL，`2026-11-04 01:47` 有效；隧道重连会换 host）：

```text
GET https://1523cdc0bd8ab6.lhr.life/.well-known/jwks.json
200 application/json
{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"gln013-t23-1","x":"<公钥>"}]}

GET  https://1523cdc0bd8ab6.lhr.life/v1/service-credentials → 404
GET  https://1523cdc0bd8ab6.lhr.life/                      → 404
```

独立核对（不依赖本仓代码）：把隧道返回的 JWKS 与本地公钥对比，并对令牌原文做 Ed25519 验签：

```text
jwks_key_matches_local_public_key=true token_signature_valid=true kid=gln013-t23-1
aud=mira:cloud-guanlan consumer_eq_sub=true scope=guanlan.read ttl=300
```

把 `https://<host>/.well-known/jwks.json` 交给 guanlan-dev 配成 `CLOUD_AUTH_JWKS_URL`，
`CLOUD_AUTH_ISSUER=mira:cloud-auth` 后重新 deploy（不必重建 D1）。

隧道方案对比（本机实测）：

| 方案 | 结果 |
| --- | --- |
| `cloudflared tunnel --url`（quick tunnel） | ✗ `POST https://api.trycloudflare.com/tunnel` 8–15s 超时（直连与走本机代理都失败），无法取得 host |
| `ssh -R` → localhost.run | ✓ 可用；**重连会换 host**，需重新配置 `CLOUD_AUTH_JWKS_URL` |
| `ssh -p 443 -R0` → pinggy.io | 连接建立但未在非交互会话中打印 host，未采用 |

**有效期与关闭**：隧道随 SSH 进程结束（或服务端重连）而失效/换址；JWKS 代理随 node 进程结束。两者都不是
常驻服务。关闭后 Worker 的 JWKS 取回会失败 → 一律 401（fail closed，不会误放行）。

## 6. 销毁步骤（跑完就做）

```powershell
# 1) 关进程：SSH 隧道、JWKS 代理、Cloud Auth 实例（本机按 job/PID 结束）
# 2) 删临时目录（SQLite、私钥、公钥、令牌、密码、tunnel 脚本）
Remove-Item -Recurse -Force "$env:TEMP\gln013-t23"
# 3) 确认端口已释放
Test-NetConnection 127.0.0.1 -Port 8788   # False
Test-NetConnection 127.0.0.1 -Port 8789   # False
# 4) 确认工作树仍然 clean，且仓库里没有 .sqlite / .env / PEM
git -C D:\cloud-auth-wt\gln-013 status --porcelain
```

隔离 D1 里的那一条测试账号/consumer/receipt 行**仍在**（属于隔离环境数据，供 t10 联调使用）。
拆除整个隔离环境时按 guanlan-dev 的 `gln-014-isolated-env.md` 销毁步骤处理；不要用本文件的步骤去删 D1。

## 7. 残留风险与缺口

1. **JWKS 是临时隧道**：URL 随机、无 SLA、随进程失效；常驻非生产域名/实例需另立工作项。
2. **代理依赖**：本机 Node `fetch` 默认不走系统代理，投递必须 `--use-env-proxy`；否则表现为
   `delivery_unconfirmed`，容易被误判为接收端故障。
3. **D1 有测试残留行**：一条真实测试账号空间行，属于隔离环境；未实现自动清理。
4. **令牌 TTL 300s**：联调用例必须现取现用。
5. **投影漂移**：Cloud Auth 已 `delivered` 但 Guanlan 空间后续被拆时，仍可能签出令牌、由资源侧拒绝
   （fail closed，但属"晚失败"）；对账机制是后续工作项，本卡不实现。
6. **未验证**：Guanlan `/mcp` 是否接受本令牌（t10）；JWKS 轮换/多 kid 行为；生产实例。

## 8. 证据清单（脱敏）

| 时间（+08:00） | 事项 | 证据 |
| --- | --- | --- |
| 2026-11-04 01:28 | 实例启动 | `/health` `{"status":"ok","service":"mira-cloud-auth"}`；`/ready` `{"status":"ready"}` |
| 01:29 | JWKS 本地 | 200，`cache-control: public, max-age=300`，`kid=gln013-t23-1` |
| 01:30 | 建号 + 设备绑定 | 账号 `<8 位>`，`device=<8 位>`，outbox `pending` |
| 01:31 | 投递第 1 次 | `{"delivered":0,"failed":1,"pending":1}`，`last_error=delivery_unconfirmed` |
| 01:32 | 投递第 2 次（代理） | `{"delivered":1,"failed":0,"pending":0}` |
| 01:32 | 闸门解除 | `status=delivered, attempts=2, lastError=null` |
| 01:35 | 签发 | `aud/scope/ttl=300/consumer_eq_sub=True/sha256_12=16d0f84f9b97` |
| 01:36 | 公网 JWKS | `https://1523cdc0bd8ab6.lhr.life/.well-known/jwks.json` 200；其它路径 404 |
| 01:47 | JWKS+签名独立核对 | `jwks_key_matches_local_public_key=true`、`token_signature_valid=true`、`ttl=300` |
