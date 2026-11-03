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
| 公网 JWKS | ✅ 先由临时隧道、终态改为 Cloudflare Pages 静态发布（§5.2），隧道与 8789 代理已关闭 |
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

> TTL 只有 300s：调用方必须**现取现用**，不能缓存令牌跨用例复用。

### 4.1 给下游（t9/t10）的取令牌方式：不依赖人工介入

`mint.mjs`（仓库外脚本，只读本机会话文件）就是唯一入口，任何人都可以在同一台机器上直接跑：

```bash
# Guanlan 只读（默认）
node "%TEMP%\gln013-t23\mint.mjs" "%TEMP%\gln013-t23"
# 加写权限
node "%TEMP%\gln013-t23\mint.mjs" "%TEMP%\gln013-t23" guanlan.read guanlan.write
# 负例：错误 audience（Shiyan）
node "%TEMP%\gln013-t23\mint.mjs" "%TEMP%\gln013-t23" --audience=mira:cloud-shiyan
```

- 只打印 `aud/scope/ttl/exp/kid/consumer_eq_sub/sha256_12`；**令牌原文不打印**，写到
  `%TEMP%\gln013-t23\token-for-t10.txt`（目录 ACL 已 `icacls /inheritance:r` 收为仅当前 Windows 用户）。
- 每次调用前重跑一次即可刷新（覆盖同一文件）；失败时非 0 退出并打印 `issue failed: <status> <code>`。
- Shiyan 令牌写在 `token-shiyan.txt` 以便与 Guanlan 令牌并存（脚本默认覆盖 `token-for-t10.txt`，需要并存时
  签完先复制）。
- 注意 audience 常量必须带 `cloud-`：`{"audience":"mira:shiyan"}` → 400 `SERVICE_CREDENTIAL_INVALID_REQUEST`，
  正确值是 `mira:cloud-shiyan`；Shiyan 请求体**只允许** `audience` 一个字段（`scopes/scope/relay` 都会 400）。

## 5. 公网 JWKS（只暴露公钥路径）

> ⚠️ **本文所有 `https://<temporary-host>` 都是占位符，刻意不保留真实主机名。**
> 当时的隧道域名（`*.lhr.life`）在隧道释放后会被回收，可能被第三方重新绑定；把它写进文档会让后来者
> 照抄到别人的域名上（无论是取公钥还是误判"隧道还活着"）。复现时请自己新开隧道、用新拿到的 host，
> **不要复用任何历史 host**。

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
# → https://<temporary-host>
```

实测（隧道重连会换 host；**当时的具体 host 已从文档移除，禁止复用**，见上方警告）：

```text
GET https://<temporary-host>/.well-known/jwks.json
200 application/json
{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"gln013-t23-1","x":"<公钥>"}]}

GET  https://<temporary-host>/v1/service-credentials → 404
GET  https://<temporary-host>/                      → 404
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

### 5.1 换址的处理：host 文件 + 计划任务看护（不靠消息传递）

隧道重连会换 host，把 host 写进聊天记录必然过期。约定：

- **唯一发布通道**：`%TEMP%\gln013-t23\current-host.txt`。下游只读这个文件，消息里不再传具体 host。
- **看护任务**：Windows 计划任务 `gln013-t23-keepalive`（每 1 分钟，用户级），跑
  `%TEMP%\gln013-t23\keepalive.ps1`：
  1. `8788` 不健康 → 用 `boot-server.mjs` 拉起（读同一 SQLite 与私钥，会话/账号状态保留）；
  2. `8789` 不健康 → 重启 JWKS-only 代理；
  3. host 文件里的 host 取不到 JWKS → 新开隧道，**新 host 实际返回 200 之后才写文件**。
- 计划任务是独立进程树，**不随 DSH 会话/job 结束而退出**；实测：杀掉承载实例的会话 job 后，61 秒内
  `/health` 与公网 JWKS 均恢复 200（日志 `instance down -> boot` → `instance 200`）。
- 代价：换址后下游需要重新 deploy 一次 Worker 变量（只改变量，不重建 D1）。因此"隧道是临时设施"这条
  要写进验收边界：它不是生产常驻，也没有可用性承诺。

### 5.2 终态：JWKS 改为静态发布（隧道与代理已退役）

消费方（Guanlan 隔离 Worker）已改为从 **Cloudflare Pages** 读取静态 JWKS：
`https://mira-auth-jwks-test.pages.dev/.well-known/jwks.json`（只含公钥、无 `d`、`max-age=300`）。
因此本轮结束后：

- **隧道与 `8789` JWKS-only 代理都已关闭**；公网只剩 Pages 上的公钥副本，本机不再有对外暴露面。
- `keepalive.ps1` 收窄为只维护 `127.0.0.1:8788`；`current-host.txt` 保留但**仅在需要手工重发布 JWKS 时**
  作为一次性取数入口（取一次公钥 → 覆盖 Pages → 冒烟）。
- **独立核对**：Pages 上的 `x` 与本机 `signing.pub.pem` 导出的 `x` 逐字节一致（`pages_matches_local=true`、
  `kid=gln013-t23-1`、无私有分量），即静态副本确实是本机这把钥匙的公钥，不是别人的。
- **密钥轮换**：静态副本不会自动更新。轮换流程 = 本机换 key（换 `kid`）→ 导出新 JWKS JSON → 交给消费方覆盖
  Pages 并 `pages deploy` → 冒烟 `whoami`。若只换 key 不重发布，`/mcp` 会立刻 401（fail closed）。
  **本轮不轮换**；真要轮换应在 t9 开始前或结束后做，避免联调中途 401。
- **边界口径**：静态发布的是**公钥**，私钥仍只在本机；这不是产品形态，生产必须用常驻 Cloud Auth 的
  真实 JWKS 端点。

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

1. **JWKS 是静态副本**（Cloudflare Pages，仅公钥）：不会随本机密钥变化自动更新，轮换必须重新发布一次，否则 /mcp 立刻 401（fail closed）；生产必须改用常驻 Cloud Auth 的真实 JWKS 端点。
2. **代理依赖**：本机 Node `fetch` 默认不走系统代理，投递必须 `--use-env-proxy`；否则表现为
   `delivery_unconfirmed`，容易被误判为接收端故障。
3. **D1 有测试残留行**：一条真实测试账号空间行，属于隔离环境；未实现自动清理。
4. **令牌 TTL 300s**：联调用例必须现取现用。
5. **投影漂移**：Cloud Auth 已 `delivered` 但 Guanlan 空间后续被拆时，仍可能签出令牌、由资源侧拒绝
   （fail closed，但属"晚失败"）；对账机制是后续工作项，本卡不实现。
6. **手工 mint 是 V1 临时形态**：`mint.mjs` 用本机会话文件现签，只解决"下游不等人"的联调问题；长期应是
   服务侧按需签发（服务凭据由调用方服务自己获取/续期），不能把手工 mint 当架构。
7. **host 变化不另行通知**：双方约定下游在每次验收前先读 `current-host.txt`，再决定是否重 deploy；
   若 `/mcp` 突然 401，先比对 host 文件与 Worker 变量，再怀疑令牌合同。
8. **未验证**：JWKS 轮换/多 kid 行为；生产实例。Guanlan `/mcp` 接受度已由 t10 真实部署 Worker 验证
   （`initialize`/`whoami`/`news_recent` 200、`consumerEqualsAccount=true`）。

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
| 01:36 | 公网 JWKS | `https://<temporary-host>/.well-known/jwks.json` 200；其它路径 404 |
| 01:47 | JWKS+签名独立核对 | `jwks_key_matches_local_public_key=true`、`token_signature_valid=true`、`ttl=300` |
| 02:29 | 脱离子进程看护 | 主动 kill 承载实例的会话 job → 日志 `instance down -> boot` → `instance 200`，同轮 `/health`、公网 JWKS 均 200 |
| 02:31 | Worker 真实接受（t10，非生产隔离 Worker） | `initialize`/`tools/list`/`whoami`/`news_recent` 均 200；`whoami` 回 `consumerEqualsAccount: true`、`scopes:["guanlan.read"]` |
| 02:31 | 错误 audience 负例（t10） | Shiyan 令牌（`scope=shiyan:authenticate`）打 Guanlan `/mcp` → `401 invalid_token`（非 503，说明是验证拒绝而非配置缺失） |
| 02:31 | 跨账户隔离（t10） | 令牌（`5728cbcd…`）读不到合成账户 `33333333…` 的文章；`decide` → `guanlan_decision_not_available`（不泄露存在性）；D1 零写入 |
| 02:47 | 静态 JWKS 独立核对 | Pages `/.well-known/jwks.json` 200；与本机 `signing.pub.pem` 导出的 JWK 比对 `pages_matches_local=true`、`kid=gln013-t23-1`、无 `d` 分量（消费方侧另核 `same_x=true`） |
| 02:55 | 隧道/代理下线后复验 | `8788 /health` 200、`8789` 已关闭；现签 `ttl=300`、`kid=gln013-t23-1`、`consumer_eq_sub=true`；该令牌打 `/mcp` 的 `initialize`/`tools/list`/`whoami` 均 200（`consumerEqualsAccount:true`） |
