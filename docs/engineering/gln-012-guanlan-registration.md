# GLN-012 · Guanlan 账户空间注册投递

Cloud Auth 在新账户插入的**同一 SQLite 事务**中插入 `guanlan_registration_outbox`。此事件不等于 Guanlan 空间已经创建；只有可信 Guanlan 接收端返回账户匹配的 `{ "accountId": "...", "registered": true }` 才标记 `delivered`。

管理员可用 `pnpm --filter @uichat-mira/cloud-auth-api admin:dev guanlan-backfill` 补齐旧活跃账户，`guanlan-status` 查看投递状态，`guanlan-retry <username>` 手动恢复待投递事件。调度器可定期运行 `guanlan-deliver`（单次最多 10 项），需在私有运行环境配置 `MIRA_GUANLAN_REGISTRATION_URL` (HTTPS) 与 `MIRA_GUANLAN_REGISTRATION_SECRET` (至少 32 字符)。本卡**不自动启动调度、部署或配置生产密钥**。

接收端合同：POST JSON `{"version":1,"accountId":"<Cloud Auth account UUID>"}`，headers `x-mira-timestamp`（Unix seconds）、`x-mira-signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`。接收端必须验证 timestamp 短窗口、签名、accountId 及重复注册幂等，并在 D1 成功提交后才响应账户匹配的确认 JSON；任何网络错误、非 2xx、错误收据均重试。接收实现属于 Guanlan 独立工程合同，**尚未交付**。

错误重试采用带上限的指数退避；`delivering` 记录超过 60 秒租约可由后续批次重领。禁用/拒绝账户会将未完成记录置为 `withheld`，重新启用可恢复；已完成的远程账户空间不由 Cloud Auth 删除。**跨服务禁用/删除通知、强撤销和观澜端数据清理需后续共同合同**；正式访问仍必须由 Cloud Auth 凭证发行方检查账号活跃状态，不能把本 outbox 当成生产授权。

此卡交付 Cloud Auth 一侧的 durable intent/受控投递，不宣称 A2 双服务全链路已上线。GLN-013 才拥有服务凭证，GLN-014 才验收真实 MCP。
