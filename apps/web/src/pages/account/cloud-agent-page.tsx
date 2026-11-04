import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { useAuthSession } from "@/lib/auth/context";
import { revokeFailedSession } from "@/lib/auth/reauth";

type Schedule = {
  scheduleId: string;
  name: string;
  kind: string;
  status: "active" | "paused" | "completed";
  nextRunAt: string | null;
  timezone: string;
  deliveryTargets: { type: string; label?: string }[];
};
type ResearchRun = {
  runId: string;
  status: string;
  createdAt: string;
  finishedAt: string | null;
  chat?: { channel: string } | null;
};
type AgentStatus = {
  checkedAt: string;
  scheduler: { scheduleCount: number; activeRuns: number; byStatus: Record<string, number> };
  research: { runCount: number };
};
type Envelope<T> = { ok: boolean; data?: T; error?: { code?: string; message?: string } };

class AgentError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

async function agentRequest<T>(
  token: string,
  path: string,
  init: { method?: "GET" | "POST"; signal?: AbortSignal } = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch("/agent-control" + path, {
      method: init.method ?? "GET",
      signal: init.signal,
      headers: {
        authorization: "Bearer " + token,
        accept: "application/json",
      },
      cache: "no-store",
    });
  } catch {
    throw new AgentError("Cloud Agent 控制服务暂时无法连接。", 503);
  }
  let value: Envelope<T>;
  try { value = await response.json() as Envelope<T>; }
  catch { throw new AgentError("控制服务返回了无效响应。", response.status); }
  if (!response.ok || value.ok !== true || value.data === undefined) {
    throw new AgentError(
      response.status === 403
        ? "当前云账号没有烤派管理权限。"
        : response.status === 401
          ? "登录凭证已失效，请重新登录。"
          : value.error?.message ?? "Cloud Agent 暂不可用。",
      response.status,
    );
  }
  return value.data;
}

function dateLabel(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("zh-CN");
}

export function CloudAgentPage() {
  const { getSessionToken, invalidateSession } = useAuthSession();
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [runs, setRuns] = useState<ResearchRun[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const refresh = useCallback(async (signal?: AbortSignal) => {
    const token = getSessionToken();
    if (!token) return;
    try {
      const [snapshot, plans, history] = await Promise.all([
        agentRequest<AgentStatus>(token, "/v1/status", { signal }),
        agentRequest<{ schedules: Schedule[] }>(token, "/v1/schedules", { signal }),
        agentRequest<{ runs: ResearchRun[] }>(token, "/v1/runs?limit=10", { signal }),
      ]);
      if (signal?.aborted) return;
      setStatus(snapshot);
      setSchedules(Array.isArray(plans.schedules) ? plans.schedules : []);
      setRuns(Array.isArray(history.runs) ? history.runs : []);
      setError("");
    } catch (cause) {
      if (signal?.aborted) return;
      if (cause instanceof AgentError && cause.status === 401) {
        revokeFailedSession(token, getSessionToken, invalidateSession);
        return;
      }
      setStatus(null);
      setSchedules([]);
      setRuns([]);
      setError(cause instanceof Error ? cause.message : "控制服务不可用。");
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [getSessionToken, invalidateSession]);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    const interval = window.setInterval(() => {
      if (!document.hidden && busy === null) void refresh();
    }, 15_000);
    return () => { controller.abort(); window.clearInterval(interval); };
  }, [refresh, busy]);

  async function operate(id: string, action: "pause" | "enable" | "run-now") {
    if (busy) return;
    if (action === "run-now" &&
        !window.confirm("现在执行这项研究？会真实调用模型、工具，并可能向已配置目标发送消息。")) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(id);
    setNotice("");
    try {
      await agentRequest<unknown>(token, "/v1/schedules/" + encodeURIComponent(id) + "/" + action, { method: "POST" });
      setNotice(action === "run-now" ? "执行已完成，结果以运行记录为准。" : "计划状态已更新。");
      await refresh();
    } catch (cause) {
      if (cause instanceof AgentError && cause.status === 401) {
        revokeFailedSession(token, getSessionToken, invalidateSession);
      } else setError(cause instanceof Error ? cause.message : "操作失败。");
    } finally { setBusy(null); }
  }

  return (
    <section className="console-page dc-page">
      <header className="console-page-head">
        <Link className="console-section-link dc-back" to="/account/services">关联服务</Link>
        <h1 tabIndex={-1}>Cloud Agent · 烤派</h1>
        <p className="console-page-caption">
          统一查看研究任务与运行状态。只有 Cloud Account 维护者可以操作；飞书和企微的普通聊天权限不会授予管理权。
        </p>
      </header>
      {error ? <p className="cloud-notice cloud-notice-danger" role="alert">{error}</p> : null}
      {notice ? <p className="cloud-notice cloud-notice-success" role="status">{notice}</p> : null}
      <div className="dc-layout">
        <section className="dc-panel" aria-label="Agent 服务状态">
          <div className="dc-panel-head">
            <h2>服务状态</h2>
            <Button variant="ghost" size="sm" disabled={busy !== null} onClick={() => void refresh()}>刷新</Button>
          </div>
          <p className="dc-primary-state">
            <strong>{loading ? "正在读取…" : status ? "控制接口在线" : "尚未连接"}</strong>
          </p>
          <dl className="console-facts dc-facts">
            <div><dt>计划数量</dt><dd>{status?.scheduler.scheduleCount ?? "—"}</dd></div>
            <div><dt>正在执行</dt><dd>{status?.scheduler.activeRuns ?? "—"}</dd></div>
            <div><dt>历史运行</dt><dd>{status?.research.runCount ?? "—"}</dd></div>
            <div><dt>状态更新时间</dt><dd>{dateLabel(status?.checkedAt)}</dd></div>
          </dl>
          <p className="dc-muted">管理接口在线不等于飞书、企微及观澜全部通过真实服务验收。</p>
        </section>
        <section className="dc-panel" aria-labelledby="agent-schedules-heading">
          <div className="dc-panel-head"><h2 id="agent-schedules-heading">研究计划</h2></div>
          {!status ? <p className="dc-muted">连接后显示。</p> : schedules.length === 0
            ? <p className="dc-muted">目前没有计划。</p>
            : <ul className="cloud-service-list">{schedules.map(s => (
              <li className="cloud-service-row" key={s.scheduleId}>
                <div className="cloud-service-row-head">
                  <span className="cloud-service-name">{s.name || s.scheduleId}</span>
                  <span className="cloud-service-pill">{s.status}</span>
                </div>
                <p className="cloud-service-detail">下次运行：{dateLabel(s.nextRunAt)} · {s.timezone} · 投递目标 {s.deliveryTargets.length} 个</p>
                <div className="dc-actions">
                  {s.status !== "completed" ? <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => void operate(s.scheduleId, s.status === "active" ? "pause" : "enable")}>{s.status === "active" ? "暂停" : "启用"}</Button> : null}
                  <Button size="sm" disabled={busy !== null} onClick={() => void operate(s.scheduleId, "run-now")}>{busy === s.scheduleId ? "执行中…" : "立即执行"}</Button>
                </div>
              </li>
            ))}</ul>}
        </section>
        <section className="dc-panel" aria-labelledby="agent-history-heading">
          <div className="dc-panel-head"><h2 id="agent-history-heading">最近运行</h2></div>
          {!status ? <p className="dc-muted">连接后显示。</p> : runs.length === 0
            ? <p className="dc-muted">还没有运行记录。</p>
            : <ul className="cloud-service-list">{runs.map(r => (
              <li className="cloud-service-row" key={r.runId}>
                <div className="cloud-service-row-head">
                  <span className="cloud-service-name">{r.chat?.channel ?? "定时研究"}</span>
                  <span className="cloud-service-pill">{r.status}</span>
                </div>
                <p className="cloud-service-detail">{dateLabel(r.finishedAt ?? r.createdAt)} · {r.runId}</p>
              </li>
            ))}</ul>}
        </section>
      </div>
      <p className="console-note">
        当前只开放状态、计划启停与已有计划的执行。模型密钥、双 IM 凭证与 Guanlan 后台委托需要独立的安全配置写入能力，不能存入浏览器或伪装已接入。
      </p>
    </section>
  );
}
