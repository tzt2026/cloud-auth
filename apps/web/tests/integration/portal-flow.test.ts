import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type Page } from "playwright-core";
import { createServer, type ViteDevServer } from "vite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const webRoot = fileURLToPath(new URL("../..", import.meta.url));
const screenshotDir = join(webRoot, "coverage", "screenshots");
const password = "correct horse battery staple";
const newPassword = "another strong replacement passphrase";
const account = { id: "account-1", username: "pilot" } as const;

// The Portal drops a persisted Cloud Session once its deadline passes, so the
// fake auth server must issue a session that is still live when the run starts.
const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();

const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
] as const;

let authServer: AuthServer;
let server: ViteDevServer;
let browser: Browser;
let baseUrl: string;

beforeAll(async () => {
  mkdirSync(screenshotDir, { recursive: true });
  authServer = await startAuthServer();

  server = await createServer({
    root: webRoot,
    server: {
      host: "127.0.0.1",
      port: 0,
      strictPort: false,
      proxy: {
        "/v1": {
          target: authServer.url,
          changeOrigin: true,
        },
      },
    },
    logLevel: "error",
  });
  await server.listen();

  const localUrl = server.resolvedUrls?.local[0];
  if (!localUrl) {
    throw new Error("Vite dev server did not expose a local URL");
  }
  baseUrl = localUrl.replace(/\/$/, "");

  browser = await chromium.launch(
    process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : { channel: "chrome" },
  );
}, 60_000);

afterAll(async () => {
  await browser?.close();
  await server?.close();
  await authServer?.close();
});

for (const viewport of viewports) {
  describe(`${viewport.name} portal flow`, () => {
    it("captures login, restore, renew, password-change, and expired states", async () => {
      const page = await browser.newPage({
        viewport: { width: viewport.width, height: viewport.height },
      });

      try {
        authServer.reset();
        await page.goto(`${baseUrl}/`, { waitUntil: "load" });
        await page.getByRole("heading", { level: 1, name: "Mira Cloud 账户" }).waitFor();
        await expectNoHorizontalOverflow(page);
        expect(new URL(page.url()).pathname).toBe("/");
        expect(await page.getByLabel("密码").count()).toBe(0);
        await screenshot(page, "home", viewport.name);
        await page.getByRole("main").getByRole("link", { name: "登录 Mira Cloud" }).click();
        await page.waitForURL("**/login");
        await page.locator(".cloud-brand").click();
        await page.waitForURL(`${baseUrl}/`);
        await page.getByRole("main").getByRole("link", { name: "登录 Mira Cloud" }).click();
        await page.getByRole("heading", { level: 1, name: "登录 Mira Cloud" }).waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "logged-out", viewport.name);

        await page.getByLabel("账号").fill("pilot");
        await page.getByLabel("密码").fill(password);
        await page.getByRole("button", { name: "登录" }).click();
        await page.waitForURL("**/account");
        await page.getByText("pilot").first().waitFor();
        await page.getByRole("heading", { name: "我的账户" }).waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "logged-in", viewport.name);
        if (viewport.name === "mobile") {
          await expectStickyMobileNavigation(page);
        }

        await page.goto(`${baseUrl}/`, { waitUntil: "load" });
        await page.getByRole("main").getByRole("link", { name: "进入账户中心" }).waitFor();
        expect(new URL(page.url()).pathname).toBe("/");
        await page.getByRole("main").getByRole("link", { name: "进入账户中心" }).click();
        await page.waitForURL("**/account");

        await page.reload({ waitUntil: "load" });
        await page.getByRole("heading", { level: 1, name: "我的账户" }).waitFor();
        await page.getByText("pilot").first().waitFor();

        // The console shell keeps one rail for all four sections.
        const rail = page.getByRole("navigation", { name: "账户分区" });
        await rail.waitFor();
        expect(await rail.getByRole("link").count()).toBe(4);

        await rail.getByRole("link", { name: "设备与授权" }).click();
        await page.getByRole("heading", { level: 1, name: "设备与授权" }).waitFor();
        await page.getByText("没有可管理的 Desktop Host").waitFor();
        // The execution caveat is stated once, by the page footer.
        await page.getByText(/云端保存成功不等于 Desktop 已立即执行/).waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "devices", viewport.name);

        await rail.getByRole("link", { name: "账户安全" }).click();
        await page.getByRole("heading", { level: 1, name: "账户安全" }).waitFor();
        // Renewal is visible without expanding a disclosure.
        await page.getByRole("button", { name: "续期 Session" }).waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "security", viewport.name);

        await page.getByRole("button", { name: "续期 Session" }).click();
        await page.getByRole("status").waitFor();
        expect(await page.getByRole("status").textContent()).toContain("Cloud Session 已续期");
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "renewed", viewport.name);

        await page.getByRole("button", { name: "修改密码" }).click();
        await page.getByRole("dialog", { name: "修改密码" }).waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "password-form", viewport.name);

        await page.getByLabel("当前密码").fill("wrong current password");
        await page.getByLabel("新密码").fill(newPassword);
        await page.getByRole("button", { name: "确认修改" }).click();
        await page.getByText("账号或密码不正确。").waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "password-error", viewport.name);

        await page.getByLabel("当前密码").fill(password);
        await page.getByLabel("新密码").fill("too short");
        expect(await page.getByRole("button", { name: "确认修改" }).isDisabled()).toBe(true);
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "password-policy-error", viewport.name);

        await page.getByLabel("当前密码").fill(password);
        await page.getByLabel("新密码").fill(newPassword);
        await page.getByRole("button", { name: "确认修改" }).click();
        await page.getByText("密码已修改，请重新登录。").waitFor();
        await page.getByRole("link", { name: "前往登录" }).waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "password-changed", viewport.name);

        await page.getByRole("link", { name: "前往登录" }).click();
        await page.getByLabel("账号").fill("pilot");
        await page.getByLabel("密码").fill(newPassword);
        await page.getByRole("button", { name: "登录" }).click();
        // Re-authentication returns to the protected page from which it began.
        await page.waitForURL("**/account/security");
        await page.getByRole("heading", { name: "账户安全" }).waitFor();
        await page.getByText("pilot").first().waitFor();

        expect(await page.getByRole("button", { name: "退出登录" }).count()).toBe(0);
        await page.getByRole("button", { name: "账户菜单" }).click();
        const accountActions = page.getByRole("group", { name: "账户操作" });
        await accountActions.getByRole("button", { name: "退出登录" }).click();
        await page.waitForURL("**/login");
        await page.getByLabel("账号").waitFor();
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "logged-out-after-logout", viewport.name);

        await page.getByLabel("账号").fill("pilot");
        await page.getByLabel("密码").fill(newPassword);
        await page.getByRole("button", { name: "登录" }).click();
        await page.waitForURL("**/account");
        await page.getByText("pilot").first().waitFor();

        const servicesRail = page.getByRole("navigation", { name: "账户分区" });
        await servicesRail.getByRole("link", { name: "关联服务" }).click();
        await page.getByRole("heading", { level: 1, name: "关联服务" }).waitFor();
        await page.getByText("Cloud Shiyan").waitFor();
        await page.getByText("Hosted Relay").waitFor();
        expect(await page.getByText("尚未接入", { exact: true }).count()).toBe(2);
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "services", viewport.name);

        // Back to the overview so the expired-session screenshot keeps a stable URL.
        await servicesRail.getByRole("link", { name: "概览" }).click();
        await page.getByRole("heading", { level: 1, name: "我的账户" }).waitFor();
        // Let the overview's own grants read settle before expiring the session.
        // A request still in flight would answer 401 after `expireSessions()` and
        // clear the persisted session before the reload, so `restore()` would see
        // no session at all and the recovery copy would lose the expiry detail.
        await page.getByText("Desktop Host").waitFor();

        authServer.expireSessions();
        await page.reload({ waitUntil: "load" });
        await page.getByRole("alert").waitFor();
        expect(await page.getByRole("alert").textContent()).toContain(
          "登录状态已失效或已过期，请重新登录。",
        );
        await expectNoHorizontalOverflow(page);
        await screenshot(page, "expired", viewport.name);
      } finally {
        await page.close();
      }
    }, 60_000);
  });
}

async function expectStickyMobileNavigation(page: Page): Promise<void> {
  const result = await page.evaluate(async () => {
    const main = document.querySelector<HTMLElement>(".console-main");
    const rail = document.querySelector<HTMLElement>(".console-rail");
    if (!main || !rail) throw new Error("Account console is not mounted");
    const oldHeight = main.style.minHeight;
    const height = Math.round(rail.getBoundingClientRect().height);
    main.style.minHeight = "1800px";
    window.scrollTo(0, 400);
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    const top = Math.round(rail.getBoundingClientRect().top);
    const position = getComputedStyle(rail).position;
    main.style.minHeight = oldHeight;
    window.scrollTo(0, 0);
    return { top, height, position };
  });

  expect(result).toEqual({ top: 52, height: 44, position: "sticky" });
}

async function screenshot(page: Page, state: string, viewport: string): Promise<void> {
  await page.screenshot({
    path: join(screenshotDir, `portal-${state}-${viewport}.png`),
    fullPage: true,
  });
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  expect(hasOverflow).toBe(false);
}

interface AuthServer {
  url: string;
  reset(): void;
  expireSessions(): void;
  close(): Promise<void>;
}

async function startAuthServer(): Promise<AuthServer> {
  let activeToken: string | null = null;
  let tokenSequence = 0;
  let currentPassword = password;

  const server = createHttpServer(async (request, response) => {
    if (request.method === "POST" && request.url === "/v1/auth/login") {
      const body = await readJson(request);
      if (body.username !== "pilot" || body.password !== currentPassword) {
        sendAuthError(response, 401, "AUTH_INVALID_CREDENTIALS");
        return;
      }
      activeToken = issueSession(response, (tokenSequence += 1));
      return;
    }

    const token = bearerToken(request);
    if (!token || token !== activeToken) {
      sendAuthError(response, 401, "AUTH_REAUTH_REQUIRED");
      return;
    }

    if (request.method === "GET" && request.url === "/v1/auth/session") {
      sendJson(response, 200, { account, expiresAt });
      return;
    }

    if (request.method === "GET" && request.url === "/v1/hosts") {
      sendJson(response, 200, { hosts: [] });
      return;
    }

    if (request.method === "GET" && request.url === "/v1/hosts/grant-management") {
      sendJson(response, 200, { hosts: [] });
      return;
    }

    if (request.method === "GET" && request.url === "/v1/devices") {
      sendJson(response, 200, { devices: [] });
      return;
    }

    if (request.method === "POST" && request.url === "/v1/auth/session/renew") {
      activeToken = issueSession(response, (tokenSequence += 1));
      return;
    }

    if (request.method === "POST" && request.url === "/v1/auth/password") {
      const body = await readJson(request);
      if (body.currentPassword !== currentPassword) {
        sendAuthError(response, 401, "AUTH_INVALID_CREDENTIALS");
        return;
      }
      if (typeof body.newPassword !== "string" || body.newPassword.length < 15) {
        sendAuthError(response, 400, "AUTH_INVALID_PASSWORD");
        return;
      }

      currentPassword = body.newPassword;
      activeToken = null;
      response.writeHead(204);
      response.end();
      return;
    }

    if (request.method === "POST" && request.url === "/v1/auth/logout") {
      activeToken = null;
      response.writeHead(204);
      response.end();
      return;
    }

    sendAuthError(response, 404, "AUTH_INTERNAL_ERROR");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Mock auth server did not expose a TCP port");
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    reset() {
      currentPassword = password;
      activeToken = null;
      tokenSequence = 0;
    },
    expireSessions() {
      activeToken = null;
    },
    async close() {
      if (!server.listening) return;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function bearerToken(request: IncomingMessage): string | null {
  const authorization = request.headers.authorization;
  const match = authorization ? /^Bearer\s+(.+)$/i.exec(authorization) : null;
  return match?.[1] ?? null;
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function issueSession(response: ServerResponse, sequence: number): string {
  const sessionToken = `mcs_v1.portal-${sequence}.secret`;
  sendJson(response, 200, { sessionToken, account, expiresAt });
  return sessionToken;
}

function sendAuthError(response: ServerResponse, status: number, code: string): void {
  sendJson(response, status, {
    error: { code, message: "Portal test auth error" },
  });
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}
