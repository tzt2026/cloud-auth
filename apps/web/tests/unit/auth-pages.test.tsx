import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { routes } from "@/app/routes";
import type { CloudAuthClient } from "@/lib/auth/client";
import { AuthProvider } from "@/lib/auth/context";
import { CloudAuthError, createAuthFailure } from "@/lib/auth/errors";
import { createAuthStore } from "@/lib/auth/store";
import { formatExpiry } from "@/lib/format";
import { HostGrantsProvider } from "@/lib/grants/context";
import { createFakeHostGrantsClient } from "../helpers/host-grants-fixtures";
import { createMemoryStorage } from "../helpers/session-storage";
import { account, expiresAt, issuedSession } from "../helpers/auth-fixtures";

function createClient(overrides: Partial<CloudAuthClient> = {}): CloudAuthClient {
  return {
    login: async () => issuedSession("token-1"),
    getSession: async () => ({ account, expiresAt }),
    renewSession: async () => issuedSession("token-2"),
    changePassword: async () => undefined,
    logout: async () => undefined,
    ...overrides,
  };
}

function emptyGrantsClient() {
  return createFakeHostGrantsClient({
    listManagement: async () => [],
    listDevices: async () => [],
  });
}

function renderWithClient({
  client,
  initialSession = null,
  path,
}: {
  client: CloudAuthClient;
  initialSession?: { sessionToken: string; expiresAt: string } | null;
  path: string;
}) {
  const storage = createMemoryStorage(initialSession);
  const store = createAuthStore({ client, storage });
  const router = createMemoryRouter(routes, { initialEntries: [path] });

  render(
    <AuthProvider store={store}>
      <HostGrantsProvider client={emptyGrantsClient()}>
        <RouterProvider router={router} />
      </HostGrantsProvider>
    </AuthProvider>,
  );

  return { storage, store, router };
}

/**
 * `pilot` now appears in the header identity chip, the page caption and the
 * account facts, so no single query is unique. Assert that the signed-in
 * identity rendered at all rather than pinning the query to one node.
 */
async function findIdentity() {
  const matches = await screen.findAllByText("pilot");
  return matches[0];
}

describe("auth-backed route components", () => {
  it("submits login through the session store and logs out without touching fetch or tokens", async () => {
    const loginCalls: Array<{ username: string; password: string }> = [];
    let logoutToken: string | null = null;

    const client: CloudAuthClient = {
      login: async (request) => {
        loginCalls.push(request);
        return issuedSession("token-1");
      },
      getSession: async () => ({ account, expiresAt }),
      renewSession: async () => issuedSession("token-2"),
      changePassword: async () => undefined,
      logout: async (token) => {
        logoutToken = token;
      },
    };

    const storage = createMemoryStorage();
    const store = createAuthStore({ client, storage });
    const router = createMemoryRouter(routes, { initialEntries: ["/login"] });

    render(
      <AuthProvider store={store}>
        <HostGrantsProvider client={emptyGrantsClient()}>
          <RouterProvider router={router} />
        </HostGrantsProvider>
      </AuthProvider>,
    );

    fireEvent.change(screen.getByLabelText("账号"), {
      target: { value: "pilot" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/account");
    });
    expect(await findIdentity()).toBeInTheDocument();
    expect(loginCalls).toEqual([{ username: "pilot", password: "correct horse battery staple" }]);
    expect(storage.load()?.sessionToken).toBe("token-1");

    fireEvent.click(screen.getByRole("button", { name: "账户菜单" }));
    fireEvent.click(screen.getByRole("button", { name: "退出登录" }));

    await waitFor(() => {
      expect(logoutToken).toBe("token-1");
      expect(storage.load()).toBeNull();
      expect(router.state.location.pathname).toBe("/login");
    });
    expect(await screen.findByRole("button", { name: "登录" })).toBeInTheDocument();
  });

  it("keeps login focused on the form and browser session note", () => {
    renderWithClient({ client: createClient(), path: "/login" });

    expect(screen.getByText(/登录状态仅保存在此浏览器/)).toBeInTheDocument();
    expect(screen.queryByText("欢迎回来。")).not.toBeInTheDocument();
    expect(screen.queryByText("Cloud Shiyan")).not.toBeInTheDocument();
    expect(screen.queryByText("Hosted Relay")).not.toBeInTheDocument();
    expect(screen.queryByText(/只是想查看账户页面/)).not.toBeInTheDocument();
  });

  it("disables submission with a pending label while login is in flight", async () => {
    let resolveLogin: () => void = () => undefined;
    const pendingLogin = new Promise<void>((resolve) => {
      resolveLogin = resolve;
    });

    const { router } = renderWithClient({
      client: createClient({
        login: async () => {
          await pendingLogin;
          return issuedSession("token-1");
        },
      }),
      path: "/login",
    });

    fireEvent.change(screen.getByLabelText("账号"), {
      target: { value: "pilot" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByRole("button", { name: "登录中…" })).toBeDisabled();
    expect(router.state.location.pathname).toBe("/login");

    resolveLogin();

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/account");
    });
  });

  it("shows restoring feedback before redirecting an existing session", async () => {
    let resolveSession: () => void = () => undefined;
    const pendingSession = new Promise<void>((resolve) => {
      resolveSession = resolve;
    });

    const { router } = renderWithClient({
      client: createClient({
        getSession: async () => {
          await pendingSession;
          return { account, expiresAt };
        },
      }),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/login",
    });

    expect(await screen.findByText("正在恢复登录状态…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "登录" })).toBeDisabled();

    resolveSession();

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/account");
    });
  });

  it("renders invalid credentials as a readable login failure", async () => {
    const { storage } = renderWithClient({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(
            createAuthFailure("invalid_credentials", {
              status: 401,
              code: "AUTH_INVALID_CREDENTIALS",
            }),
          );
        },
      }),
      path: "/login",
    });

    fireEvent.change(screen.getByLabelText("账号"), {
      target: { value: "pilot" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("账号或密码不正确。");
    expect(screen.getByRole("button", { name: "登录" })).toBeEnabled();
    expect(storage.load()).toBeNull();
  });

  it("renders a distinct network-unavailable failure", async () => {
    renderWithClient({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(createAuthFailure("network_unavailable"));
        },
      }),
      path: "/login",
    });

    fireEvent.change(screen.getByLabelText("账号"), {
      target: { value: "pilot" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "无法连接认证服务，请检查网络后重试。",
    );
  });

  it("summarises the account, the grant counts and the not-yet-connected services on the overview", async () => {
    renderWithClient({
      client: createClient(),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account",
    });

    expect(await screen.findByRole("heading", { level: 1, name: "我的账户" })).toBeInTheDocument();
    await findIdentity();

    // Account facts: the identifier is visible without expanding anything.
    expect(screen.getByText("账号")).toBeInTheDocument();
    expect(screen.getByText("Account ID")).toBeInTheDocument();
    expect(screen.getByText("account-1")).toBeInTheDocument();
    expect(screen.getByText("登录状态")).toBeInTheDocument();
    expect(screen.getByText("会话到期")).toBeInTheDocument();
    expect(screen.getAllByText(formatExpiry(expiresAt)).length).toBeGreaterThan(0);

    // Section links own the detail pages instead of duplicating them.
    expect(screen.getByRole("link", { name: "管理会话" })).toHaveAttribute(
      "href",
      "/account/security",
    );
    expect(screen.getByRole("link", { name: "管理" })).toHaveAttribute("href", "/account/devices");
    expect(screen.getByRole("link", { name: "查看" })).toHaveAttribute("href", "/account/services");

    // Grant counts come from the same controller the devices page uses.
    const counts = await screen.findByRole("list");
    expect(within(counts).getByText("Desktop Host")).toBeInTheDocument();
    expect(within(counts).getByText("手机设备")).toBeInTheDocument();
    expect(within(counts).getByText("有效授权")).toBeInTheDocument();
    expect(within(counts).getAllByRole("listitem")).toHaveLength(3);

    expect(screen.getByText("4 项服务 · 2 项尚未接入")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "关联服务" })).toBeInTheDocument();
  });

  it("lists the owned device records on the devices route with one page-level caveat", async () => {
    const { router } = renderWithClient({
      client: createClient(),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/devices",
    });

    expect(
      await screen.findByRole("heading", { level: 1, name: "设备与授权" }),
    ).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/account/devices");
    expect(screen.getByRole("button", { name: "刷新列表" })).toBeInTheDocument();

    expect(await screen.findByText("没有可管理的 Desktop Host")).toBeInTheDocument();

    // The execution caveat lives once on the page, not inside every record card.
    const caveats = screen.getAllByText(/云端保存成功不等于 Desktop 已立即执行/);
    expect(caveats).toHaveLength(1);
    expect(caveats[0]?.closest("[data-slot='card']")).toBeNull();
  });

  it("shows the password action and this browser's session on the security route", async () => {
    renderWithClient({
      client: createClient(),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/security",
    });

    expect(await screen.findByRole("heading", { level: 1, name: "账户安全" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "密码" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "修改密码" })).toBeInTheDocument();

    expect(screen.getByRole("heading", { level: 2, name: "当前登录会话" })).toBeInTheDocument();
    // Renewal has to be reachable without expanding a disclosure.
    expect(screen.getByRole("button", { name: "续期 Session" })).toBeEnabled();
    expect(screen.getByText("状态")).toBeInTheDocument();
    expect(screen.getByText("到期时间")).toBeInTheDocument();
    expect(screen.getAllByText("已登录").length).toBeGreaterThan(0);
    expect(screen.getAllByText(formatExpiry(expiresAt)).length).toBeGreaterThan(0);
  });

  it("lists DC alongside other services without introducing a second login or navigation area", async () => {
    renderWithClient({
      client: createClient(),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/services",
    });

    expect(await screen.findByRole("heading", { level: 1, name: "关联服务" })).toBeInTheDocument();

    const services = screen.getByRole("list");
    expect(within(services).getAllByRole("listitem")).toHaveLength(4);
    expect(within(services).getByText("DC 控制台")).toBeInTheDocument();
    expect(within(services).getByText("Cloud Agent · 烤派")).toBeInTheDocument();
    expect(within(services).getByRole("link", { name: "进入 Cloud Agent · 烤派" })).toHaveAttribute("href", "/account/services/cloud-agent");
    expect(within(services).getByText("Cloud Shiyan")).toBeInTheDocument();
    expect(within(services).getByText("Hosted Relay")).toBeInTheDocument();
    expect(within(services).getAllByText("尚未接入")).toHaveLength(2);

    // The migrated DC page must stay inside the same account route and session.
    const dcLink = within(services).getByRole("link", { name: "进入 DC 控制台" });
    expect(dcLink).toHaveAttribute("href", "/account/services/dc");
    expect(dcLink).not.toHaveAttribute("target");

    // The account navigation and page heading remain single instances.
    expect(screen.getAllByRole("navigation", { name: "账户分区" })).toHaveLength(1);
    expect(screen.queryAllByRole("heading", { level: 2 })).toHaveLength(0);
  });

  it("confirms an explicit session renewal without leaving the security route", async () => {
    const { storage, router } = renderWithClient({
      client: createClient({
        renewSession: async () => issuedSession("token-2"),
      }),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/security",
    });

    await findIdentity();

    fireEvent.click(screen.getByRole("button", { name: "续期 Session" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Cloud Session 已续期");
    await waitFor(() => {
      expect(storage.load()?.sessionToken).toBe("token-2");
    });
    expect(router.state.location.pathname).toBe("/account/security");
    expect(screen.getByRole("heading", { level: 1, name: "账户安全" })).toBeInTheDocument();
  });

  it("keeps password fields in a dismissible dialog and clears them on cancel", async () => {
    renderWithClient({
      client: createClient(),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/security",
    });

    await findIdentity();
    expect(screen.queryByLabelText("当前密码")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "修改密码" }));

    expect(screen.getByRole("dialog", { name: "修改密码" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("当前密码"), {
      target: { value: "an example old password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(screen.queryByRole("dialog", { name: "修改密码" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "修改密码" }));
    expect(screen.getByLabelText("当前密码")).toHaveValue("");
  });

  it("submits a password change, shows pending state, and forces re-login", async () => {
    let resolveChange: () => void = () => undefined;
    const pendingChange = new Promise<void>((resolve) => {
      resolveChange = resolve;
    });
    const calls: Array<{
      token: string;
      currentPassword: string;
      newPassword: string;
    }> = [];

    const { storage } = renderWithClient({
      client: createClient({
        changePassword: async (token, request) => {
          calls.push({ token, ...request });
          await pendingChange;
        },
      }),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/security",
    });

    await findIdentity();
    fireEvent.click(screen.getByRole("button", { name: "修改密码" }));
    expect(screen.getByRole("dialog", { name: "修改密码" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("当前密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "another strong replacement passphrase" },
    });
    fireEvent.click(screen.getByRole("button", { name: "确认修改" }));

    expect(await screen.findByRole("button", { name: "修改中…" })).toBeDisabled();

    resolveChange();

    expect(await screen.findByText("密码已修改，请重新登录。")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "前往登录" })).toHaveAttribute(
      "href",
      "/login?returnTo=%2Faccount%2Fsecurity",
    );
    expect(screen.queryByLabelText("当前密码")).not.toBeInTheDocument();
    expect(calls).toEqual([
      {
        token: "token-1",
        currentPassword: "correct horse battery staple",
        newPassword: "another strong replacement passphrase",
      },
    ]);
    await waitFor(() => {
      expect(storage.load()).toBeNull();
    });
  });

  it("shows an incorrect-current-password error without ending the session", async () => {
    const { storage } = renderWithClient({
      client: createClient({
        changePassword: async () => {
          throw new CloudAuthError(
            createAuthFailure("invalid_credentials", {
              status: 401,
              code: "AUTH_INVALID_CREDENTIALS",
            }),
          );
        },
      }),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/security",
    });

    await findIdentity();
    fireEvent.click(screen.getByRole("button", { name: "修改密码" }));
    const dialog = screen.getByRole("dialog", { name: "修改密码" });
    fireEvent.change(screen.getByLabelText("当前密码"), {
      target: { value: "wrong current password" },
    });
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "another strong replacement passphrase" },
    });
    fireEvent.click(screen.getByRole("button", { name: "确认修改" }));

    // While the dialog is open it owns the alert region: the console must not
    // answer the same failure twice.
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("账号或密码不正确。");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByLabelText("当前密码")).toBeInTheDocument();
    expect(storage.load()).toEqual({ sessionToken: "token-1", expiresAt });
  });

  it("shows a password-policy error without revoking the session", async () => {
    const { storage } = renderWithClient({
      client: createClient({
        changePassword: async () => {
          throw new CloudAuthError(
            createAuthFailure("invalid_password", {
              status: 400,
              code: "AUTH_INVALID_PASSWORD",
            }),
          );
        },
      }),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account/security",
    });

    await findIdentity();
    fireEvent.click(screen.getByRole("button", { name: "修改密码" }));
    const dialog = screen.getByRole("dialog", { name: "修改密码" });
    fireEvent.change(screen.getByLabelText("当前密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "a long but rejected new password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "确认修改" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "新密码不符合密码策略，请使用至少 15 个字符的新密码。",
    );
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByLabelText("当前密码")).toBeInTheDocument();
    expect(storage.load()).toEqual({ sessionToken: "token-1", expiresAt });
  });

  it("returns to the logged-out account view with an expired-session explanation", async () => {
    const { storage } = renderWithClient({
      client: createClient({
        getSession: async () => {
          throw new CloudAuthError(
            createAuthFailure("reauth_required", {
              status: 401,
              code: "AUTH_REAUTH_REQUIRED",
            }),
          );
        },
      }),
      initialSession: { sessionToken: "token-1", expiresAt },
      path: "/account",
    });

    expect(await screen.findByText("登录状态已失效或已过期，请重新登录。")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "前往登录" })).toHaveAttribute("href", "/login");
    expect(storage.load()).toBeNull();
  });

  it("renders rate limiting with a retry hint", async () => {
    const { storage } = renderWithClient({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(createAuthFailure("rate_limited", { retryAfterSeconds: 30 }));
        },
      }),
      path: "/login",
    });

    fireEvent.change(screen.getByLabelText("账号"), {
      target: { value: "pilot" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "尝试次数过多，请稍后再试。（约 30 秒后可重试）",
    );
    expect(storage.load()).toBeNull();
  });

  it("renders a distinct service-unavailable failure", async () => {
    renderWithClient({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(createAuthFailure("service_unavailable"));
        },
      }),
      path: "/login",
    });

    fireEvent.change(screen.getByLabelText("账号"), {
      target: { value: "pilot" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByText("认证服务暂时不可用，请稍后重试。")).toBeInTheDocument();
  });
});
