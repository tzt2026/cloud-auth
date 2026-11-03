import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { CloudAuthClient } from "@/lib/auth/client";
import { CloudAuthError, createAuthFailure } from "@/lib/auth/errors";
import type { HostGrantsClient } from "@/lib/grants/client";
import { createFakeAuthClient, createFakeHostGrantsClient } from "../helpers/host-grants-fixtures";
import { mountPortal, storedSession } from "../helpers/render-portal";

type ConsoleStatus = "authenticated" | "unauthenticated" | "unavailable" | "idle" | "restoring";

const sections = [
  { href: "/account", label: "概览" },
  { href: "/account/devices", label: "设备与授权" },
  { href: "/account/security", label: "账户安全" },
  { href: "/account/services", label: "关联服务" },
] as const;

/** A grants client that records every read so tests can prove none happened. */
function countingGrantsClient(): { client: HostGrantsClient; calls: string[] } {
  const calls: string[] = [];
  const base = createFakeHostGrantsClient();
  const client: HostGrantsClient = {
    ...base,
    listManagement: async (token) => {
      calls.push("listManagement");
      return base.listManagement(token);
    },
    listDevices: async (token) => {
      calls.push("listDevices");
      return base.listDevices(token);
    },
  };
  return { client, calls };
}

function authClientFor(status: ConsoleStatus): CloudAuthClient {
  if (status === "unavailable") {
    return createFakeAuthClient({
      getSession: async () => {
        throw new CloudAuthError(createAuthFailure("service_unavailable"));
      },
    });
  }
  if (status === "restoring") {
    // Never resolves: the shell has to stay in its checking state.
    return createFakeAuthClient({ getSession: () => new Promise<never>(() => undefined) });
  }
  return createFakeAuthClient();
}

function mountConsole({
  path,
  status,
  grantsClient = createFakeHostGrantsClient(),
}: {
  path: string;
  status: ConsoleStatus;
  grantsClient?: HostGrantsClient;
}) {
  return mountPortal({
    path,
    client: authClientFor(status),
    grantsClient,
    session: status === "unauthenticated" ? null : storedSession,
    configure:
      status === "idle"
        ? (store) => {
            // Keep the store in its initial gate: no restore work has happened yet.
            vi.spyOn(store.getState(), "restore").mockImplementation(async () => undefined);
          }
        : undefined,
  });
}

async function consoleNav() {
  const nav = await screen.findByRole("navigation", { name: "账户分区" });
  return nav;
}

describe("console section navigation", () => {
  it.each([
    ["/account", "概览"],
    ["/account/devices", "设备与授权"],
    ["/account/security", "账户安全"],
    ["/account/services", "关联服务"],
    ["/account/services/dc", "关联服务"],
  ] as const)("offers the four sections on %s and marks %s active", async (path, activeLabel) => {
    mountConsole({ path, status: "authenticated" });

    const nav = await consoleNav();
    await waitFor(() => {
      expect(within(nav).getAllByRole("link")).toHaveLength(sections.length);
    });

    const links = within(nav).getAllByRole("link");
    expect(links.map((link) => link.getAttribute("href"))).toEqual(
      sections.map((section) => section.href),
    );
    expect(links.map((link) => link.textContent?.trim())).toEqual(
      sections.map((section) => section.label),
    );

    const active = links.filter((link) => link.getAttribute("aria-current") === "page");
    expect(active).toHaveLength(1);
    expect(active[0]).toHaveTextContent(activeLabel);
  });

  it("shows one logout action only inside the header account dropdown", async () => {
    mountConsole({ path: "/account", status: "authenticated" });
    await screen.findByRole("heading", { level: 1, name: "我的账户" });

    const trigger = screen.getByRole("button", { name: "账户菜单" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: "退出登录" })).not.toBeInTheDocument();
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    const actions = screen.getByRole("group", { name: "账户操作" });
    expect(within(actions).getAllByRole("button", { name: "退出登录" })).toHaveLength(1);
    expect(screen.getByRole("navigation", { name: "账户分区" })).not.toContainElement(actions);
  });

  it("closes the account dropdown with Escape or outside pointer input", async () => {
    mountConsole({ path: "/account", status: "authenticated" });
    const trigger = await screen.findByRole("button", { name: "账户菜单" });

    fireEvent.click(trigger);
    fireEvent.keyDown(trigger, { key: "Escape" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("group", { name: "账户操作" })).not.toBeInTheDocument();

    fireEvent.click(trigger);
    fireEvent.pointerDown(document.body);
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: "退出登录" })).not.toBeInTheDocument();
  });

  it("leaves Escape outside the account menu to the rest of the page", async () => {
    mountConsole({ path: "/account", status: "authenticated" });
    const trigger = await screen.findByRole("button", { name: "账户菜单" });

    fireEvent.click(trigger);
    // Another overlay owns Escape while focus is elsewhere; the account menu
    // must not swallow the key or steal focus back to its trigger.
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(trigger).not.toHaveFocus();
  });

  it.each(["unauthenticated", "unavailable", "idle", "restoring"] as const)(
    "never offers section links while %s",
    async (status) => {
      mountConsole({ path: "/account/devices", status });

      const nav = await consoleNav();
      expect(within(nav).queryAllByRole("link")).toHaveLength(0);
      expect(screen.queryAllByRole("button", { name: "退出登录" })).toHaveLength(0);
    },
  );

  it("explains a deep link instead of mounting the page while signed out", async () => {
    const { client, calls } = countingGrantsClient();
    const { router } = mountConsole({
      path: "/account/devices",
      status: "unauthenticated",
      grantsClient: client,
    });

    expect(await screen.findByRole("heading", { level: 1, name: "我的账户" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "前往登录" })).toHaveAttribute(
      "href",
      "/login?returnTo=%2Faccount%2Fdevices",
    );

    // The route is preserved; only the content inside the shell is the recovery.
    expect(router.state.location.pathname).toBe("/account/devices");
    expect(screen.queryByRole("heading", { level: 1, name: "设备与授权" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "刷新列表" })).not.toBeInTheDocument();

    // No grant read may be attempted without a confirmed session.
    await waitFor(() => expect(calls).toEqual([]));
  });

  it("keeps the grants reads to the console pages themselves", async () => {
    const { client, calls } = countingGrantsClient();
    mountConsole({ path: "/account/devices", status: "authenticated", grantsClient: client });

    expect(
      await screen.findByRole("heading", { level: 1, name: "设备与授权" }),
    ).toBeInTheDocument();
    await waitFor(() => expect(calls).toContain("listManagement"));
  });
});
