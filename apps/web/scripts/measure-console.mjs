// Console IA verification pass: screenshots + numeric UI metrics (computed styles,
// geometry, contrast, tap targets, ARIA state) for every account route.
//
// Preconditions:
//   1. an API on :8788 serving a database with a provisioned account that owns at
//      least one Desktop Host and one Mobile grant (see docs/ui/redesign-verification.md),
//   2. `pnpm --filter @uichat-mira/cloud-auth-web run build` and `run preview` (:4173).
//
// Usage:
//   $env:MEASURE_USER="verify.user"; $env:MEASURE_PASS="<password>"
//   node apps/web/scripts/measure-console.mjs
//
// Output: .screenshots/after-ia/ (PNG per route x viewport + metrics.json).
import { mkdirSync, writeFileSync } from "node:fs";
import { chromium } from "playwright-core";

const BASE = process.env.MEASURE_BASE ?? "http://127.0.0.1:4173";
const OUT = process.env.MEASURE_OUT ?? ".screenshots/after-ia";
const USER = process.env.MEASURE_USER ?? "";
const PASS = process.env.MEASURE_PASS ?? "";

if (!USER || !PASS) {
  console.error("Set MEASURE_USER and MEASURE_PASS to a provisioned Mira Cloud account.");
  process.exit(2);
}

mkdirSync(OUT, { recursive: true });

const routes = [
  { path: "/login", name: "login", anon: true },
  { path: "/account", name: "overview" },
  { path: "/account/devices", name: "devices" },
  { path: "/account/security", name: "security" },
  { path: "/account/services", name: "services" },
  { path: "/account/unknown-section", name: "console-404", h1: "页面不存在" },
  { path: "/account", name: "recovery", anon: true, h1: "我的账户" },
  { path: "/missing-route", name: "public-404", anon: true, h1: "页面不存在" },
];

const viewports = [
  { name: "1440x900", width: 1440, height: 900, full: true },
  { name: "1280x800", width: 1280, height: 800, full: false },
  { name: "1024x768", width: 1024, height: 768, full: false },
  { name: "768x1024", width: 768, height: 768, full: false },
  { name: "390x844", width: 390, height: 844, full: true },
];

const measure = () => {
  const visible = (el) => {
    const s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden" || s.opacity === "0") return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };

  const parseColor = (value) => {
    const m = /rgba?\(([^)]+)\)/.exec(value);
    if (!m) return null;
    const parts = m[1].split(",").map((p) => Number.parseFloat(p.trim()));
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const blend = (top, bottom) => ({
    r: top.r * top.a + bottom.r * (1 - top.a),
    g: top.g * top.a + bottom.g * (1 - top.a),
    b: top.b * top.a + bottom.b * (1 - top.a),
    a: 1,
  });
  const backgroundOf = (el) => {
    let stack = [];
    let node = el;
    while (node && node !== document.documentElement) {
      const c = parseColor(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0) {
        stack.push(c);
        if (c.a === 1) break;
      }
      node = node.parentElement;
    }
    const base = { r: 255, g: 255, b: 255, a: 1 };
    return stack.reverse().reduce((acc, c) => blend(c, acc), base);
  };
  const luminance = (c) => {
    const f = (v) => {
      const x = v / 255;
      return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const contrast = (fg, bg) => {
    const fgL = luminance(fg);
    const bgL = luminance(bg);
    const light = Math.max(fgL, bgL);
    const dark = Math.min(fgL, bgL);
    return (light + 0.05) / (dark + 0.05);
  };

  const textSamples = [];
  const histogram = {};
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    const text = (node.textContent || "").trim();
    if (!text) continue;
    const el = node.parentElement;
    if (!el || !visible(el)) continue;
    const s = getComputedStyle(el);
    const size = Math.round(Number.parseFloat(s.fontSize) * 10) / 10;
    histogram[size] = (histogram[size] || 0) + 1;
    const fg = parseColor(s.color);
    if (!fg) continue;
    const bg = backgroundOf(el);
    textSamples.push({
      text: text.slice(0, 40),
      size,
      weight: s.fontWeight,
      fg: `rgba(${Math.round(fg.r)},${Math.round(fg.g)},${Math.round(fg.b)},${fg.a})`,
      bg: `rgb(${Math.round(bg.r)},${Math.round(bg.g)},${Math.round(bg.b)})`,
      contrast: Math.round(contrast(blend(fg, bg), bg) * 100) / 100,
    });
  }

  const tapTargets = [];
  const interactive = document.querySelectorAll(
    'a[href], button, summary, [role="button"], [role="link"], input, select',
  );
  for (const el of interactive) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    const label = (
      el.getAttribute("aria-label") ||
      el.textContent ||
      el.getAttribute("placeholder") ||
      el.tagName
    )
      .trim()
      .slice(0, 30);
    tapTargets.push({ label, w: Math.round(r.width), h: Math.round(r.height) });
  }

  const metricsOf = (selector) => {
    const el = document.querySelector(selector);
    if (!el) return null;
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return {
      width: Math.round(r.width),
      height: Math.round(r.height),
      fontSize: s.fontSize,
      fontWeight: s.fontWeight,
      color: s.color,
    };
  };

  const h1 = document.querySelector("h1");
  const nav = document.querySelector(".console-nav");
  const navLinks = nav ? [...nav.querySelectorAll("a")] : [];
  const h2s = [...document.querySelectorAll("h2")].map((h) => h.textContent.trim());
  const fonts = Object.keys(histogram)
    .map(Number)
    .sort((a, b) => a - b);

  return {
    h1: h1 ? h1.textContent.trim() : null,
    h1Metrics: metricsOf("h1"),
    caption: document.querySelector(".console-page-caption")?.textContent.trim() ?? null,
    captionMetrics: metricsOf(".console-page-caption"),
    h2s,
    navLinks: navLinks.map((a) => ({
      label: a.textContent.trim(),
      href: a.getAttribute("href"),
      current: a.getAttribute("aria-current"),
    })),
    publicNavLinks: [...document.querySelectorAll(".cloud-navigation a")].map((a) =>
      a.textContent.trim(),
    ),
    roles: {
      status: document.querySelectorAll('[role="status"]').length,
      alert: document.querySelectorAll('[role="alert"]').length,
      dialog: document.querySelectorAll("dialog").length,
    },
    counts: {
      logoutButtons: [...document.querySelectorAll("button")].filter(
        (b) => b.textContent.trim() === "退出登录",
      ).length,
      details: document.querySelectorAll("details").length,
      cards: document.querySelectorAll('[data-slot="card"]').length,
      totalNodes: document.querySelectorAll("*").length,
    },
    geometry: {
      header: metricsOf(".console-header") ?? metricsOf(".cloud-header"),
      rail: metricsOf(".console-rail"),
      navLink: metricsOf(".console-nav-link"),
      main: metricsOf(".console-main"),
      body: metricsOf(".console-body"),
      section: metricsOf(".console-section"),
      factsRow: metricsOf(".console-facts > div"),
      firstSectionHead: metricsOf(".console-section-head"),
    },
    overflow: {
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
      delta: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    },
    fontHistogram: histogram,
    fontSizes: fonts,
    minFontSize: fonts.length ? fonts[0] : null,
    textUnder13: textSamples.filter((t) => t.size < 13).length,
    textSamples: textSamples.length,
    contrastFailures: textSamples.filter((t) => t.contrast < 4.5),
    minContrast: textSamples.length
      ? Math.round(Math.min(...textSamples.map((t) => t.contrast)) * 100) / 100
      : null,
    tapTargetsUnder40: tapTargets.filter((t) => t.h < 40 || t.w < 40),
    tapTargets: tapTargets.length,
  };
};

const browser = await chromium.launch({ channel: "chrome" });
const report = { base: BASE, generatedAt: new Date().toISOString(), routes: {} };
const consoleErrors = [];

for (const viewport of viewports) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
  });
  const page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(`${viewport.name}: ${message.text()}`);
  });
  page.on("pageerror", (error) =>
    consoleErrors.push(`${viewport.name}: pageerror ${error.message}`),
  );

  // Log in once per viewport (the session is persisted in localStorage).
  await page.goto(`${BASE}/login`, { waitUntil: "networkidle" });
  await page.getByLabel("账号").fill(USER);
  await page.getByLabel("密码").fill(PASS);
  await page.getByRole("button", { name: "登录" }).click();
  await page.getByRole("heading", { level: 1, name: "我的账户" }).waitFor({ timeout: 15000 });

  for (const route of routes) {
    if (route.anon) {
      // Fresh context: no persisted session, so the recovery / public states are real.
      const anon = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
      });
      const anonPage = await anon.newPage();
      anonPage.on("console", (message) => {
        if (message.type() === "error")
          consoleErrors.push(`${viewport.name} anon: ${message.text()}`);
      });
      await anonPage.goto(`${BASE}${route.path}`, { waitUntil: "networkidle" });
      if (route.h1) {
        await anonPage
          .getByRole("heading", { level: 1, name: route.h1 })
          .waitFor({ timeout: 15000 });
      } else {
        await anonPage.waitForSelector("h1");
      }
      await anonPage.waitForTimeout(250);
      const file = `${OUT}/${route.name}-${viewport.name}.png`;
      if (viewport.full) {
        await anonPage.screenshot({ path: file, fullPage: true });
      } else {
        await anonPage.screenshot({ path: file });
      }
      report.routes[`${route.name}@${viewport.name}`] = await anonPage.evaluate(measure);
      await anon.close();
      continue;
    }

    await page.goto(`${BASE}${route.path}`, { waitUntil: "networkidle" });
    if (route.h1) {
      await page.getByRole("heading", { level: 1, name: route.h1 }).waitFor({ timeout: 15000 });
    } else {
      await page.getByRole("heading", { level: 1 }).first().waitFor({ timeout: 15000 });
    }
    await page.waitForTimeout(250);
    const file = `${OUT}/${route.name}-${viewport.name}.png`;
    if (viewport.full) {
      await page.screenshot({ path: file, fullPage: true });
    } else {
      await page.screenshot({ path: file });
    }
    report.routes[`${route.name}@${viewport.name}`] = await page.evaluate(measure);
  }

  await context.close();
}

// Interaction states worth one screenshot each: password dialog + row hover/focus.
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
await page.goto(`${BASE}/login`, { waitUntil: "networkidle" });
await page.getByLabel("账号").fill(USER);
await page.getByLabel("密码").fill(PASS);
await page.getByRole("button", { name: "登录" }).click();
await page.getByRole("heading", { level: 1, name: "我的账户" }).waitFor();
await page.goto(`${BASE}/account/security`, { waitUntil: "networkidle" });
await page.getByRole("button", { name: "修改密码" }).click();
await page.getByRole("dialog").waitFor();
await page.waitForTimeout(250);
await page.screenshot({ path: `${OUT}/security-dialog-1440x900.png` });
await page.keyboard.press("Escape");

// Keyboard focus ring on the active rail link, for the focus-visibility evidence.
await page.goto(`${BASE}/account/devices`, { waitUntil: "networkidle" });
await page.keyboard.press("Tab");
await page.keyboard.press("Tab");
const focusInfo = await page.evaluate(() => {
  const el = document.activeElement;
  if (!el) return null;
  const s = getComputedStyle(el);
  return {
    tag: el.tagName,
    text: (el.textContent || "").trim().slice(0, 20),
    outlineColor: s.outlineColor,
    outlineWidth: s.outlineWidth,
    outlineStyle: s.outlineStyle,
    outlineOffset: s.outlineOffset,
  };
});
report.focus = focusInfo;
await page.screenshot({ path: `${OUT}/devices-focus-1440x900.png` });

await context.close();
await browser.close();

report.consoleErrors = [...new Set(consoleErrors)];
writeFileSync(`${OUT}/metrics.json`, JSON.stringify(report, null, 2));

const lines = [];
for (const [key, value] of Object.entries(report.routes)) {
  lines.push(
    `${key.padEnd(22)} h1=${String(value.h1).padEnd(6)} nav=${value.navLinks.length} link|aria-current=${value.navLinks.find((l) => l.current)?.label ?? "-"} status=${value.roles.status} alert=${value.roles.alert} dialog=${value.roles.dialog} logout=${value.counts.logoutButtons} details=${value.counts.details} overflow=${value.overflow.delta} minFont=${value.minFontSize} <13px=${value.textUnder13}/${value.textSamples} minContrast=${value.minContrast} fail=${value.contrastFailures.length} tap<40=${value.tapTargetsUnder40.length}/${value.tapTargets}`,
  );
}
console.log(lines.join("\n"));
console.log(`\nfocus: ${JSON.stringify(report.focus)}`);
console.log(`console errors: ${report.consoleErrors.length}`);
