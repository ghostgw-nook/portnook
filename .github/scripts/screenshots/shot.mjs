// Screenshot driver for .github/scripts/screenshots.sh. Runs inside a headless Chromium container that shares
// the network namespace of an agent (so http://127.0.0.1:8090 is that agent's UI). Talks to Chromium over the
// DevTools protocol with Node's built-in WebSocket (node --experimental-websocket), no npm packages.
//   node shot.mjs <scenario> [args...]   scenarios: svg, wizard, status, cert, redirect, push
// Screenshots go to /out, a printed "RESULT <value>" line returns data to the shell script.
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const BASE = "http://127.0.0.1:8090";
const PORT = 9333;
const W = 1280, H = 800;
const [scenario, ...args] = process.argv.slice(2);
const AGENT_PW = process.env.AGENT_PW || "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn("chromium-browser", ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
  "--hide-scrollbars", "--lang=de-CH", `--remote-debugging-port=${PORT}`, `--window-size=${W},${H}`, "about:blank"],
  { stdio: "ignore" });

let ws, seq = 0;
const pending = new Map();
function send(method, params = {}) {
  const id = ++seq;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject, method }));
}
async function connect() {
  let target;
  for (let i = 0; i < 50 && !target; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      target = list.find((t) => t.type === "page");
    } catch (e) { await sleep(200); }
  }
  if (!target) throw new Error("chromium did not start");
  ws = new WebSocket(target.webSocketDebuggerUrl);
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id); pending.delete(msg.id);
      msg.error ? p.reject(new Error(p.method + ": " + msg.error.message)) : p.resolve(msg.result);
    }
  };
  await new Promise((r) => (ws.onopen = r));
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  // headless Chromium ignores --lang for navigator.languages; the UI follows the browser language since 0.26
  const { userAgent } = await send("Browser.getVersion");
  await send("Network.setUserAgentOverride", { userAgent, acceptLanguage: "de-CH,de" });
}

async function js(expr) {
  const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error("js: " + (r.exceptionDetails.exception?.description || expr));
  return r.result.value;
}
async function waitFor(expr, ms = 20000, what = expr) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { if (await js(expr)) return; } catch (e) { /* page still loading */ }
    await sleep(250);
  }
  throw new Error("timeout waiting for " + what);
}
async function nav(url) { await send("Page.navigate", { url }); await sleep(800); }
const q = (s) => JSON.stringify(s);
async function fill(sel, value) {
  await js(`(() => { const e = document.querySelector(${q(sel)}); e.value = ${q(value)};
    e.dispatchEvent(new Event("input", { bubbles: true })); e.dispatchEvent(new Event("change", { bubbles: true })); })()`);
}
async function click(sel) { await js(`document.querySelector(${q(sel)}).click()`); }
async function clickText(sel, text) {
  await js(`[...document.querySelectorAll(${q(sel)})].find((e) => e.textContent.trim() === ${q(text)}).click()`);
}
const visible = (sel) => `(() => { const e = document.querySelector(${q(sel)}); return !!e && e.offsetParent !== null; })()`;
const hasText = (sel, text) => `(document.querySelector(${q(sel)})?.textContent || "").includes(${q(text)})`;

async function shot(name, { full = false } = {}) {
  await js("document.activeElement && document.activeElement.blur()");
  await js("window.scrollTo(0, 0)");
  await sleep(400);
  // viewport shots end below the content (no empty area), full shots cover the whole page
  let height = Math.min(H, Math.max(360, await js(`Math.ceil(document.querySelector("main").getBoundingClientRect().bottom + 24)`)));
  if (full) {
    height = Math.max(H, await js("Math.ceil(document.documentElement.scrollHeight)"));
    await send("Emulation.setDeviceMetricsOverride", { width: W, height, deviceScaleFactor: 1, mobile: false });
    await sleep(400);
  }
  const r = await send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: W, height, scale: 1 } });
  writeFileSync(`/out/${name}.png`, Buffer.from(r.data, "base64"));
  if (full) await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  console.log("shot " + name);
}

// Agent login (password already set). Lands on the status page.
async function agentLogin(path = "/") {
  await nav(BASE + path);
  await waitFor(visible("#login-pw"), 20000, "agent login");
  await fill("#login-pw", AGENT_PW);
  await click("#f-login button.primary");
  await waitFor(`!document.getElementById("v-login").offsetParent`, 20000, "agent logged in");
}
// ---- scenarios -------------------------------------------------------------------------------------
const scenarios = {
  // SVG -> PNG with transparent background (args: svg file, output name, width, height).
  async svg(file, name, w, h) {
    w = Number(w); h = Number(h);
    writeFileSync("/tmp/svg.html", `<!doctype html><style>html,body{margin:0;background:transparent}</style>
      <img src="file://${file}" width="${w}" height="${h}" style="display:block">`);
    await send("Emulation.setDefaultBackgroundColorOverride", { color: { r: 0, g: 0, b: 0, a: 0 } });
    await send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: false });
    await nav("file:///tmp/svg.html");
    await waitFor(`document.querySelector("img").complete`, 5000, "svg loaded");
    const r = await send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: w, height: h, scale: 1 } });
    writeFileSync(`/out/${name}.png`, Buffer.from(r.data, "base64"));
    console.log("png " + name);
  },

  // Agent wizard on a fresh agent (args: backend, LAN net).
  async wizard(backend, lan) {
    await nav(BASE + "/");
    await waitFor(visible("#pw1"), 30000, "wizard step 1");
    await fill("#pw1", AGENT_PW); await fill("#pw2", AGENT_PW);
    await shot("agent-wizard-1-passwort");
    await click("#f-pw button.primary");
    await waitFor(visible("#proton-save") + ` && ${visible("#proton-conf")}`, 20000, "wizard step 2");
    await fill("#proton-conf", [
      "[Interface]", "# Key for portnook", "# NAT-PMP (Port Forwarding) = on",
      "PrivateKey = EXAMPLEexampleEXAMPLEexampleEXAMPLEexample0=",
      "Address = 10.2.0.2/32", "DNS = 10.2.0.1", "", "[Peer]", "# CH#42", "PublicKey = EXAMPLEpeerEXAMPLEpeerEXAMPLEpeerEXAMPLE0=",
      "AllowedIPs = 0.0.0.0/0", "Endpoint = 198.51.100.42:51820"].join("\n"));
    await shot("agent-wizard-2-proton");
    await click("input[name=proton][value=off]");
    await click("#proton-save");
    await waitFor(hasText("#proton-msg", "Ohne VPN gespeichert"), 20000, "proton off saved");
    await shot("agent-wizard-2-ohne-proton");
    await click("#proton-next");
    await waitFor(visible("#backend-save"), 10000, "wizard step 3");
    await fill("#backend", backend); await fill("#lan", lan);
    await click("#backend-save");
    await waitFor(hasText("#backend-msg", "Backend"), 30000, "backend test");
    await shot("agent-wizard-3-backend");
    await click("#backend-next");
    await waitFor(visible("#finish"), 10000, "wizard step 4");
    await shot("agent-wizard-4-zusammenfassung");
  },

  // Status page (all configured parts green), light and dark.
  async status() {
    await agentLogin("/");
    await waitFor(`!document.getElementById("v-status").classList.contains("hidden")`, 20000, "status view");
    await waitFor(`["d-backend","d-ddns","d-cert","d-redirect"].every((i) => document.getElementById(i).className.includes("ok"))`,
      120000, "green status lights");
    await sleep(1000);
    await shot("agent-status", { full: true });
    await fill("#theme", "dark");
    await sleep(1500);
    await shot("agent-status-dunkel", { full: true });
    await fill("#theme", "auto");
  },

  // Certificate page with name, certificate and delivery.
  async cert() {
    await agentLogin("/");
    await click("#nav [data-view=myaddr]");
    await waitFor(`document.getElementById("c-cert").textContent.includes("Gültig bis")`, 30000, "certificate page");
    await sleep(1000);
    await shot("agent-zertifikat", { full: true });
  },

  // myaddr page: name, DDNS state.
  async myaddr() {
    await agentLogin("/");
    await click("#nav [data-view=myaddr]");
    await waitFor(`!document.getElementById("v-myaddr").classList.contains("hidden")`, 20000, "myaddr page");
    await sleep(2500);
    await shot("agent-myaddr", { full: true });
  },

  // VPN page: profiles, failover and rotation, LAN entry.
  async vpn() {
    await agentLogin("/");
    await click("#nav [data-view=vpn]");
    await waitFor(`!document.getElementById("v-vpn").classList.contains("hidden")`, 20000, "vpn page");
    await sleep(1500);
    await shot("agent-vpn", { full: true });
  },

  // Settings page: language and theme.
  async settings() {
    await agentLogin("/");
    await click("#nav [data-view=system]");
    await waitFor(`!document.getElementById("v-settings").classList.contains("hidden")`, 20000, "settings page");
    await sleep(500);
    await shot("agent-einstellungen");
  },

  // Redirect page with the script provider.
  async redirect() {
    await agentLogin("/");
    await click("#nav [data-view=redirect]");
    await waitFor(`document.getElementById("r-out").textContent.includes("Redirect gesetzt")`, 30000, "redirect page");
    await sleep(1000);
    await shot("agent-redirect", { full: true });
    // script generator: .htaccess per SSH (not saved)
    await fill("#g-kind", "htaccess");
    await fill("#g-user", "webuser"); await fill("#g-host", "server.example.ch"); await fill("#g-root", "httpdocs");
    await waitFor(`document.getElementById("r-text").value.includes("SSH_USER='webuser'")`, 10000, "generator preview");
    await shot("agent-skript-generator", { full: true });
  },

  // Push page: Gotify in the LAN (test sent), ntfy.sh on the internet.
  async push() {
    await agentLogin("/");
    await click("#nav [data-view=system]");
    await waitFor(`document.getElementById("p-state").textContent.includes("LAN")`, 30000, "push page");
    await sleep(1000);
    await shot("agent-push", { full: true });
  },
};

let rc = 0;
try {
  if (!scenarios[scenario]) throw new Error("unknown scenario " + scenario);
  await connect();
  await scenarios[scenario](...args);
} catch (e) {
  console.error("ERROR " + e.message);
  try { await shot("error-" + scenario); } catch (e2) { /* ignore */ }
  rc = 1;
}
chrome.kill("SIGKILL");
process.exit(rc);
