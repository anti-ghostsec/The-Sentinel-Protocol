"use strict";
// Sentinel UI. Rules: untrusted text (names, posts) is only ever inserted
// with textContent; innerHTML is used solely for the static icon set below.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const ICONS = {
  logo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z"/><circle cx="12" cy="11" r="2.2" fill="currentColor"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  back: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>',
  home: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/></svg>',
  mail: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>',
  user: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3.5 12h17"/><path d="M12 3c2.8 3 2.8 15 0 18"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.2" fill="currentColor"/></svg>',
  compass: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M15.5 8.5l-2 5-5 2 2-5z"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2z"/><path d="M12 10v5"/><circle cx="12" cy="18" r="0.6" fill="currentColor"/></svg>',
  send: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l16-8-6 16-2.5-6.5z"/></svg>',
  heart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/></svg>',
  hash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 9h15M4 15h15M10 3L8 21M16 3l-2 18"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>',
  film: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M10 9.5v5l4.5-2.5z" fill="currentColor"/></svg>',
  music: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V6l11-2v12"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="17.5" cy="16" r="2.5"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/></svg>',
  image: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2.5"/><circle cx="9" cy="10" r="1.8"/><path d="M21 16l-5-5-9 9"/></svg>',
};

const $ = (id) => document.getElementById(id);
const S = { mode: "tor", tab: "home", status: null, posts: [], discoverable: false };

function paintIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => {
    if (!el.firstChild) el.innerHTML = ICONS[el.dataset.icon] || "";
  });
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function show(screen) {
  // Disguised: the calculator stands in front of the unlock (and welcome)
  // screen until the code is typed.
  if (S.disguised && !S.calcPassed && (screen === "unlock" || screen === "welcome")) screen = "disguise";
  for (const id of ["welcome", "account", "host", "unlock", "connecting", "app", "disguise", "linkdev", "linkwait"]) $(id).hidden = id !== screen;
}

function initial(name) {
  return (name || "?").trim().charAt(0).toUpperCase() || "?";
}

function ago(minute) {
  const now = Math.floor(Date.now() / 60000);
  const d = Math.max(0, now - minute);
  if (d < 1) return "now";
  if (d < 60) return d + "m";
  if (d < 1440) return Math.floor(d / 60) + "h";
  return Math.floor(d / 1440) + "d";
}

function setError(id, msg) {
  const e = $(id);
  e.textContent = msg || "";
  e.hidden = !msg;
}

/* ---------- onboarding ---------- */

function paintChoice() {
  document.querySelectorAll(".choice").forEach((c) => c.setAttribute("aria-checked", String(c.dataset.mode === S.mode)));
}

document.querySelectorAll(".choice").forEach((c) =>
  c.addEventListener("click", () => {
    S.mode = c.dataset.mode;
    paintChoice();
  }),
);
function accountMode(recover) {
  S.recovering = recover;
  $("account-title").textContent = recover ? "Recover your account" : "Create your account";
  $("account-sub").textContent = recover ? "Type your recovery words, your name and a new passphrase for this device." : "Pick any name. It doesn't have to be your real one.";
  $("account-recover-row").hidden = !recover;
  $("account-create").textContent = recover ? "Recover account" : "Create account";
  validateAccount();
}
$("welcome-continue").addEventListener("click", () => {
  accountMode(false);
  show("account");
  $("account-name").focus();
});
$("welcome-recover").addEventListener("click", () => {
  accountMode(true);
  show("account");
  $("account-recover-words").focus();
});
$("account-back").addEventListener("click", () => show("welcome"));

/** Rough strength in bits (same model as the Rust side); generated
    7-word passphrases are credited with their real ~90 bits. */
function passBits(p) {
  if (S.generated && p === S.generated) return 90;
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^A-Za-z0-9]/.test(p)) pool += 33;
  const len = Math.min([...p].length, new Set([...p]).size * 2);
  return Math.floor(len * Math.log2(Math.max(pool, 1)));
}
const MIN_BITS = 60;

function paintStrength() {
  const b = passBits($("account-pass").value);
  const bar = $("account-strength-bar");
  bar.style.width = Math.min(100, (b / 90) * 100) + "%";
  bar.className = b >= 80 ? "good" : b >= MIN_BITS ? "ok" : "";
  $("account-strength").textContent =
    b >= 80 ? "Strong." : b >= MIN_BITS ? "Acceptable. 7 random words (Generate) is much stronger." : "Too weak: someone who seizes this device could guess it. Press Generate.";
}

/* Show generated words as a numbered list (a single input cuts them off). */
function showWords(prefix, pass) {
  const box = $(prefix + "-words");
  const generated = !!pass && pass === S.generated;
  box.hidden = !generated;
  if (generated) {
    $(prefix + "-word-list").replaceChildren(...pass.split("-").map((w) => el("li", "", w)));
  } else {
    $(prefix + "-wrote").checked = false;
  }
  return generated;
}
function validateAccount() {
  paintStrength();
  const pass = $("account-pass").value;
  // Generated words must be written down before the account exists.
  const generated = showWords("account", pass);
  const wrote = !generated || $("account-wrote").checked;
  $("account-create").disabled = !($("account-name").value.trim() && pass.length >= 12 && passBits(pass) >= MIN_BITS && wrote);
}
$("account-generate").addEventListener("click", async () => {
  const p = await invoke("generate_passphrase");
  S.generated = p;
  const i = $("account-pass");
  i.type = "text"; // show it so it can be written down
  i.value = p;
  $("account-wrote").checked = false;
  validateAccount();
});
$("account-wrote").addEventListener("change", validateAccount);
$("welcome-restore").addEventListener("click", async () => {
  try {
    if (await invoke("import_backup")) {
      $("restore-msg").textContent = "";
      show("unlock");
      $("unlock-pass").focus();
    }
  } catch (e) {
    $("restore-msg").textContent = String(e);
  }
});
$("account-name").addEventListener("input", validateAccount);
$("account-pass").addEventListener("input", validateAccount);

$("account-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setError("account-error", "");
  const pass = $("account-pass").value;
  try {
    if (S.recovering) {
      await invoke("recover_account", { words: $("account-recover-words").value, name: $("account-name").value, pass, mode: S.mode });
      $("account-recover-words").value = "";
    } else {
      await invoke("create_account", { name: $("account-name").value, pass, mode: S.mode });
    }
    $("account-pass").value = "";
    $("account-pass").type = "password";
    S.generated = null;
    // Phones can't run a Pillar (they sleep and change networks): go straight on.
    const st = await invoke("status").catch(() => null);
    if (st && (st.platform === "android" || st.platform === "ios")) startConnecting();
    else show("host");
  } catch (e) {
    setError("account-error", String(e));
  }
});

$("unlock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setError("unlock-error", "");
  try {
    await invoke("unlock", { pass: $("unlock-pass").value });
    $("unlock-pass").value = "";
    $("unlock-keyfile-name").textContent = "";
    $("unlock-keyfile").textContent = "Use a key file";
    await startConnecting();
  } catch (e) {
    setError("unlock-error", String(e));
  }
});

/* ---------- hosting a Pillar ---------- */

$("host-no").addEventListener("click", () => startConnecting());
$("host-yes").addEventListener("click", async () => {
  try {
    await invoke("set_hosting", { on: true });
  } catch {
    /* saved choice failed; continue without hosting */
  }
  startConnecting();
});

function paintHosting() {
  const st = S.status;
  if (!st || !st.hosting) return;
  const h = st.hosting;
  const highRisk = !!(st.privacy && st.privacy.highRisk);
  const t = $("host-toggle");
  t.setAttribute("aria-checked", String(h.enabled && !highRisk));
  t.disabled = highRisk;
  let text = "Off.";
  if (highRisk) text = "Disabled in High-risk mode.";
  else if (h.enabled && h.state === "online") text = "Online · " + h.usedMb + " MB stored · " + h.served + " objects served";
  else if (h.enabled && h.state === "starting") text = "Starting your Pillar (separate Tor identity)…";
  else if (h.enabled && h.state === "restart") text = "Starts again the next time you open Sentinel.";
  else if (h.enabled && h.state === "error") text = "Couldn't start: " + (h.error || "unknown error");
  else if (h.enabled) text = "Starts when Sentinel is connected.";
  $("host-status").textContent = text;
  if (h.enabled) loadHostReports();
  else $("host-reports").hidden = true;
  const arch = h.enabled && !highRisk && (h.archiveGb || 0) > 0;
  $("archive-toggle").setAttribute("aria-checked", String(arch));
  $("archive-toggle").disabled = highRisk;
  $("archive-gb").disabled = highRisk;
  if (arch) $("archive-gb").value = String(h.archiveGb);
  let at = "Off.";
  if (highRisk) at = "Disabled in High-risk mode.";
  else if (arch && h.state === "online") at = "Online · lending " + h.archiveGb + " GB · " + h.chunksMb + " MB of files kept";
  else if (arch && h.state === "restart") at = "Lending " + h.archiveGb + " GB · starts the next time you open Sentinel.";
  else if (arch) at = "Lending " + h.archiveGb + " GB · starts with your Pillar.";
  $("archive-status").textContent = at;
  $("self-seed").setAttribute("aria-checked", String(arch && !!h.selfSeed));
  $("self-seed").disabled = highRisk || !arch;
}
async function setArchive(gb) {
  try {
    await invoke("set_archive", { gb });
  } catch (e) {
    $("archive-status").textContent = String(e);
  }
  refreshStatus();
}
$("archive-toggle").addEventListener("click", () => {
  const on = $("archive-toggle").getAttribute("aria-checked") !== "true";
  $("archive-status").textContent = on ? "Starting…" : "Stopping…";
  setArchive(on ? parseInt($("archive-gb").value, 10) : 0);
});
$("archive-gb").addEventListener("change", () => {
  if ($("archive-toggle").getAttribute("aria-checked") === "true") setArchive(parseInt($("archive-gb").value, 10));
});
$("host-toggle").addEventListener("click", async () => {
  const on = $("host-toggle").getAttribute("aria-checked") !== "true";
  try {
    await invoke("set_hosting", { on });
  } catch (e) {
    $("host-status").textContent = String(e);
  }
  refreshStatus();
});

/* ---------- connecting ---------- */

// The exact step and how long it has taken, so a tester can say where it stopped.
function paintConnectDetail() {
  if ($("connect-log-box").open) paintConnectLog();
  const net = S.lastNet;
  if (!net || !S.connectStart) return;
  const secs = Math.floor((Date.now() - S.connectStart) / 1000);
  const time = Math.floor(secs / 60) + ":" + String(secs % 60).padStart(2, "0");
  $("connect-detail").textContent = "Step: " + (net.text || net.state || "starting") + " · " + Math.round((net.frac || 0) * 100) + "% · " + time;
}

function paintNet(net) {
  if (!net) return;
  S.lastNet = net;
  paintConnectDetail();
  const f = net.frac || 0;
  $("connect-bar").style.width = Math.round(f * 100) + "%";
  let text = net.text || "";
  if (net.state === "connecting") {
    text =
      f < 0.15 ? "Starting Tor on this device…" :
      f < 0.5 ? (S.status && S.status.mode === "bridges" ? "Reaching Tor through a disguised bridge…" : "Joining the Tor network…") :
      f < 0.9 ? "Building private routes…" :
      /still trying/.test(net.text || "") ? "Still looking for Pillars… (this can take a few minutes)" : "Almost there…";
  } else if (net.state === "ready") {
    text = "Connected privately.";
  }
  $("connect-text").textContent = text;
  $("connect-retry").hidden = net.state !== "error";
  $("connect-help").hidden = !(/still trying|any Pillar/.test(net.text || "") && net.state !== "ready");
  const dot = $("status-dot");
  dot.className = "dot " + (net.state === "ready" ? "ready" : net.state === "error" ? "err" : "busy");
  $("status-title").textContent =
    net.state === "ready" ? "Private" : net.state === "error" ? "Not connected" : "Connecting…";
  const bridges = S.status && S.status.mode === "bridges";
  $("status-line").textContent =
    net.state === "ready"
      ? (bridges ? "Connected through Tor, disguised as a video call." : "Connected through Tor.") + " Your location is hidden."
      : net.state === "error"
        ? "Not connected. Your posts and messages wait on this device until it reconnects."
        : "Starting Tor on this device…";
}

/* settings: one section at a time */
S.settingsGroup = "privacy";
function paintSettings() {
  const phone = !!(S.status && (S.status.platform === "android" || S.status.platform === "ios"));
  document.body.classList.toggle("is-phone", phone);
  document.querySelectorAll("[data-settings]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.settings === S.settingsGroup)));
  document.querySelectorAll("#tab-privacy [data-group]").forEach((el) => (el.hidden = el.dataset.group !== S.settingsGroup));
}
document.querySelectorAll("[data-settings]").forEach((b) =>
  b.addEventListener("click", () => {
    S.settingsGroup = b.dataset.settings;
    paintSettings();
  }),
);
paintSettings();

/* empty timeline: share my link */
$("empty-copy-link").addEventListener("click", async () => {
  noteShared();
  if (!S.status || !S.status.link) return;
  const ok = await invoke("copy_secret", { text: S.status.link });
  $("empty-copy-link").textContent = ok ? "Copied · clears in 1 minute" : "Couldn't copy";
});

/* Discover: starter topics for a first visit */
const STARTER_TOPICS = ["news", "technology", "privacy", "art", "music", "science", "books", "games"];
function paintStarters() {
  const mine = (S.status && S.status.topics) || [];
  const box = $("topic-starters");
  const left = STARTER_TOPICS.filter((t) => !mine.includes(t));
  box.hidden = mine.length >= 3 || left.length === 0;
  box.replaceChildren(
    ...left.slice(0, 6).map((t) => {
      const c = el("button", "chip", "+ " + t);
      c.type = "button";
      c.addEventListener("click", async () => {
        try {
          await invoke("add_topic", { topic: t });
        } catch {}
        await refreshStatus();
        paintTopics();
        paintStarters();
      });
      return c;
    }),
  );
}

async function startConnecting() {
  S.connectStart = Date.now();
  S.lastNet = null;
  $("connect-detail").textContent = "";
  clearInterval(S.connectTimer);
  S.connectTimer = setInterval(paintConnectDetail, 1000);
  await refreshStatus();
  show(S.status && S.status.linking ? "linkwait" : "connecting");
  try {
    await invoke("connect");
    await refreshStatus();
    if (S.status.linking) return waitForLink();
    enterApp();
  } catch (e) {
    paintNet({ state: "error", frac: 0, text: String(e) });
  }
}
$("connect-retry").addEventListener("click", startConnecting);
async function paintConnectLog() {
  try {
    $("connect-log").textContent = (await invoke("connection_log")) || "Nothing yet.";
  } catch {}
}
$("settings-log-box").addEventListener("toggle", async () => {
  if ($("settings-log-box").open) $("settings-log").textContent = (await invoke("connection_log").catch(() => "")) || "Nothing yet.";
});
$("settings-log-copy").addEventListener("click", async () => {
  $("settings-log").textContent = (await invoke("connection_log").catch(() => "")) || "Nothing yet.";
  const ok = await invoke("copy_connection_log").catch(() => false);
  $("settings-log-copy").textContent = ok ? "Copied" : "Couldn't copy";
  setTimeout(() => ($("settings-log-copy").textContent = "Copy the log"), 3000);
});
$("connect-log-box").addEventListener("toggle", () => {
  if ($("connect-log-box").open) paintConnectLog();
});
$("connect-log-copy").addEventListener("click", async () => {
  await paintConnectLog();
  const ok = await invoke("copy_connection_log").catch(() => false);
  $("connect-log-copy").textContent = ok ? "Copied" : "Couldn't copy";
  setTimeout(() => ($("connect-log-copy").textContent = "Copy the log"), 3000);
});
$("connect-pillar-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await invoke("add_pillar_hint", { onion: $("connect-pillar").value });
    $("connect-pillar").value = "";
    $("connect-pillar-msg").textContent = "Added. Sentinel will try it next.";
    if (!$("connect-retry").hidden) startConnecting();
  } catch (err) {
    $("connect-pillar-msg").textContent = String(err);
  }
});

listen("net", (ev) => {
  paintNet(ev.payload);
});
listen("timeline", () => loadTimeline());
listen("discover", () => loadDiscover());
listen("status", () => refreshStatus());

/* ---------- app ---------- */

async function refreshStatus() {
  S.status = await invoke("status");
  const st = S.status;
  document.body.classList.toggle("is-phone", st.platform === "android" || st.platform === "ios");
  const name = st.name || "You";
  document.querySelectorAll(".me-avatar").forEach((a) => {
    a.textContent = initial(name);
    if (st.hasAvatar) setPicture(a, "me", "avatar");
  });
  $("me-name").textContent = name;
  $("me-handle").textContent = "@" + st.handle;
  $("profile-name").textContent = name;
  $("profile-handle").textContent = "@" + st.handle;
  $("stat-following").textContent = String(st.following);
  $("stat-followers").textContent = st.followers == null ? "" : st.followers === 0 ? "0" : "~" + st.followers; // an estimate, so marked with ~
  $("stat-followers-wrap").hidden = !!st.hideCount || st.followers == null; // no estimate yet: show nothing rather than a dash
  if (S.discoverable !== st.discoverDefault && !S.composeTouched) {
    S.discoverable = !!st.discoverDefault;
    paintDiscoverToggle();
  }
  paintTopics();
  $("copy-link").disabled = !st.link;
  if (!$("pillar-input").value && st.pillar) $("pillar-input").value = st.pillar;
  paintNet(st.net);
  paintPrivacy();
  paintHosting();
  paintCredits();
}

function setTab(tab) {
  S.tab = tab;
  for (const t of ["home", "discover", "messages", "rooms", "profile", "privacy", "user"]) $("tab-" + t).hidden = t !== tab;
  if (tab === "profile") loadMyProfile();
  if (tab === "privacy") {
    loadConn();
    loadStorageHealth();
    loadHidden();
  }
  if (tab === "discover") loadDiscover();
  if (tab === "rooms") closeRoom();
  if (tab === "messages") {
    S.thread = null;
    $("dm-thread").hidden = true;
    loadConversations();
  }
  document.querySelectorAll(".nav-item").forEach((n) => {
    if (n.dataset.tab === tab) n.setAttribute("aria-current", "page");
    else n.removeAttribute("aria-current");
  });
  if (tab === "profile") $("copy-link-label").textContent = "Copy follow link";
}
document.querySelectorAll(".nav-item").forEach((n) => n.addEventListener("click", () => setTab(n.dataset.tab)));
async function lockNow() {
  await invoke("lock");
  if (S.status) S.status.unlocked = false;
  S.posts = [];
  closeLightbox();
  clearAttachments(false);
  forgetMedia();
  forgetPictures();
  S.room = null;
  for (const id of ["feed", "my-feed", "discover-feed", "thread", "room-thread", "room-list", "conv-list"]) $(id).replaceChildren();
  S.calcPassed = false;
  $("unlock-keyfile-name").textContent = "";
  $("unlock-keyfile").textContent = "Use a key file";
  show("unlock");
}
$("lock-btn").addEventListener("click", lockNow);

/* auto-lock after a while without use */
let lastActivity = Date.now();
for (const ev of ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"]) {
  window.addEventListener(ev, () => (lastActivity = Date.now()), { passive: true, capture: true });
}
setInterval(() => {
  const st = S.status;
  if (!st || !st.unlocked || !st.privacy || st.privacy.autoLock === false) return;
  const limit = (st.privacy.highRisk ? 5 : 15) * 60 * 1000;
  if (Date.now() - lastActivity > limit) {
    lastActivity = Date.now();
    lockNow();
  }
}, 30 * 1000);

function enterApp() {
  clearInterval(S.connectTimer);
  show("app");
  setTimeout(paintGettingStarted, 1500);
  if (typeof paintRecovery === "function") paintRecovery();
  setTab(S.tab);
  loadTimeline();
}

function postNode(p) {
  const art = el("article", "post");
  const av = el("span", "avatar", initial(p.name));
  if (!p.mine) {
    // Stable per-author colour from the handle (no network, no tracking).
    const palette = [["#173A35", "#9FE3D2"], ["#3A2A16", "#F3C98B"], ["#2B1E3A", "#D5B8FF"], ["#1C2E3F", "#9FD0FF"]];
    const c = palette[[...p.handle].reduce((a, ch) => a + ch.charCodeAt(0), 0) % palette.length];
    av.style.background = c[0];
    av.style.color = c[1];
  }
  if (p.avatar) setPicture(av, p.mine ? "me" : p.author, "avatar");
  av.addEventListener("click", () => openUser(p.author));
  const body = el("div", "post-body");
  const meta = el("div", "post-meta");
  const nm = el("span", "post-name", p.name);
  nm.addEventListener("click", () => openUser(p.author));
  meta.append(nm, el("span", "post-sub", "@" + p.handle + " · " + ago(p.minute)));
  if (p.mine && !p.sent && p.progress == null) meta.append(el("span", "post-pending", "sending privately…"));
  if (p.followLink) {
    const fb = el("button", "btn outline follow-btn", "Follow");
    fb.type = "button";
    fb.addEventListener("click", async () => {
      try {
        await invoke("follow", { link: p.followLink });
        fb.textContent = "Following";
        fb.disabled = true;
        refreshStatus();
      } catch (e) {
        fb.textContent = String(e).slice(0, 40);
      }
    });
    meta.append(fb);
  }
  body.append(meta);
  if (p.text) body.append(el("p", "post-text", p.text));
  if (p.media && p.media.length) body.append(...mediaBlocks(p));
  if (p.progress != null) body.append(uploadBar(p));
  if (p.topics && p.topics.length) {
    const tags = el("div", "post-topics");
    for (const t of p.topics) tags.append(el("span", "tag", "#" + t));
    body.append(tags);
  }
  const actions = el("div", "post-actions");
  const like = el("button", "act" + (p.liked ? " liked" : ""));
  like.type = "button";
  like.setAttribute("aria-label", p.liked ? "Unlike" : "Like");
  like.setAttribute("aria-pressed", String(p.liked));
  const heart = el("span", "icon");
  heart.dataset.icon = "heart";
  like.append(heart);
  like.addEventListener("click", async () => {
    await invoke("toggle_like", { id: p.id });
    p.liked = !p.liked;
    like.classList.toggle("liked", p.liked);
    like.setAttribute("aria-pressed", String(p.liked));
  });
  actions.append(like);
  if (!p.mine && p.public) {
    const rb = el("button", "link-btn small", "Report");
    rb.type = "button";
    rb.addEventListener("click", async () => {
      const r = await chooseReport("post");
      if (!r) return;
      try {
        const n = await invoke("report_post", { id: p.id, category: r.category });
        art.replaceChildren(el("p", "muted small", n > 0 ? "Reported. It's hidden on this device, and the Pillars holding it were told." : "Reported and hidden on this device. The Pillars holding it couldn't be reached right now."));
      } catch (e) {
        rb.textContent = String(e).slice(0, 80);
      }
    });
    actions.append(rb);
  }
  body.append(actions);
  art.append(av, body);
  paintIcons(art);
  return art;
}

/* ---------- reporting ---------- */

let REPORT_CATS = null;
const REPORT_EXPLAIN = {
  post: "Sent to the Pillars that hold this public post. After a few reports it's hidden from Discover until the person running that Pillar decides. Nobody is told it was you.",
  listing: "Sent to the Pillar that lists this public room. After a few reports it's hidden from Discover until the person running that Pillar decides. Nobody is told it was you.",
  room: "Sent only to this room's admin and moderators, sealed so other members and the Pillar can't read it. They see the message and your note, not who sent the report.",
};

/** Ask what's wrong; resolves to { category, note } or null. */
async function chooseReport(kind) {
  if (!REPORT_CATS) REPORT_CATS = await invoke("report_categories").catch(() => []);
  const d = $("report-dialog");
  $("report-explain").textContent = REPORT_EXPLAIN[kind] || "";
  $("report-note-field").hidden = kind !== "room";
  $("report-note").value = "";
  $("report-send").disabled = true;
  $("report-options").replaceChildren(
    ...REPORT_CATS.map((c) => {
      const lab = el("label", "report-option");
      const r = document.createElement("input");
      r.type = "radio";
      r.name = "report-cat";
      r.value = c.id;
      r.addEventListener("change", () => ($("report-send").disabled = false));
      lab.append(r, el("span", "", c.label));
      return lab;
    }),
  );
  return new Promise((resolve) => {
    d.addEventListener(
      "close",
      () => {
        const picked = d.querySelector("input[name=report-cat]:checked");
        resolve(d.returnValue === "send" && picked ? { category: picked.value, note: $("report-note").value.trim() } : null);
      },
      { once: true },
    );
    d.showModal();
  });
}

/* Media from people you don't follow (Discover) is blurred until tapped. */
function blurStranger(art) {
  if (!art.querySelector(".media-grid, video, .stream-block")) return art;
  art.classList.add("stranger");
  const note = el("p", "muted small media-note", "Media from someone you don't follow is blurred. Tap it to show it.");
  const body = art.querySelector(".post-body");
  if (body) body.insertBefore(note, body.querySelector(".media-grid, .stream-block") || null);
  art.addEventListener(
    "click",
    (e) => {
      if (art.classList.contains("stranger") && e.target.closest(".media-grid, video, .stream-block")) {
        e.preventDefault();
        e.stopPropagation();
        art.classList.remove("stranger");
      }
    },
    true,
  );
  return art;
}

/* ---------- reports on my Pillar ---------- */

async function loadHostReports() {
  let list = [];
  try {
    list = await invoke("host_reports");
  } catch {
    list = [];
  }
  $("host-reports").hidden = list.length === 0;
  $("host-report-list").replaceChildren(
    ...list.map((r) => {
      const box = el("div", "report-box stack-8");
      box.append(el("span", "strong", r.summary), el("span", "muted small", r.hidden ? "Hidden from Discover until you decide." : "Still shown in Discover (fewer than three reports)."));
      if (r.preview) box.append(el("div", "report-quote small", r.preview));
      if (r.hasMedia) box.append(el("span", "muted small", "It has media, which isn't shown here."));
      const row = el("div", "inline-actions");
      const rm = el("button", "btn outline small-btn", "Remove it");
      rm.type = "button";
      armed(rm, "Remove it from your Pillar? Click again", async () => {
        try {
          await invoke("host_remove", { address: r.address });
        } catch (e) {
          rm.textContent = String(e).slice(0, 60);
        }
        loadHostReports();
      });
      const keep = el("button", "btn ghost small-btn", "Keep it");
      keep.type = "button";
      keep.addEventListener("click", async () => {
        try {
          await invoke("host_keep", { address: r.address });
        } catch (e) {
          keep.textContent = String(e).slice(0, 60);
        }
        loadHostReports();
      });
      row.append(rm, keep);
      box.append(row);
      return box;
    }),
  );
}

/* ---------- inline media (spec §5.7) ----------
   Media is fetched over Tor and decrypted in Rust, handed to the page as raw
   bytes, and shown from an in-memory blob: URL. Nothing decrypted touches
   disk; locking the app revokes every URL. */

const MEDIA = new Map(); // "postId:index" -> Promise<blob URL>

function mediaUrl(postId, index, mime) {
  const k = postId + ":" + index;
  if (!MEDIA.has(k)) {
    const pr = invoke("media_bytes", { postId, index }).then((buf) =>
      URL.createObjectURL(new Blob([buf], { type: mime })),
    );
    pr.catch(() => MEDIA.delete(k)); // allow a retry later
    MEDIA.set(k, pr);
    // Bound decrypted media held in memory (~48 × 25 MB worst case) so the
    // engine never spills decrypted blobs to its on-disk blob store.
    while (MEDIA.size > 48) {
      const [oldKey, oldPr] = MEDIA.entries().next().value;
      MEDIA.delete(oldKey);
      oldPr.then((u) => URL.revokeObjectURL(u), () => {});
    }
  }
  return MEDIA.get(k);
}

function forgetMedia() {
  for (const pr of MEDIA.values()) pr.then((u) => URL.revokeObjectURL(u), () => {});
  MEDIA.clear();
}

// Load media only when it scrolls near the viewport; play videos only while visible.
const mediaObserver = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      const tile = e.target;
      if (e.isIntersecting && !tile.dataset.loaded) {
        tile.dataset.loaded = "1";
        loadTile(tile);
      }
      const v = tile.querySelector("video");
      if (v && v.dataset.auto) {
        if (e.isIntersecting) v.play().catch(() => {});
        else v.pause();
      }
    }
  },
  { rootMargin: "300px 0px" },
);

async function loadTile(tile) {
  const { postId, index, mime, kind } = tile.dataset;
  try {
    const url = await mediaUrl(postId, Number(index), mime);
    if (kind === "video") {
      const v = document.createElement("video");
      v.src = url;
      v.muted = true;
      v.loop = true;
      v.playsInline = true;
      v.controls = true;
      v.preload = "auto";
      v.dataset.auto = "1";
      v.disablePictureInPicture = false;
      tile.replaceChildren(v);
      v.play().catch(() => {});
    } else {
      const img = document.createElement("img");
      img.src = url;
      img.alt = kind === "gif" ? "GIF" : "Image";
      img.draggable = false;
      tile.replaceChildren(img);
      if (kind === "gif") tile.append(el("span", "media-badge", "GIF"));
      tile.tabIndex = 0;
      tile.setAttribute("role", "button");
      tile.setAttribute("aria-label", "Enlarge image");
      const open = () => openLightbox(url);
      tile.addEventListener("click", open);
      tile.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          open();
        }
      });
    }
    tile.classList.remove("loading");
  } catch (e) {
    tile.classList.remove("loading");
    tile.dataset.loaded = "";
    const retry = el("button", "media-retry", "Couldn't load privately · retry");
    retry.type = "button";
    retry.addEventListener("click", (ev) => {
      ev.stopPropagation();
      tile.classList.add("loading");
      tile.replaceChildren();
      tile.dataset.loaded = "1";
      loadTile(tile);
    });
    tile.replaceChildren(retry);
  }
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return (n < 10 ? n.toFixed(1) : Math.round(n)) + " " + u[i];
}

function iconEl(name, cls = "icon") {
  const i = el("span", cls);
  i.dataset.icon = name;
  return i;
}

/** Visual inline media in a grid; audio, streamed media and files as blocks. */
function mediaBlocks(p) {
  const out = [];
  const visual = [];
  p.media.forEach((m, i) => {
    if (m.inline && m.kind !== "audio") visual.push([m, i]);
    else if (m.inline && m.kind === "audio") out.push(audioBlock(p, m, i));
    else if (m.stream) out.push(streamBlock(p, m, i));
    else out.push(fileCard(p, m, i));
  });
  if (visual.length) out.unshift(mediaGrid(p, visual));
  return out;
}

function mediaGrid(p, items) {
  const grid = el("div", "media-grid n" + Math.min(items.length, 4));
  items.slice(0, 4).forEach(([m, i]) => {
    const tile = el("div", "media-tile loading");
    tile.dataset.postId = p.id;
    tile.dataset.index = String(i);
    tile.dataset.mime = m.mime;
    tile.dataset.kind = m.kind;
    // A single item keeps its own shape (within limits), like Twitter.
    if (items.length === 1 && m.width && m.height) {
      tile.style.aspectRatio = String(Math.min(Math.max(m.width / m.height, 0.75), 2));
    }
    grid.append(tile);
    mediaObserver.observe(tile);
  });
  return grid;
}

function audioBlock(p, m, i) {
  const box = el("div", "audio-block");
  box.append(iconEl("music"));
  const a = document.createElement("audio");
  a.controls = true;
  a.preload = "none";
  box.append(a);
  mediaUrl(p.id, i, m.mime).then(
    (u) => (a.src = u),
    () => box.replaceChildren(el("span", "muted small", "Couldn't load this audio privately.")),
  );
  return box;
}

function streamUrl(p, i) {
  return "http://smedia.localhost/" + S.status.streamToken + "/" + encodeURIComponent(p.id) + "/" + i;
}

/** Large audio/video: plays on request, streamed and decrypted in memory. */
function streamBlock(p, m, i) {
  const box = el("div", "stream-block");
  const highRisk = !!(S.status && S.status.privacy && S.status.privacy.highRisk);
  const start = el("button", "stream-start");
  start.type = "button";
  start.append(iconEl(m.kind === "audio" ? "music" : "film", "icon lg"), el("span", "strong", m.name || (m.kind === "audio" ? "Audio" : "Video")), el("span", "muted small", fmtSize(m.size) + " · plays over Tor"));
  start.addEventListener("click", () => {
    const v = document.createElement(m.kind === "audio" ? "audio" : "video");
    v.controls = true;
    v.preload = "metadata";
    v.playsInline = true;
    v.src = streamUrl(p, i);
    box.replaceChildren(v, fileActions(p, m, i));
    v.play().catch(() => {});
  });
  // Nothing is fetched until the reader asks (always in High-risk mode,
  // and by default for large media: it can be gigabytes over Tor).
  box.append(start, fileActions(p, m, i));
  if (highRisk) box.append(el("p", "muted small", "High-risk mode: large media loads only when you press play."));
  paintIcons(box);
  return box;
}

function fileActions(p, m, i) {
  const row = el("div", "file-actions");
  if (m.pending) return row;
  const key = p.id + ":" + i;
  const save = el("button", "btn outline small-btn");
  save.type = "button";
  save.append(iconEl("download", "icon sm"), el("span", null, "Save"));
  const prog = el("div", "progress thin");
  prog.hidden = true;
  prog.append(el("span"));
  const note = el("span", "muted small");
  note.dataset.transfer = key;
  prog.dataset.transferBar = key;
  const cancel = el("button", "btn ghost small-btn", "Cancel");
  cancel.type = "button";
  cancel.hidden = true;
  cancel.dataset.transferCancel = key;
  cancel.addEventListener("click", () => invoke("cancel_transfer", { key }));
  const started = () => {
    prog.hidden = false;
    cancel.hidden = false;
    note.textContent = "Downloading privately…";
  };
  save.addEventListener("click", async () => {
    try {
      const r = await invoke("save_media", { postId: p.id, index: i });
      if (r.started) started();
      else if (r.cloud) {
        // A cloud-synced folder would upload the file to that company.
        note.textContent = "That folder syncs to " + r.cloud + ": the file would be uploaded to " + r.cloud + ".";
        const yes = el("button", "btn ghost small-btn", "Save there anyway");
        const no = el("button", "btn outline small-btn", "Choose another folder");
        yes.type = no.type = "button";
        const done = () => { yes.remove(); no.remove(); };
        yes.addEventListener("click", async () => {
          done();
          if (await invoke("confirm_save", { postId: p.id, index: i, go: true })) started();
        });
        no.addEventListener("click", async () => {
          done();
          note.textContent = "";
          await invoke("confirm_save", { postId: p.id, index: i, go: false });
          save.click();
        });
        row.append(no, yes);
      }
    } catch (e) {
      note.textContent = String(e);
    }
  });
  const keep = el("button", "btn ghost small-btn", "Keep 1 year");
  keep.type = "button";
  keep.title = "Pay credits so its Archives keep it for 12 months (instead of 90 days after the last view).";
  keep.addEventListener("click", async () => {
    try {
      const n = await invoke("pin_quote", { postId: p.id, index: i, months: 12 });
      if (keep.dataset.confirm !== "1") {
        keep.dataset.confirm = "1";
        keep.textContent = "Pay " + n + " credits to keep it";
        return;
      }
      keep.disabled = true;
      await invoke("pin_media", { postId: p.id, index: i, months: 12 });
      keep.textContent = "Kept for a year";
      refreshStatus();
    } catch (e) {
      note.textContent = String(e);
      keep.disabled = false;
    }
  });
  row.append(save, keep, cancel, note, prog);
  paintIcons(row);
  return row;
}

function fileCard(p, m, i) {
  const card = el("div", "file-card");
  card.append(iconEl(m.kind === "video" ? "film" : m.kind === "audio" ? "music" : "file", "icon lg file-icon"));
  const info = el("div", "stack-4 grow");
  info.append(el("span", "strong file-name", m.name || "file"));
  info.append(el("span", "muted small", fmtSize(m.size) + (m.pending ? " · uploading" : "")));
  if (!m.cleaned) {
    const w = el("span", "file-warn small");
    w.append(iconEl("alert", "icon sm"), el("span", null, "Files like this can carry names, dates or places that couldn't be removed. Never opened automatically."));
    info.append(w);
  }
  info.append(fileActions(p, m, i));
  card.append(info);
  paintIcons(card);
  return card;
}

function uploadBar(p) {
  const box = el("div", "upload-box");
  const text = el("span", "muted small", p.uploadError ? "Upload paused: " + p.uploadError : "Uploading privately… " + Math.round(p.progress * 100) + "%");
  text.dataset.upload = p.id;
  const prog = el("div", "progress thin");
  const bar = el("span");
  bar.style.width = Math.round(p.progress * 100) + "%";
  prog.append(bar);
  prog.dataset.uploadBar = p.id;
  const cancel = el("button", "btn ghost small-btn", "Discard");
  cancel.type = "button";
  cancel.addEventListener("click", async () => {
    await invoke("discard_draft", { id: p.id });
    loadTimeline();
  });
  box.append(text, prog, cancel);
  return box;
}

listen("transfer", (ev) => {
  const t = ev.payload;
  if (t.kind === "download") {
    const note = document.querySelector('[data-transfer="' + CSS.escape(t.key) + '"]');
    const bar = document.querySelector('[data-transfer-bar="' + CSS.escape(t.key) + '"]');
    const cancel = document.querySelector('[data-transfer-cancel="' + CSS.escape(t.key) + '"]');
    if (!note) return;
    if (t.state === "running") {
      const pct = t.total ? Math.floor((t.done / t.total) * 100) : 0;
      note.textContent = "Downloading privately… " + pct + "%";
      if (bar) bar.firstChild.style.width = pct + "%";
    } else {
      if (bar) bar.hidden = true;
      if (cancel) cancel.hidden = true;
      note.textContent = t.state === "done" ? "Saved to " + t.path : t.state === "cancelled" ? "Cancelled." : "Download failed: " + (t.error || "");
    }
    return;
  }
  const postId = t.key.slice(0, t.key.lastIndexOf(":"));
  const text = document.querySelector('[data-upload="' + CSS.escape(postId) + '"]');
  const bar = document.querySelector('[data-upload-bar="' + CSS.escape(postId) + '"]');
  if (!text || t.state !== "running") {
    if (t.state === "done" || t.state === "error") loadTimeline();
    return;
  }
  const frac = t.kind === "prepare" ? 0.1 * (t.done / (t.total || 1)) : 0.1 + 0.9 * (t.done / (t.total || 1));
  text.textContent = (t.kind === "prepare" ? "Removing metadata and encrypting… " : "Uploading privately… ") + Math.round(frac * 100) + "%";
  if (bar) bar.firstChild.style.width = Math.round(frac * 100) + "%";
});

function openLightbox(url) {
  const lb = $("lightbox");
  $("lightbox-img").src = url;
  lb.hidden = false;
  $("lightbox-close").focus();
}
function closeLightbox() {
  $("lightbox").hidden = true;
  $("lightbox-img").removeAttribute("src");
}
$("lightbox").addEventListener("click", (ev) => {
  if (ev.target.id !== "lightbox-img") closeLightbox();
});
$("lightbox-close").addEventListener("click", closeLightbox);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && !$("lightbox").hidden) closeLightbox();
});

async function loadTimeline() {
  try {
    S.posts = await invoke("timeline");
  } catch {
    return;
  }
  $("feed").replaceChildren(...S.posts.map(postNode));
  $("feed-empty").hidden = S.posts.length > 0;
  const mine = S.posts.filter((p) => p.mine);
  $("my-feed").replaceChildren(...mine.map(postNode));
  $("stat-posts").textContent = String(mine.length);
}

/* compose */
S.attachments = []; // [{id, kind, inline, name, size, cleaned, preview, busy}]

function paintCompose() {
  const n = [...$("compose-text").value.trim()].length;
  const busy = S.attachments.some((a) => a.busy) || S.attaching;
  $("compose-post").disabled = busy || (n === 0 && S.attachments.length === 0) || n > 500;
  $("compose-attach").disabled = S.attachments.length >= 4 || !!S.attaching;
  const c = $("compose-count");
  c.textContent = n > 400 ? String(500 - n) : "";
  c.classList.toggle("over", n > 500);
}
$("compose-text").addEventListener("input", paintCompose);

function removeButton(a) {
  const x = el("button", "media-remove");
  x.type = "button";
  x.setAttribute("aria-label", "Remove attachment");
  x.append(iconEl("x", "icon sm"));
  x.addEventListener("click", () => removeAttachment(a));
  return x;
}

function paintAttachments() {
  const inline = S.attachments.filter((a) => a.inline);
  const files = S.attachments.filter((a) => !a.inline);
  const box = $("compose-media");
  box.hidden = inline.length === 0;
  box.className = "compose-media media-grid n" + Math.max(1, inline.length);
  box.replaceChildren(
    ...inline.map((a) => {
      const tile = el("div", "media-tile" + (a.preview ? "" : " loading"));
      if (a.preview) {
        const m = el(a.kind === "video" ? "video" : a.kind === "audio" ? "audio" : "img");
        m.src = a.preview;
        if (a.kind === "video") {
          m.muted = true;
          m.loop = true;
          m.autoplay = true;
          m.playsInline = true;
        } else if (a.kind === "audio") m.controls = true;
        else m.alt = "Attachment preview";
        tile.append(m);
      }
      const b = el("span", "media-badge clean-badge");
      b.append(iconEl("shield", "icon sm"), el("span", null, "Metadata removed"));
      tile.append(b, removeButton(a));
      paintIcons(tile);
      return tile;
    }),
  );
  const partial = $("compose-partial");
  partial.hidden = !S.attachments.some((a) => a.partial);
  const list = $("compose-files");
  list.hidden = files.length === 0;
  list.replaceChildren(
    ...files.map((a) => {
      const card = el("div", "file-card compose-file");
      card.append(iconEl(a.kind === "video" ? "film" : a.kind === "audio" ? "music" : "file", "icon lg file-icon"));
      const info = el("div", "stack-4 grow");
      const label = el("label", "muted small", "Name readers see");
      const name = el("input", "file-name-input");
      name.type = "text";
      name.value = a.name;
      name.maxLength = 120;
      name.spellcheck = false;
      name.autocomplete = "off";
      name.addEventListener("change", async () => {
        try {
          a.name = await invoke("rename_attachment", { id: a.id, name: name.value });
        } catch {
          name.value = a.name;
        }
      });
      label.append(name);
      info.append(label, el("span", "muted small", fmtSize(a.size) + " · stored encrypted on Archives"));
      const w = el("span", (a.cleaned ? "file-ok" : "file-warn") + " small");
      w.append(
        iconEl(a.cleaned ? "shield" : "alert", "icon sm"),
        el("span", null, a.cleaned ? "Metadata removed on this device" : "Sentinel can't remove metadata from this kind of file. It may contain names, dates, places or software details — check it before sharing."),
      );
      info.append(w);
      card.append(info, removeButton(a));
      paintIcons(card);
      return card;
    }),
  );
  paintCompose();
}

function removeAttachment(a) {
  S.attachments = S.attachments.filter((x) => x !== a);
  if (a.id) invoke("discard_attachment", { id: a.id });
  if (a.preview) URL.revokeObjectURL(a.preview);
  paintAttachments();
}

function clearAttachments(discard = true) {
  for (const a of S.attachments) {
    if (discard && a.id) invoke("discard_attachment", { id: a.id });
    if (a.preview) URL.revokeObjectURL(a.preview);
  }
  S.attachments = [];
  paintAttachments();
}

/** Add an attachment result ({Ok} | {Err}) from the dialog or a drop. */
async function addAttached(r) {
  if (r.Err !== undefined) {
    setError("compose-error", r.Err);
    return;
  }
  const a = r.Ok;
  if (S.attachments.length >= 4) {
    invoke("discard_attachment", { id: a.id });
    setError("compose-error", "Up to 4 attachments per post.");
    return;
  }
  S.attachments.push(a);
  paintAttachments();
  if (a.inline) {
    try {
      const buf = await invoke("attachment_bytes", { id: a.id });
      a.preview = URL.createObjectURL(new Blob([buf]));
    } catch {
      /* preview is optional */
    }
    paintAttachments();
  }
}

$("compose-attach").addEventListener("click", async () => {
  setError("compose-error", "");
  S.attaching = true;
  paintCompose();
  try {
    // Native dialog: nothing is added to the system's recent-files lists.
    for (const r of await invoke("attach_files")) await addAttached(r);
  } catch (e) {
    setError("compose-error", String(e));
  }
  S.attaching = false;
  paintCompose();
});

// Files dropped anywhere on the window (no dialog, no trace).
listen("attached", (ev) => {
  if (S.tab !== "home") setTab("home");
  setError("compose-error", "");
  addAttached(ev.payload);
});

$("compose").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setError("compose-error", "");
  const topics = S.discoverable && !S.approvedOnly
    ? $("compose-topics").value.split(/[,\s]+/).map((t) => t.trim()).filter(Boolean)
    : [];
  try {
    const attachments = S.attachments.filter((a) => a.id).map((a) => a.id);
    if (attachments.some((id) => !S.attachments.find((a) => a.id === id).inline) && !S.status.pillar) throw "Connect first to share files.";
    await invoke("publish", { text: $("compose-text").value, topics, discoverable: S.discoverable && !S.approvedOnly, approvedOnly: !!S.approvedOnly, attachments });
    clearAttachments(false);
    $("compose-text").value = "";
    $("compose-topics").value = "";
    paintCompose();
    if (!S.status.pillar) setError("compose-error", "Saved on this device. It will be sent as soon as a Pillar is reachable.");
    loadTimeline();
  } catch (e) {
    setError("compose-error", String(e));
  }
});

/* discoverable toggle on compose */
function paintDiscoverToggle() {
  const highRisk = !!(S.status && S.status.privacy && S.status.privacy.highRisk);
  const on = S.discoverable && !highRisk && !S.approvedOnly;
  const b = $("compose-discover");
  b.setAttribute("aria-pressed", String(on || !!S.approvedOnly));
  b.title = highRisk ? "High-risk mode keeps posts out of Discover" : "Who can read this post (click to change)";
  $("compose-discover-label").textContent = S.approvedOnly ? "Approved followers" : on ? "Discoverable" : "People with your link";
  $("compose-topics").hidden = !on;
}
// Audience cycles: people with your link -> Discoverable -> approved followers.
$("compose-discover").addEventListener("click", () => {
  const highRisk = !!(S.status && S.status.privacy && S.status.privacy.highRisk);
  if (S.approvedOnly) {
    S.approvedOnly = false;
    S.discoverable = false;
  } else if (S.discoverable || highRisk) {
    S.discoverable = false;
    S.approvedOnly = true;
  } else {
    S.discoverable = true;
  }
  S.composeTouched = true;
  paintDiscoverToggle();
  if (S.discoverable && !S.approvedOnly) $("compose-topics").focus();
});

/* discover tab */
function paintTopics() {
  if (typeof paintStarters === "function") paintStarters();
  const topics = (S.status && S.status.topics) || [];
  $("topic-chips").replaceChildren(
    ...topics.map((t) => {
      const c = el("span", "chip", "#" + t);
      const x = el("button");
      x.type = "button";
      x.setAttribute("aria-label", "Remove topic " + t);
      const xi = el("span", "icon sm");
      xi.dataset.icon = "x";
      x.append(xi);
      x.addEventListener("click", async () => {
        await invoke("remove_topic", { topic: t });
        await refreshStatus();
      });
      c.append(x);
      paintIcons(c);
      return c;
    }),
  );
}
$("topic-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const t = await invoke("add_topic", { topic: $("topic-input").value });
    $("topic-input").value = "";
    $("topic-msg").textContent = "Added #" + t + ". Matching posts appear on the next refresh.";
    await refreshStatus();
  } catch (e) {
    $("topic-msg").textContent = String(e);
  }
});
async function loadDiscover() {
  let items = [];
  let rooms = [];
  try {
    items = await invoke("discovered");
    rooms = await invoke("discovered_rooms");
  } catch {
    return;
  }
  $("discover-feed").replaceChildren(...items.map((p) => blurStranger(postNode(p))));
  paintDiscoverRooms(rooms);
  $("discover-empty").hidden = items.length > 0 || rooms.length > 0;
}
function paintDiscoverRooms(rooms) {
  const box = $("discover-rooms");
  box.hidden = rooms.length === 0;
  box.replaceChildren(
    el("span", "setting-title", "Rooms"),
    ...rooms.map((r) => {
      const card = el("div", "card stack-4");
      const price = r.access === "free" ? "Free" : r.access === "pass" ? r.price + " credits, once" : r.price + " credits a month";
      card.append(el("span", "strong", r.name), el("span", "muted small", price + " · " + r.topics.map((t) => "#" + t).join(" ")));
      if (r.description) card.append(el("span", "small", r.description));
      const note = el(
        "span",
        "muted small",
        r.approval
          ? "Ask to join: the room's admin or a moderator sees your name, handle and note, then lets you in."
          : r.access === "free"
            ? "Public room: anyone who finds it can read it and see who's there."
            : "Paid with anonymous credits.",
      );
      const label = r.joined ? "Joined" : r.waiting ? "Asked · waiting" : r.approval ? "Ask to join" : r.access === "free" ? "Join" : "Pay " + r.price + " credits";
      const btn = el("button", "btn outline small-btn", label);
      btn.type = "button";
      btn.disabled = r.joined || r.waiting;
      const msg = el("span", "muted small");
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try {
          if (r.access === "free") await invoke("join_room", { link: r.link });
          else await invoke("buy_room", { link: r.link });
          btn.textContent = r.approval ? "Asked · waiting" : r.access === "free" ? "Joined" : "Paid · waiting for the invite";
        } catch (e) {
          msg.textContent = String(e);
          btn.disabled = false;
        }
      });
      const row = el("div", "inline-actions");
      const rep = el("button", "link-btn small", "Report");
      rep.type = "button";
      rep.addEventListener("click", async () => {
        const c = await chooseReport("listing");
        if (!c) return;
        try {
          await invoke("report_room_listing", { id: r.id, category: c.category });
          card.replaceChildren(el("p", "muted small", "Reported. It's hidden on this device, and the Pillar listing it was told."));
        } catch (e) {
          msg.textContent = String(e);
        }
      });
      row.append(btn, rep, msg);
      card.append(note, row);
      return card;
    }),
  );
}
$("discover-refresh").addEventListener("click", async () => {
  const b = $("discover-refresh");
  b.disabled = true;
  b.textContent = "Refreshing…";
  try {
    await invoke("discover_now");
  } catch (e) {
    $("topic-msg").textContent = String(e);
  }
  b.disabled = false;
  b.textContent = "Refresh";
  loadDiscover();
});

/* messages */
S.thread = null; // author of the open conversation

function minuteLabel(m) {
  return m ? ago(m) : "";
}

async function loadConversations() {
  let convs = [];
  try {
    convs = await invoke("conversations");
  } catch {
    return;
  }
  $("dm-empty").hidden = convs.length > 0 || !!S.thread;
  $("conv-list").hidden = !!S.thread;
  $("conv-list").replaceChildren(
    ...convs.map((c) => {
      const b = el("button", "conv");
      b.type = "button";
      b.setAttribute("role", "listitem");
      b.disabled = !c.canMessage;
      const av = el("span", "avatar", initial(c.name));
      const text = el("span", "conv-text");
      const top = el("span", "conv-top");
      top.append(el("span", "strong", c.name), el("span", "muted small mono", minuteLabel(c.minute)));
      const last = el(
        "span",
        "conv-last",
        c.last || (c.canMessage ? "Start an encrypted conversation" : "Waiting for their contact card"),
      );
      text.append(top, last);
      b.append(av, text);
      b.addEventListener("click", () => openThread(c));
      return b;
    }),
  );
}

async function openThread(c) {
  S.thread = c;
  $("conv-list").hidden = true;
  $("dm-empty").hidden = true;
  $("dm-thread").hidden = false;
  $("thread-avatar").textContent = initial(c.name);
  $("thread-name").textContent = c.name;
  $("thread-handle").textContent = "@" + c.handle;
  setError("dm-error", "");
  await loadThread();
  if (!document.body.classList.contains("is-phone")) $("dm-input").focus();
}

async function loadThread() {
  if (!S.thread) return;
  let msgs = [];
  try {
    msgs = await invoke("thread", { author: S.thread.author });
  } catch {
    return;
  }
  const note = el("p", "thread-note", "Messages are end-to-end encrypted. Pillars only ever see sealed blobs.");
  $("thread").replaceChildren(
    note,
    ...msgs.map((m) => {
      const row = el("div", "bubble-row" + (m.mine ? " mine" : ""));
      const wrap = el("div");
      wrap.append(
        el("div", "bubble", m.text),
        el("div", "bubble-meta", m.mine && !m.sent ? "sending privately…" : ago(m.minute)),
      );
      row.append(wrap);
      selectable(row, "dm", m.id);
      return row;
    }),
  );
  const t = $("thread");
  t.scrollTop = t.scrollHeight;
}

$("thread-back").addEventListener("click", () => {
  if (S.sel) endSelect();
  S.thread = null;
  $("dm-thread").hidden = true;
  loadConversations();
});

$("dm-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const text = $("dm-input").value;
  if (!text.trim() || !S.thread) return;
  try {
    await invoke("send_dm", { author: S.thread.author, text });
    $("dm-input").value = "";
    setError("dm-error", "");
    loadThread();
  } catch (e) {
    setError("dm-error", String(e));
  }
});

listen("messages", () => {
  loadConversations();
  loadThread();
});

$("dm-credits-btn").addEventListener("click", async () => {
  const f = $("dm-credits");
  if (!f.hidden) {
    f.hidden = true;
    return;
  }
  try {
    $("dm-credits-have").textContent = String((await invoke("wallet")).balance);
  } catch {}
  f.hidden = false;
  $("dm-credits-n").focus();
});
$("dm-credits-cancel").addEventListener("click", () => ($("dm-credits").hidden = true));
$("dm-credits").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const amount = parseInt($("dm-credits-n").value, 10);
  if (!S.thread || !(amount > 0)) return;
  try {
    await invoke("send_credits", { author: S.thread.author, amount });
    $("dm-credits").hidden = true;
    setError("dm-error", "");
    loadThread();
    refreshStatus();
  } catch (e) {
    setError("dm-error", String(e));
  }
});

/* rooms */
S.room = null; // open room view
S.newRoom = { vis: "private", access: "free" };

const VIS_HELP = {
  private: "Only people you give the invite link to can join.",
  public: "Listed in Discover under its topics. Anyone who finds it can join, read everything in it and see who's there. The listing is signed with the room's own key, not your account; a paid room's listing includes your follow link (so people can pay you), which ties the room to you.",
};

function paintRoomForm() {
  document.querySelectorAll("[data-vis]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.vis === S.newRoom.vis)));
  document.querySelectorAll("[data-access]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.access === S.newRoom.access)));
  $("room-vis-help").textContent = VIS_HELP[S.newRoom.vis];
  $("room-price-row").hidden = S.newRoom.access === "free";
  $("room-paid-help").hidden = S.newRoom.access === "free";
  $("room-public-fields").hidden = S.newRoom.vis !== "public";
  $("room-approval-row").hidden = S.newRoom.access !== "free";
  if (S.newRoom.access !== "free") $("room-approval").checked = false;
  $("room-approval-help").hidden = !$("room-approval").checked;
}
$("room-approval").addEventListener("change", paintRoomForm);
document.querySelectorAll("[data-vis]").forEach((b) =>
  b.addEventListener("click", () => {
    S.newRoom.vis = b.dataset.vis;
    paintRoomForm();
  }),
);
document.querySelectorAll("[data-access]").forEach((b) =>
  b.addEventListener("click", () => {
    if (b.disabled) return;
    S.newRoom.access = b.dataset.access;
    paintRoomForm();
  }),
);

function roomSub(r) {
  if (r.waiting) return r.declined ? "Not let in" : "Waiting for someone to let you in";
  const n = r.members === 1 ? "1 member" : r.members + " members";
  const extra = (r.approval ? " · Ask to join" : "") + (r.moderator ? " · You moderate" : "") + (r.requests ? " · " + r.requests + (r.requests === 1 ? " request" : " requests") : "");
  return (r.visibility === "public" ? "Public" : "Private") + " · " + n + extra;
}

async function loadRooms() {
  let list = [];
  try {
    list = await invoke("rooms");
  } catch {
    return;
  }
  S.roomList = list;
  $("room-list").replaceChildren(
    ...list.map((r) => {
      const b = el("button", "conv");
      b.type = "button";
      b.setAttribute("role", "listitem");
      const badge = el("span", "room-badge");
      const hi = el("span", "icon");
      hi.dataset.icon = "hash";
      badge.append(hi);
      const text = el("span", "conv-text");
      const top = el("span", "conv-top");
      top.append(el("span", "strong", r.name), el("span", "muted small mono", minuteLabel(r.minute)));
      text.append(top, el("span", "conv-last", r.last || roomSub(r)));
      if (r.access !== "free") top.firstChild.append(el("span", "price-badge", r.access === "pass" ? " · Pass " + r.price : " · " + r.price + "/month"));
      b.append(badge, text);
      b.addEventListener("click", () => openRoom(r));
      paintIcons(b);
      return b;
    }),
  );
  if (S.room) {
    const r = list.find((x) => x.id === S.room.id);
    if (r) {
      S.room = r;
      $("room-title").textContent = r.name;
      $("room-sub").textContent = roomSub(r);
    }
  }
}

function closeRoom() {
  if (S.sel) endSelect();
  S.room = null;
  $("room-view").hidden = true;
  $("rooms-home").hidden = false;
  loadRooms();
}

async function openRoom(r) {
  S.room = r;
  const staff = r.admin || r.moderator;
  $("room-members-btn").hidden = !staff || r.waiting;
  $("room-members-btn").textContent = r.requests ? "Members · " + r.requests + (r.requests === 1 ? " request" : " requests") : "Members";
  $("room-members").hidden = true;
  $("room-apps").hidden = true;
  $("room-apps-btn").hidden = r.waiting;
  $("room-invite").hidden = r.waiting || (r.approval ? !staff : !r.admin && r.access !== "free");
  $("room-form").hidden = r.waiting;
  S.leaveArmed = false;
  $("room-leave").textContent = r.waiting ? (r.declined ? "Remove" : "Cancel request") : "Leave";
  $("rooms-home").hidden = true;
  $("room-view").hidden = false;
  $("room-title").textContent = r.name;
  $("room-sub").textContent = roomSub(r);
  $("room-invite-label").textContent = r.approval ? "Copy ask-to-join link" : "Copy invite link";
  setError("room-error", "");
  await loadRoomThread();
  if (!r.waiting && !document.body.classList.contains("is-phone")) $("room-input").focus();
}

async function loadRoomThread() {
  if (!S.room) return;
  let msgs = [];
  try {
    msgs = await invoke("room_messages", { id: S.room.id });
  } catch {
    return;
  }
  const note = S.room.waiting
    ? el("p", "thread-note", S.room.declined ? "The room's admin or a moderator didn't let you in." : "You asked to join. When the room's admin or a moderator lets you in, the conversation appears here. Nobody else in the room saw your request.")
    : el("p", "thread-note", "End-to-end encrypted room. Pillars store sealed blobs and never learn who is in it.");
  const warn = S.room.fork
    ? [el("p", "thread-note error", "Warning: this room's admin key signed two conflicting sets of changes. It may have been stolen or misused. Be careful what you share here.")]
    : [];
  let prev = null;
  $("room-thread").replaceChildren(
    note,
    ...warn,
    ...msgs.map((m) => {
      const row = el("div", "bubble-row" + (m.mine ? " mine" : ""));
      const wrap = el("div");
      // Name above a run of messages from the same person.
      if (!m.mine && prev !== m.handle) {
        const n = el("div", "bubble-name clickable", m.name + " · @" + m.handle);
        n.title = "Open their profile";
        n.addEventListener("click", () => openUser(m.author, m.name));
        // Not yet proven to me (their next hello will verify them).
        if (!m.verified) n.append(el("span", "unverified", " · unverified"));
        wrap.append(n);
      }
      prev = m.mine ? null : m.handle;
      const meta = el("div", "bubble-meta", m.mine && !m.sent ? "sending privately…" : ago(m.minute));
      // The room's creator and moderators can hide a message for everyone.
      if ((S.room.admin || S.room.moderator) && !m.mine && m.id && !m.id.startsWith(":")) {
        const hide = el("button", "link-btn small", " · Hide");
        hide.type = "button";
        hide.title = "Hide this message for everyone in the room";
        hide.addEventListener("click", async () => {
          try {
            await invoke("hide_room_message", { id: S.room.id, msgId: m.id });
          } catch (e) {
            setError("room-error", String(e));
          }
          loadRoomThread();
        });
        meta.append(hide);
      }
      if (!m.mine && m.id && !m.id.startsWith(":") && !(S.room.admin || S.room.moderator)) {
        const rp = el("button", "link-btn small", " · Report");
        rp.type = "button";
        rp.title = "Report this message to the room's admin and moderators";
        rp.addEventListener("click", async () => {
          const c = await chooseReport("room");
          if (!c) return;
          try {
            const n = await invoke("report_room_message", { id: S.room.id, msg: m.id, category: c.category, note: c.note });
            rp.textContent = " · Reported to " + n + (n === 1 ? " person" : " people");
            rp.disabled = true;
          } catch (e) {
            setError("room-error", String(e));
          }
        });
        meta.append(rp);
      }
      wrap.append(el("div", "bubble", m.text), meta);
      row.append(wrap);
      selectable(row, "room", m.id);
      return row;
    }),
  );
  if ((S.room.admin || S.room.moderator) && S.room.reports > 0) {
    const reports = await invoke("room_reports", { id: S.room.id }).catch(() => []);
    if (reports.length) {
      const box = el("div", "report-box stack-8");
      box.append(el("span", "strong", reports.length === 1 ? "1 report from members" : reports.length + " reports from members"), el("span", "muted small", "Sealed to you and the other moderators: nobody else in the room saw them, and they don't say who sent them."));
      for (const r of reports) {
        const cat = (REPORT_CATS || (REPORT_CATS = await invoke("report_categories").catch(() => []))).find((c) => c.id === r.category);
        const one = el("div", "stack-4");
        one.append(el("span", "small strong", cat ? cat.label : r.category), el("div", "report-quote small", r.text || "(no text)"));
        if (r.note) one.append(el("span", "muted small", "Note: " + r.note));
        const row = el("div", "inline-actions");
        if (!r.hidden) {
          const hide = el("button", "btn outline small-btn", "Hide for everyone");
          hide.type = "button";
          hide.addEventListener("click", async () => {
            try {
              await invoke("hide_room_message", { id: S.room.id, msgId: r.id });
              await invoke("dismiss_room_report", { id: S.room.id, msg: r.id });
            } catch (e) {
              setError("room-error", String(e));
            }
            S.room.reports = Math.max(0, S.room.reports - 1);
            loadRoomThread();
          });
          row.append(hide);
        } else {
          row.append(el("span", "muted small", "Already hidden."));
        }
        const dismiss = el("button", "btn ghost small-btn", "Dismiss");
        dismiss.type = "button";
        dismiss.addEventListener("click", async () => {
          await invoke("dismiss_room_report", { id: S.room.id, msg: r.id }).catch(() => {});
          S.room.reports = Math.max(0, S.room.reports - 1);
          loadRoomThread();
        });
        row.append(dismiss);
        one.append(row);
        box.append(one);
      }
      $("room-thread").prepend(box);
    }
  }
  const t = $("room-thread");
  t.scrollTop = t.scrollHeight;
}

$("room-back").addEventListener("click", closeRoom);
/* Leave: a second press confirms (it deletes the room from this device). */
$("room-leave").addEventListener("click", async () => {
  const r = S.room;
  if (!r) return;
  if (!S.leaveArmed && !r.waiting) {
    S.leaveArmed = true;
    $("room-leave").textContent = "Press again to leave";
    setError(
      "room-error",
      r.admin
        ? "You created this room. If you leave, nobody can remove people, choose moderators or change its key again. Its messages are deleted from this device; members keep theirs."
        : "Leaving deletes this room and its messages from this device. Members aren't told and keep what you posted.",
    );
    return;
  }
  try {
    await invoke("leave_room", { id: r.id });
    setError("room-error", "");
    closeRoom();
  } catch (e) {
    setError("room-error", String(e));
  }
});
$("room-members-btn").addEventListener("click", async () => {
  const box = $("room-members");
  if (!box.hidden) {
    box.hidden = true;
    return;
  }
  $("room-apps").hidden = true;
  await paintMembers();
  box.hidden = false;
});

async function paintMembers() {
  const box = $("room-members");
  const r = S.room;
  let list = [];
  let reqs = [];
  try {
    list = await invoke("room_members", { id: r.id });
    if (r.approval) reqs = await invoke("join_requests", { id: r.id });
  } catch (e) {
    box.replaceChildren(el("span", "error small", String(e)));
    return;
  }
  const parts = [];
  if (r.approval) {
    parts.push(el("span", "strong", "Asking to join"));
    parts.push(el("span", "muted small", "Names and handles in requests aren't proven yet; once someone is in, the room checks who they really are."));
    if (!reqs.length) parts.push(el("span", "muted small", "No requests right now."));
    for (const q of reqs) {
      const row = el("div", "member-row");
      const who = el("span", "grow stack-2");
      who.append(el("span", "", q.name + " · @" + q.handle));
      if (q.note) who.append(el("span", "muted small", q.note));
      const yes = el("button", "btn outline small-btn", "Let in");
      const no = el("button", "btn ghost small-btn", "Turn down");
      yes.type = no.type = "button";
      const answer = async (approve) => {
        yes.disabled = no.disabled = true;
        try {
          await invoke("answer_request", { id: r.id, request: q.id, approve });
          row.replaceWith(el("span", "muted small", approve ? q.name + " was let in." : q.name + " was turned down."));
        } catch (e) {
          setError("room-error", String(e));
          yes.disabled = no.disabled = false;
        }
      };
      yes.addEventListener("click", () => answer(true));
      no.addEventListener("click", () => answer(false));
      row.append(who, yes, no);
      parts.push(row);
    }
  }
  parts.push(el("span", "strong", "Members"));
  parts.push(
    el(
      "span",
      "muted small",
      r.admin
        ? "Removing someone gives everyone else a new room key; they keep what they already saw. Moderators can hide messages, remove people and answer requests."
        : "As a moderator you can hide messages, remove people and answer requests. The creator's app finishes each removal with a new room key.",
    ),
  );
  if (!list.length) parts.push(el("span", "muted small", "No one has joined yet."));
  for (const [author, name, removed, isMod] of list) {
    const row = el("div", "member-row");
    const who = el("span", "grow member-name", name + " · @" + author.slice(0, 8) + (isMod ? " · moderator" : ""));
    who.title = "Open their profile";
    who.addEventListener("click", () => openUser(author, name));
    row.append(who);
    if (removed) {
      row.append(el("span", "muted small", "removed"));
    } else {
      if (r.admin) {
        const m = el("button", "btn ghost small-btn", isMod ? "Stop moderating" : "Make moderator");
        m.type = "button";
        m.addEventListener("click", async () => {
          try {
            await invoke("set_moderator", { id: r.id, author, on: !isMod });
          } catch (e) {
            setError("room-error", String(e));
          }
          paintMembers();
        });
        row.append(m);
      }
      if (r.admin || !isMod) {
        const b = el("button", "btn ghost small-btn", "Remove");
        b.type = "button";
        b.addEventListener("click", async () => {
          try {
            await invoke("remove_member", { id: r.id, author });
            b.replaceWith(el("span", "muted small", "removed"));
          } catch (e) {
            setError("room-error", String(e));
          }
        });
        row.append(b);
      }
    }
    parts.push(row);
  }
  box.replaceChildren(...parts);
}

$("room-invite").addEventListener("click", async () => {
  if (!S.room) return;
  try {
    const link = await invoke("room_link", { id: S.room.id });
    const ok = await invoke("copy_secret", { text: link });
    const what = S.room.approval ? "people with it can ask to join" : "anyone with it can read the room";
    $("room-invite-label").textContent = ok ? "Copied: " + what + " · clears in 1 minute" : "Couldn't copy";
  } catch (e) {
    $("room-invite-label").textContent = String(e).slice(0, 60);
  }
});

$("room-create").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const msg = $("room-create-msg");
  try {
    const price = S.newRoom.access === "free" ? 0 : parseInt($("room-price").value, 10) || 0;
    const topics = $("room-topics").value.split(/[,\s]+/).map((t) => t.trim()).filter(Boolean);
    const approval = S.newRoom.access === "free" && $("room-approval").checked;
    const id = await invoke("create_room", { name: $("room-name").value, visibility: S.newRoom.vis, access: S.newRoom.access, price, description: $("room-desc").value, topics, approval });
    $("room-approval").checked = false;
    paintRoomForm();
    $("room-name").value = "";
    $("room-desc").value = "";
    $("room-topics").value = "";
    msg.textContent = "";
    await loadRooms();
    const r = (S.roomList || []).find((x) => x.id === id);
    if (r) openRoom(r);
  } catch (e) {
    msg.textContent = String(e);
  }
});

$("room-join-input").addEventListener("input", async () => {
  const link = $("room-join-input").value.trim();
  const b = await invoke("parse_buy_link", { link });
  const ask = b ? null : await invoke("parse_ask_link", { link });
  S.buy = b;
  S.ask = ask;
  $("room-ask-row").hidden = !ask;
  $("room-join-btn").textContent = b ? "Pay " + b[2] + " credits for " + (b[1] === "pass" ? "a pass to " : "a month in ") + b[0] : ask ? "Ask to join " + ask : "Join";
});
$("room-join").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const msg = $("room-join-msg");
  if (S.buy) {
    try {
      msg.textContent = "Paying privately…";
      await invoke("buy_room", { link: $("room-join-input").value.trim() });
      $("room-join-input").value = "";
      S.buy = null;
      $("room-join-btn").textContent = "Join";
      msg.textContent = "Paid. The room appears here once the creator's app confirms (usually within a few minutes).";
      refreshStatus();
    } catch (e) {
      msg.textContent = String(e);
    }
    return;
  }
  if (S.ask) {
    try {
      await invoke("ask_to_join", { link: $("room-join-input").value.trim(), note: $("room-ask-note").value });
      $("room-join-input").value = "";
      $("room-ask-note").value = "";
      $("room-ask-row").hidden = true;
      S.ask = null;
      $("room-join-btn").textContent = "Join";
      msg.textContent = "Request sent. The room opens here once its admin or a moderator lets you in.";
      loadRooms();
    } catch (e) {
      msg.textContent = String(e);
    }
    return;
  }
  try {
    const id = await invoke("join_room", { link: $("room-join-input").value.trim() });
    $("room-join-input").value = "";
    msg.textContent = "Joined. Earlier messages appear as they're fetched.";
    await loadRooms();
    const r = (S.roomList || []).find((x) => x.id === id);
    if (r) openRoom(r);
    invoke("refresh_rooms")
      .then(() => {
        loadRooms();
        loadRoomThread();
      })
      .catch(() => {});
  } catch (e) {
    msg.textContent = String(e);
  }
});

$("room-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const text = $("room-input").value;
  if (!text.trim() || !S.room) return;
  try {
    await invoke("send_room", { id: S.room.id, text });
    $("room-input").value = "";
    setError("room-error", "");
    loadRoomThread();
  } catch (e) {
    setError("room-error", String(e));
  }
});

listen("rooms", () => {
  if (S.tab !== "rooms") return;
  loadRooms();
  loadRoomThread();
  if (S.room && !$("room-apps").hidden) paintApps();
});

/* ---------- Sentinel Apps in rooms ---------- */

S.appDrafts = new Map(); // "appId:inputId" -> text being typed (survives repaints)

$("room-apps-btn").addEventListener("click", async () => {
  const box = $("room-apps");
  if (!box.hidden) {
    box.hidden = true;
    return;
  }
  $("room-members").hidden = true;
  await paintApps();
  box.hidden = false;
});

async function paintApps() {
  const box = $("room-apps");
  const r = S.room;
  if (!r) return;
  let apps = [];
  try {
    apps = await invoke("room_apps", { id: r.id });
  } catch (e) {
    box.replaceChildren(el("span", "error small", String(e)));
    return;
  }
  const out = [];
  if (!apps.length) {
    out.push(
      el(
        "p",
        "muted small",
        r.admin
          ? "This room has no apps yet. Apps add things like polls to a room. Every member's device runs the same rules, so nobody can fake a result."
          : "This room has no apps yet. The person who made the room can add some.",
      ),
    );
  }
  for (const a of apps) out.push(appFrame(r, a));
  if (r.admin) out.push(await addAppCard(r, apps));
  box.replaceChildren(...out);
  paintIcons(box);
}

function appFrame(r, a) {
  const f = el("section", "app-frame stack-12");
  f.setAttribute("aria-label", "App: " + a.name);
  const head = el("div", "app-head");
  head.append(el("span", "app-badge", "App"), el("span", "strong", a.name), el("span", "muted small grow", a.builtin ? "Built into Sentinel" : "Made by " + a.author));
  if (r.admin) {
    const rm = el("button", "btn ghost small-btn", "Remove");
    rm.type = "button";
    let armed = false;
    rm.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        rm.textContent = "Remove for everyone?";
        return;
      }
      try {
        await invoke("remove_app", { id: r.id, appId: a.id });
        await paintApps();
      } catch (e) {
        rm.textContent = String(e);
      }
    });
    head.append(rm);
  }
  f.append(head);
  if (a.error) {
    f.append(el("p", "muted small", a.error));
    return f;
  }
  const msg = el("p", "small error");
  msg.setAttribute("role", "status");
  const ctx = { r, a, inputs: new Map(), msg };
  const body = el("div", "app-body stack-12");
  renderParts(a.parts, body, ctx);
  f.append(body, msg);
  return f;
}

// Draw an app's screen from its parts. Text is only ever set as text,
// never as HTML, so an app can't add links, scripts or Sentinel look-alikes.
function renderParts(parts, into, ctx) {
  for (const p of parts || []) {
    const kind = typeof p === "string" ? p : Object.keys(p)[0];
    const v = typeof p === "string" ? null : p[kind];
    switch (kind) {
      case "Title":
        into.append(el("h3", "app-title", v));
        break;
      case "Text":
        into.append(el("p", "app-text", v));
        break;
      case "Muted":
        into.append(el("p", "muted small", v));
        break;
      case "Member":
        into.append(el("span", "app-member", v));
        break;
      case "Input": {
        const lab = el("label", "field tight");
        lab.append(el("span", "muted small", v.label));
        const i = el("input");
        i.type = "text";
        i.maxLength = v.max;
        i.autocomplete = "off";
        const key = ctx.a.id + ":" + v.id;
        i.value = S.appDrafts.get(key) || "";
        i.addEventListener("input", () => S.appDrafts.set(key, i.value));
        ctx.inputs.set(v.id, i);
        lab.append(i);
        into.append(lab);
        break;
      }
      case "Button": {
        const b = el("button", v.primary ? "btn primary" : "btn outline small-btn", v.label);
        b.type = "button";
        b.addEventListener("click", () => appAction(ctx, v, b));
        into.append(b);
        break;
      }
      case "Bar": {
        const pct = v.total ? Math.round((v.value * 100) / v.total) : 0;
        const row = el("div", "app-bar" + (v.mine ? " mine" : ""));
        const top = el("div", "app-bar-top");
        top.append(el("span", null, v.label + (v.mine ? " · your vote" : "")), el("span", "muted small", v.value + (v.total ? " · " + pct + "%" : "")));
        const track = el("div", "app-bar-track");
        const fill = el("span");
        fill.style.width = pct + "%";
        track.append(fill);
        row.append(top, track);
        into.append(row);
        break;
      }
      case "Row": {
        const d = el("div", "app-row");
        renderParts(v, d, ctx);
        into.append(d);
        break;
      }
      case "Card": {
        const d = el("div", "app-card stack-8");
        renderParts(v, d, ctx);
        into.append(d);
        break;
      }
      case "Divider":
        into.append(el("hr", "app-divider"));
        break;
    }
  }
}

async function appAction(ctx, v, btn) {
  const inputs = [...ctx.inputs].map(([id, i]) => [id, i.value]);
  btn.disabled = true;
  ctx.msg.textContent = "";
  try {
    await invoke("app_action", { id: ctx.r.id, appId: ctx.a.id, action: v.action, arg: v.arg, inputs });
    if (inputs.some(([, val]) => val.trim())) {
      for (const k of [...S.appDrafts.keys()]) if (k.startsWith(ctx.a.id + ":")) S.appDrafts.delete(k);
    }
    await paintApps();
  } catch (e) {
    ctx.msg.textContent = String(e);
    btn.disabled = false;
  }
}

async function addAppCard(r, apps) {
  const card = el("div", "card stack-12 app-add");
  card.append(el("span", "strong", "Add an app"));
  let cat = [];
  try {
    cat = await invoke("app_catalog");
  } catch {}
  const offers = el("div", "stack-12");
  for (const c of cat.filter((c) => !apps.some((a) => a.id === c.id))) offers.append(appOffer(r, c));
  const note = el("p", "muted small", "Only add apps from people you trust. Apps can't reach the internet or see anything outside this room, but they decide what happens inside it.");
  const file = el("button", "btn ghost small-btn", "Add an app from a file…");
  file.type = "button";
  file.addEventListener("click", async () => {
    try {
      const c = await invoke("choose_app_file");
      if (c) offers.replaceChildren(appOffer(r, c));
    } catch (e) {
      note.textContent = String(e);
    }
  });
  card.append(offers, file, note);
  return card;
}

function appOffer(r, c) {
  const d = el("div", "app-offer stack-8");
  d.append(el("span", "strong", c.name), el("span", "muted small", c.builtin ? "Built into Sentinel" : "Made by " + c.author + " (check this with them)"), el("span", "small", c.description));
  const can = el("ul", "app-perms small");
  for (const x of c.can) can.append(el("li", null, x));
  const cannot = el("ul", "app-perms small muted");
  for (const x of c.cannot) cannot.append(el("li", null, x));
  d.append(el("span", "small strong", "It can"), can, el("span", "small strong", "It can't"), cannot);
  const b = el("button", "btn primary small-btn", "Add " + c.name + " to this room");
  b.type = "button";
  const err = el("p", "error small");
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await invoke("add_app", { id: r.id, appId: c.id });
      await paintApps();
    } catch (e) {
      err.textContent = String(e);
      b.disabled = false;
    }
  });
  d.append(b, err);
  return d;
}


/* ---------- profiles ---------- */

const PICS = new Map(); // "which:author:version" -> Promise<blob URL>
S.picVersion = 0;

function pictureUrl(author, which) {
  const k = which + ":" + author + ":" + S.picVersion;
  if (!PICS.has(k)) {
    const pr = invoke("profile_image", { author, which }).then((buf) => URL.createObjectURL(new Blob([buf], { type: "image/jpeg" })));
    pr.catch(() => PICS.delete(k));
    PICS.set(k, pr);
  }
  return PICS.get(k);
}

function forgetPictures() {
  for (const pr of PICS.values()) pr.then((u) => URL.revokeObjectURL(u), () => {});
  PICS.clear();
}

/** Put a profile picture into an avatar circle or banner box. */
function setPicture(box, author, which) {
  pictureUrl(author, which).then(
    (u) => {
      const img = document.createElement("img");
      img.src = u;
      img.alt = "";
      box.replaceChildren(img);
    },
    () => {},
  );
}

async function loadMyProfile() {
  loadCircle();
  let pr;
  try {
    pr = await invoke("my_profile");
  } catch {
    return;
  }
  $("profile-bio").textContent = pr.bio;
  const av = $("my-avatar");
  av.textContent = initial(pr.name);
  if (pr.avatar) setPicture(av, "me", "avatar");
  const bn = $("my-banner");
  bn.replaceChildren();
  if (pr.banner) setPicture(bn, "me", "banner");
  S.myProfile = pr;
}

$("edit-profile").addEventListener("click", () => {
  const f = $("profile-form");
  f.hidden = !f.hidden;
  if (!f.hidden && S.myProfile) {
    $("pf-name").value = S.myProfile.name;
    $("pf-bio").value = S.myProfile.bio;
    $("pf-bio").dispatchEvent(new Event("input"));
  }
});
$("pf-cancel").addEventListener("click", () => ($("profile-form").hidden = true));
$("pf-bio").addEventListener("input", () => ($("pf-bio-count").textContent = [...$("pf-bio").value].length + "/300"));
$("profile-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await invoke("update_profile", { name: $("pf-name").value, bio: $("pf-bio").value });
    $("profile-form").hidden = true;
    $("pf-msg").textContent = "";
    await refreshStatus();
    loadMyProfile();
    loadTimeline();
  } catch (e) {
    $("pf-msg").textContent = String(e);
  }
});
document.querySelectorAll("[data-pick]").forEach((b) =>
  b.addEventListener("click", async () => {
    $("pf-msg").textContent = "Removing metadata and encrypting…";
    try {
      if (await invoke("pick_profile_image", { which: b.dataset.pick })) {
        S.picVersion++;
        $("pf-msg").textContent = "Saved. It is published with your profile on the next sync.";
        loadMyProfile();
        loadTimeline();
      } else $("pf-msg").textContent = "";
    } catch (e) {
      $("pf-msg").textContent = String(e);
    }
  }),
);
document.querySelectorAll("[data-remove]").forEach((b) =>
  b.addEventListener("click", async () => {
    await invoke("remove_profile_image", { which: b.dataset.remove });
    S.picVersion++;
    loadMyProfile();
    loadTimeline();
  }),
);

/* someone's profile */
/** Open someone's profile. `nameHint`: the name a room or message already
 * knows, for people I don't follow (their profile isn't fetched). */
async function openUser(author, nameHint) {
  let pr;
  try {
    pr = await invoke("user_profile", { author });
  } catch {
    return;
  }
  if (pr.mine) {
    setTab("profile");
    return;
  }
  if (nameHint && pr.name === pr.handle) pr.name = nameHint;
  // Back returns where I came from (a room, Discover, …).
  if (S.tab !== "user") S.userFrom = { tab: S.tab, room: S.room };
  S.user = pr;
  setTab("user");
  $("user-note").hidden = pr.following;
  $("user-title").textContent = pr.name;
  $("user-name").textContent = pr.name;
  $("user-handle").textContent = "@" + pr.handle;
  $("user-bio").textContent = pr.bio;
  const av = $("user-avatar");
  av.textContent = initial(pr.name);
  if (pr.avatar) setPicture(av, pr.author, "avatar");
  const bn = $("user-banner");
  bn.replaceChildren();
  if (pr.banner) setPicture(bn, pr.author, "banner");
  $("user-message").hidden = !pr.canMessage || pr.blocked;
  const cb = $("user-circle");
  cb.hidden = !pr.following || pr.blocked || !pr.canMessage;
  cb.disabled = pr.circleState !== "";
  cb.textContent = pr.circleState === "approved" ? "Approved follower" : pr.circleState === "requested" ? "Asked to be approved" : "Ask to be approved";
  cb.title = "Ask them to add you to their approved followers (sent as an encrypted message)";
  $("user-unfollow").hidden = !pr.following;
  $("user-mute").textContent = pr.muted ? "Unmute" : "Mute";
  $("user-block").textContent = pr.blocked ? "Unblock" : "Block";
  $("user-mute").hidden = pr.blocked;
  $("user-safety").hidden = true;
  $("user-feed").replaceChildren(...S.posts.filter((x) => x.author === author).map(postNode));
}
$("user-back").addEventListener("click", () => {
  const from = S.userFrom || { tab: "home" };
  setTab(from.tab);
  if (from.tab === "rooms" && from.room) openRoom(from.room);
});
$("user-circle").addEventListener("click", async () => {
  const u = S.user;
  try {
    await invoke("request_circle", { author: u.author });
  } catch (e) {
    $("user-circle").title = String(e);
    return;
  }
  openUser(u.author);
});
async function loadCircle() {
  let v;
  try {
    v = await invoke("circle_view");
  } catch {
    return;
  }
  const row = (person, buttons) => {
    const r = el("div", "inline-actions");
    r.append(el("span", "small grow", person.name + " · @" + person.handle), ...buttons);
    return r;
  };
  const btn = (label, cls, fn) => {
    const b = el("button", "btn " + cls + " small-btn", label);
    b.type = "button";
    b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        await fn();
      } catch (e) {
        $("circle-msg").textContent = String(e);
      }
      loadCircle();
    });
    return b;
  };
  $("circle-requests").replaceChildren(
    ...(v.requests.length ? [el("span", "muted small", "Asking to be approved:")] : []),
    ...v.requests.map((p) => row(p, [btn("Approve", "outline", () => invoke("approve_circle", { author: p.author })), btn("Decline", "ghost", () => invoke("decline_circle", { author: p.author }))])),
  );
  $("circle-members").replaceChildren(
    el("span", "muted small", v.members.length ? "Approved (" + v.members.length + "):" : "Nobody approved yet. People who follow you can ask from your profile."),
    ...v.members.map((p) =>
      row(p, [
        btn("Remove", "ghost", async () => {
          const n = await invoke("remove_circle", { author: p.author });
          $("circle-msg").textContent = "Removed. New key sent to " + n + " approved follower" + (n === 1 ? "" : "s") + ".";
        }),
      ]),
    ),
  );
}
$("user-mute").addEventListener("click", async () => {
  const u = S.user;
  try {
    await invoke("set_muted", { author: u.author, on: !u.muted });
  } catch (e) {
    return;
  }
  await loadTimeline();
  openUser(u.author);
});
$("user-block").addEventListener("click", async () => {
  const u = S.user;
  try {
    await invoke("set_blocked", { author: u.author, on: !u.blocked });
  } catch (e) {
    return;
  }
  await loadTimeline();
  openUser(u.author);
});
async function loadHidden() {
  let list = [];
  try {
    list = await invoke("hidden_people");
  } catch {
    /* locked */
  }
  const box = $("hidden-list");
  if (!list.length) {
    box.replaceChildren(el("span", "muted small", "Nobody."));
    return;
  }
  box.replaceChildren(
    ...list.map((h) => {
      const row = el("div", "inline-actions");
      const undo = el("button", "btn ghost small-btn", h.blocked ? "Unblock" : "Unmute");
      undo.type = "button";
      undo.addEventListener("click", async () => {
        await invoke(h.blocked ? "set_blocked" : "set_muted", { author: h.author, on: false });
        await loadTimeline();
        loadHidden();
      });
      row.append(el("span", "small", h.name + " · @" + h.handle + (h.blocked ? " · blocked" : " · muted")), undo);
      return row;
    }),
  );
}
$("user-message").addEventListener("click", () => {
  const u = S.user;
  setTab("messages");
  openThread({ author: u.author, name: u.name, handle: u.handle, canMessage: true });
});
$("user-verify").addEventListener("click", async () => {
  $("user-safety-digits").textContent = await invoke("safety_number", { author: S.user.author });
  $("user-safety").hidden = false;
});

/* connection: Tor / bridges / private bridges */
S.conn = null;
function paintConn() {
  const c = S.conn;
  if (!c) return;
  document.querySelectorAll("[data-conn]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.conn === c.mode)));
  document.querySelectorAll("[data-bset]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.bset === c.builtin)));
  $("bridge-opts").hidden = c.mode !== "bridges";
  $("bridge-count").textContent = c.custom ? "(" + c.custom + " saved)" : "";
}
async function loadConn() {
  try {
    S.conn = await invoke("connection");
    paintConn();
  } catch {
    /* locked */
  }
}
document.querySelectorAll("[data-conn]").forEach((b) => b.addEventListener("click", () => { S.conn.mode = b.dataset.conn; paintConn(); }));
document.querySelectorAll("[data-bset]").forEach((b) => b.addEventListener("click", () => { S.conn.builtin = b.dataset.bset; paintConn(); }));
$("conn-save").addEventListener("click", async () => {
  const text = $("bridge-lines").value.trim();
  try {
    // Lines are sent only when typed; saved bridges are never shown again.
    await invoke("set_connection", { mode: S.conn.mode, builtin: S.conn.builtin, custom: text ? text.split(/\n+/) : null });
    $("bridge-lines").value = "";
    $("conn-msg").textContent = "Saved. Lock and unlock Sentinel to reconnect this way.";
    loadConn();
  } catch (e) {
    $("conn-msg").textContent = String(e);
  }
});

/* credits, storage checks, archive capacity */
function paintCredits() {
  const st = S.status;
  if (!st) return;
  $("credit-balance").textContent = String(st.credits || 0);
  const pend = st.creditsPending || 0;
  $("credit-pending").textContent = pend ? pend + (pend === 1 ? " more on the way (checked by its issuer every few minutes)" : " more on the way (checked by their issuers every few minutes)") : "";
}
async function loadStorageHealth() {
  try {
    const h = await invoke("storage_health");
    $("check-storage").hidden = !h.archives;
    $("storage-health").textContent = h.archives
      ? h.passed + " checks passed · " + h.failed + " failed · " + h.archives + " Archives · " + h.pending + " checks scheduled" + (h.unreliable ? " · " + h.unreliable + " Archives avoided" : "")
      : "No large files uploaded yet.";
  } catch {
    /* locked */
  }
}
$("check-storage").addEventListener("click", async () => {
  $("check-msg").textContent = "Checking over Tor…";
  try {
    $("check-msg").textContent = (await invoke("check_storage")) ? "Passed: the Archive still holds it." : "Nothing to check, or the Archive failed.";
  } catch (e) {
    $("check-msg").textContent = String(e);
  }
  loadStorageHealth();
});
$("import-credits-btn").addEventListener("click", async () => {
  try {
    const n = await invoke("import_credits");
    if (n != null) $("credit-msg").textContent = "Imported " + n + " credit parts. You can delete the file now.";
    refreshStatus();
  } catch (e) {
    $("credit-msg").textContent = String(e);
  }
});
$("self-seed").addEventListener("click", async () => {
  const on = $("self-seed").getAttribute("aria-checked") !== "true";
  try {
    await invoke("set_self_seed", { on });
  } catch (e) {
    $("host-status").textContent = String(e);
  }
  refreshStatus();
});

/* account & security */
$("pass-generate").addEventListener("click", async () => {
  const i = $("pass-new");
  i.type = "text";
  i.value = await invoke("generate_passphrase");
  S.generated = i.value;
  $("pass-wrote").checked = false;
  showWords("pass", i.value);
});
$("pass-new").addEventListener("input", () => showWords("pass", $("pass-new").value));
$("emergency-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("em-msg").textContent = "Saving… (this takes a few seconds)";
  try {
    const set = await invoke("set_emergency", { current: $("em-current").value, emergency: $("em-pass").value, name: $("em-name").value || (S.status && S.status.name) || "" });
    $("em-msg").textContent = set ? "Emergency passphrase saved." : "Emergency passphrase removed.";
  } catch (e) {
    $("em-msg").textContent = String(e);
  }
  $("em-current").value = "";
  $("em-pass").value = "";
});
$("pass-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const n = $("pass-new").value;
  if (passBits(n) < MIN_BITS) {
    $("pass-msg").textContent = "That passphrase is too weak. Press Generate.";
    return;
  }
  if (n === S.generated && !$("pass-wrote").checked) {
    $("pass-msg").textContent = "Write the new words down first, then tick the box.";
    return;
  }
  try {
    await invoke("change_passphrase", { old: $("pass-old").value, new: n });
    $("pass-old").value = "";
    $("pass-new").value = "";
    $("pass-new").type = "password";
    showWords("pass", "");
    $("pass-msg").textContent = "Passphrase changed. Older backups still open with the old one.";
  } catch (e) {
    $("pass-msg").textContent = String(e);
  }
});
async function saveBackup(allowCloud) {
  const m = $("backup-msg");
  try {
    const r = await invoke("export_backup", { allowCloud });
    if (r.started) m.textContent = "Backup saved. It opens only with your passphrase; keep it off cloud drives.";
    else if (r.cloud) {
      m.textContent = "That folder syncs to " + r.cloud + ", which would get a copy it could try to crack offline. ";
      const again = el("button", "btn ghost small-btn", "Save there anyway");
      again.type = "button";
      again.addEventListener("click", () => saveBackup(true));
      m.append(again);
    } else m.textContent = "";
  } catch (e) {
    m.textContent = String(e);
  }
}
$("backup-btn").addEventListener("click", () => saveBackup(false));
$("wipe-btn").addEventListener("click", async () => {
  try {
    await invoke("panic_wipe", { confirm: $("wipe-confirm").value.trim() });
  } catch (e) {
    $("wipe-msg").textContent = String(e);
  }
});

/* follow */
$("follow-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const msg = $("follow-msg");
  try {
    await invoke("follow", { link: $("follow-input").value });
    $("follow-input").value = "";
    msg.textContent = "Following. Their posts will appear shortly.";
    refreshStatus();
  } catch (e) {
    msg.textContent = String(e);
  }
});

/* profile link */
$("copy-link").addEventListener("click", async () => {
  noteShared();
  if (!S.status.link) return;
  // Copied outside clipboard history and cloud sync; cleared after a minute.
  const ok = await invoke("copy_secret", { text: S.status.link });
  $("copy-link-label").textContent = ok ? "Copied · clears in 1 minute" : "Couldn't copy";
});

/* privacy */
const PRIVACY = [
  ["disappearing", "Disappearing messages", "Direct and room messages are deleted after 7 days on this device. Your DMs carry the timer, so the other person's app deletes them too."],
  ["screenSecurity", "Screen security", "Blocks screenshots, screen recording, screen sharing and Windows Recall from capturing this window."],
  ["autoLock", "Lock when I step away", "Locks Sentinel after 15 minutes without use (5 minutes in High-risk mode), so a computer left open doesn't stay readable."],
  ["mix", "Mix my messages", "Messages and room posts travel through two other Pillars, each holding them for a random time (usually a minute or two, up to ten) before passing them on. Someone watching the whole network can't match when you send with when it arrives. Slower; always on in High-risk mode."],
  ["showCount", "Show my follower count", "Counts come from anonymous notices; nobody can see who follows you either way."],
  ["highRisk", "High-risk mode", "Keeps your posts out of Discover, stops follow notices, sends posts after a random 2–20 minute delay, adds background cover traffic so activity bursts don't show when you read or post, never keeps viewed media on disk, and turns off running a Pillar."],
];

function paintPrivacy() {
  const phone = !!(S.status && (S.status.platform === "android" || S.status.platform === "ios"));
  const p = Object.assign({}, (S.status && S.status.privacy) || {});
  // "Show my follower count" is the inverse of the stored hideCount flag.
  p.showCount = !(S.status && S.status.hideCount);
  const list = $("privacy-list");
  paintDiscoverToggle();
  list.replaceChildren(
    // Phones always block screenshots and screen recording of Sentinel.
    ...PRIVACY.filter(([key]) => !(phone && key === "screenSecurity")).map(([key, title, desc]) => {
      const row = el("div", "row-setting");
      const text = el("div", "stack-4");
      text.append(el("span", "setting-title", title), el("span", "muted small", desc));
      const t = el("button", "toggle");
      t.type = "button";
      t.setAttribute("role", "switch");
      t.setAttribute("aria-label", title);
      t.setAttribute("aria-checked", String(!!p[key]));
      t.addEventListener("click", async () => {
        const on = t.getAttribute("aria-checked") !== "true";
        if (key === "showCount") {
          await invoke("set_hide_count", { hide: !on });
          S.status.hideCount = !on;
        } else {
          await invoke("set_privacy", { key, on });
          S.status.privacy[key] = on;
        }
        t.setAttribute("aria-checked", String(on));
        await refreshStatus();
      });
      row.append(text, t);
      return row;
    }),
  );
}

$("pillar-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await invoke("set_pillar", { onion: $("pillar-input").value });
    $("pillar-msg").textContent = "Saved. Your posts and profile will be published there.";
    refreshStatus();
  } catch (e) {
    $("pillar-msg").textContent = String(e);
  }
});

/* ---------- boot ---------- */

(async function boot() {
  paintIcons();
  paintChoice();
  paintRoomForm();
  S.disguised = await invoke("disguise_state").catch(() => false);
  paintDisguise();
  const st = await invoke("status");
  S.status = st;
  if (!st.initialized) show("welcome");
  else if (!st.unlocked) {
    show("unlock");
    $("unlock-pass").focus();
  } else await startConnecting();
})();

/* disguise: a working calculator in front of the unlock screen */
const C = { cur: "0", acc: null, op: null, fresh: false, typed: "" };
function calcPaint() {
  let t = C.cur;
  if (t.length > 14) t = Number(t).toPrecision(10).replace(/\.?0+(e|$)/, "$1");
  $("calc-display").textContent = t;
}
function calcApply(a, b, op) {
  const r = op === "+" ? a + b : op === "-" ? a - b : op === "*" ? a * b : op === "/" ? (b === 0 ? NaN : a / b) : b;
  return Number.isFinite(r) ? String(parseFloat(r.toPrecision(12))) : "Error";
}
function calcReset() {
  Object.assign(C, { cur: "0", acc: null, op: null, fresh: false, typed: "" });
}
async function calcKey(k) {
  if (/^[0-9]$/.test(k)) {
    C.cur = C.fresh || C.cur === "0" || C.cur === "Error" ? k : C.cur.length < 16 ? C.cur + k : C.cur;
    C.fresh = false;
    C.typed = (C.typed + k).slice(-12);
  } else if (k === ".") {
    if (C.fresh || C.cur === "Error") C.cur = "0";
    if (!C.cur.includes(".")) C.cur += ".";
    C.fresh = false;
    C.typed = "";
  } else if (k === "C") {
    calcReset();
  } else if (k === "back") {
    if (!C.fresh) C.cur = C.cur.length > 1 ? C.cur.slice(0, -1) : "0";
    C.typed = C.typed.slice(0, -1);
  } else if (k === "neg") {
    if (C.cur !== "0" && C.cur !== "Error") C.cur = C.cur.startsWith("-") ? C.cur.slice(1) : "-" + C.cur;
    C.typed = "";
  } else if (k === "%") {
    C.cur = calcApply(parseFloat(C.cur), 100, "/");
    C.typed = "";
  } else if ("+-*/".includes(k)) {
    if (C.op && !C.fresh) C.cur = calcApply(C.acc, parseFloat(C.cur), C.op);
    C.acc = parseFloat(C.cur);
    C.op = k;
    C.fresh = true;
    C.typed = "";
  } else if (k === "=") {
    const typed = C.typed;
    C.typed = "";
    // The code typed on its own, then "=": the unlock screen.
    if (typed.length >= 4 && !C.op && (await invoke("disguise_check", { code: typed }).catch(() => false))) {
      calcReset();
      calcPaint();
      S.calcPassed = true;
      const st = await invoke("status").catch(() => null);
      show(st && st.initialized ? "unlock" : "welcome");
      if (st && st.initialized) $("unlock-pass").focus();
      return;
    }
    if (C.op) {
      C.cur = calcApply(C.acc, parseFloat(C.cur), C.op);
      C.op = null;
      C.acc = null;
    }
    C.fresh = true;
  }
  calcPaint();
}
document.querySelectorAll("[data-k]").forEach((b) => b.addEventListener("click", () => calcKey(b.dataset.k)));
document.addEventListener("keydown", (e) => {
  if ($("disguise").hidden) return;
  const map = { Enter: "=", "=": "=", Escape: "C", Delete: "C", Backspace: "back" };
  const k = map[e.key] || (/^[0-9.+\-*/%]$/.test(e.key) ? e.key : null);
  if (k) {
    e.preventDefault();
    calcKey(k);
  }
});

/* Settings: turn the disguise on or off */
function paintDisguise() {
  document.title = S.disguised ? "Calculator" : "The Sentinel Protocol";
  $("disguise-off").hidden = !S.disguised;
  $("disguise-save").textContent = S.disguised ? "Change code" : "Turn on";
}
$("disguise-save").addEventListener("click", async () => {
  const code = $("disguise-code").value.trim();
  try {
    await invoke("set_disguise", { code });
    $("disguise-code").value = "";
    S.disguised = true;
    S.calcPassed = true;
    $("disguise-msg").textContent = "On. Next time Sentinel locks, it shows a calculator: type your code and press = to unlock.";
  } catch (e) {
    $("disguise-msg").textContent = String(e);
  }
  paintDisguise();
});
$("disguise-off").addEventListener("click", async () => {
  try {
    await invoke("set_disguise", { code: null });
    S.disguised = false;
    $("disguise-msg").textContent = "Off. Sentinel shows its own name and icon again.";
  } catch (e) {
    $("disguise-msg").textContent = String(e);
  }
  paintDisguise();
});

/* key files: chosen with the native dialog; only a fingerprint is kept, in memory */
async function pickKeyfile(make, label) {
  try {
    const name = await invoke(make ? "make_keyfile" : "choose_keyfile");
    if (name) $(label).textContent = (make ? "New key file saved: " : "Key file: ") + name;
    return name;
  } catch (e) {
    $(label).textContent = String(e);
    return null;
  }
}
$("unlock-keyfile").addEventListener("click", async () => {
  if (await pickKeyfile(false, "unlock-keyfile-name")) $("unlock-keyfile").textContent = "Use a different key file";
  $("unlock-pass").focus();
});
$("account-keyfile").addEventListener("click", () => pickKeyfile(false, "account-keyfile-name"));
$("account-keyfile-new").addEventListener("click", () => pickKeyfile(true, "account-keyfile-name"));
$("keyfile-choose").addEventListener("click", () => pickKeyfile(false, "keyfile-chosen"));
$("keyfile-new").addEventListener("click", () => pickKeyfile(true, "keyfile-chosen"));
function paintKeyfile() {
  const on = !!(S.status && S.status.keyfile);
  $("keyfile-state").textContent = on ? "This account needs a key file to unlock." : "No key file: your passphrase alone unlocks this account.";
  $("keyfile-remove").hidden = !on;
  $("keyfile-save").textContent = on ? "Switch to this key file" : "Use this key file";
}
async function saveKeyfile(remove) {
  try {
    const on = await invoke("set_keyfile", { current: $("keyfile-current").value, remove });
    $("keyfile-current").value = "";
    $("keyfile-chosen").textContent = "";
    $("keyfile-msg").textContent = on ? "Done. From now on, unlock with your passphrase and this key file." : "Removed. Your passphrase alone unlocks this account now.";
    await refreshStatus();
  } catch (e) {
    $("keyfile-msg").textContent = String(e);
  }
  paintKeyfile();
}
$("keyfile-save").addEventListener("click", () => saveKeyfile(false));
$("keyfile-remove").addEventListener("click", () => saveKeyfile(true));
document.querySelectorAll("[data-settings]").forEach((b) => b.addEventListener("click", paintKeyfile));

/* updates */
async function paintUpdate() {
  let u;
  try {
    u = await invoke("update_status");
  } catch {
    return;
  }
  S.update = u;
  let state = "You have version " + u.current + ".";
  if (u.progress != null) state += " Downloading an update: " + Math.round(u.progress * 100) + "%.";
  else if (u.checking) state += " Checking…";
  else if (u.ready) {
    state += " Version " + u.ready.version + " is downloaded and checked (" + u.ready.sizeMb + " MB)." + (u.ready.notes ? " " + u.ready.notes : "");
    const now = Date.now() / 1000;
    if (u.ready.handed) state += " It was handed to you as a file, so it hasn't been compared with what others got: install it only if you trust who gave it to you.";
    else if (u.ready.sources < 2) state += " Waiting until another Pillar carries the very same update.";
    else if (now < u.ready.installableAt) state += " It can be installed from " + new Date(u.ready.installableAt * 1000).toLocaleDateString() + ": every update waits three days, so a bad one can be caught and revoked first.";
  }
  $("update-state").textContent = state;
  const canInstall = !!u.ready && (u.ready.handed || (u.ready.sources >= 2 && Date.now() / 1000 >= u.ready.installableAt));
  $("update-install").hidden = !canInstall;
  if (u.message) $("update-msg").textContent = u.message;
  // A quiet note in the side panel when one is ready.
  const line = $("status-line");
  if (line && canInstall && !line.dataset.update) {
    line.dataset.update = "1";
    const b = el("button", "link-btn small", " Update " + u.ready.version + " ready");
    b.type = "button";
    b.addEventListener("click", () => {
      setTab("privacy");
      S.settingsGroup = "connection";
      paintSettings();
    });
    line.after(b);
  }
}
listen("update", paintUpdate);
$("update-check").addEventListener("click", async () => {
  $("update-msg").textContent = "Checking over Tor…";
  try {
    await invoke("check_updates");
  } catch (e) {
    $("update-msg").textContent = String(e);
  }
  paintUpdate();
});
$("update-file").addEventListener("click", async () => {
  try {
    const r = await invoke("update_from_file");
    if (r) $("update-msg").textContent = "Checked: version " + r.version + " is genuine and newer. You can install it now.";
  } catch (e) {
    $("update-msg").textContent = "Not installed: " + String(e);
  }
  paintUpdate();
});
$("update-install").addEventListener("click", async () => {
  $("update-msg").textContent = "Installing… Sentinel restarts by itself.";
  try {
    await invoke("install_update");
  } catch (e) {
    $("update-msg").textContent = String(e);
  }
});
document.querySelectorAll("[data-settings]").forEach((b) => b.addEventListener("click", paintUpdate));
paintUpdate();

/* recovery words */
async function paintRecovery() {
  let r;
  try {
    r = await invoke("recovery_status");
  } catch {
    return;
  }
  S.recovery = r;
  $("recovery-state").textContent = !r.set
    ? "This account doesn't have recovery words yet."
    : r.pending
      ? "Not written down yet. Until you do, losing this device means losing your account."
      : "Set. You wrote them down." + (r.generation ? " Your account has moved to a new key " + r.generation + (r.generation === 1 ? " time." : " times.") : "");
  $("recovery-show").hidden = !(r.set && r.pending);
  $("recovery-create").hidden = r.set;
  // A quiet reminder in the side panel until they're written down.
  const line = $("status-line");
  if (line && r.pending && !line.dataset.recovery) {
    line.dataset.recovery = "1";
    const b = el("button", "link-btn small", " Write down your recovery words");
    b.type = "button";
    b.id = "recovery-nudge";
    b.addEventListener("click", () => {
      setTab("privacy");
      S.settingsGroup = "safety";
      paintSettings();
      paintRecovery();
    });
    line.after(b);
  }
  if (!r.pending && $("recovery-nudge")) $("recovery-nudge").remove();
}
$("recovery-show").addEventListener("click", async () => {
  try {
    const words = await invoke("recovery_words");
    $("recovery-word-list").replaceChildren(...words.map((w) => el("li", "", w)));
    $("recovery-words-box").hidden = false;
    $("recovery-show").hidden = true;
  } catch (e) {
    $("recovery-state").textContent = String(e);
  }
});
$("recovery-wrote").addEventListener("change", () => ($("recovery-confirm").disabled = !$("recovery-wrote").checked));
$("recovery-confirm").addEventListener("click", async () => {
  await invoke("recovery_confirm").catch(() => {});
  $("recovery-word-list").replaceChildren();
  $("recovery-words-box").hidden = true;
  $("recovery-wrote").checked = false;
  paintRecovery();
});
$("recovery-create").addEventListener("click", async () => {
  try {
    await invoke("recovery_create");
  } catch (e) {
    $("recovery-state").textContent = String(e);
  }
  await paintRecovery();
  $("recovery-show").click();
});
$("move-go").addEventListener("click", async () => {
  $("move-msg").textContent = "Signing the move and telling the network over Tor…";
  try {
    await invoke("move_account", { words: $("move-words").value, taken: $("move-taken").checked });
    $("move-words").value = "";
    $("move-msg").textContent = $("move-taken").checked
      ? "Moved. Followers switch over automatically. Share your new follow link (Profile) with people who should see your private posts."
      : "Moved. Followers switch over automatically and keep reading.";
    await refreshStatus();
  } catch (e) {
    $("move-msg").textContent = String(e);
  }
  paintRecovery();
});
document.querySelectorAll("[data-settings]").forEach((b) => b.addEventListener("click", paintRecovery));

/* release key holders */
$("rk-create").addEventListener("click", async () => {
  try {
    const r = await invoke("release_key_create");
    if (!r) return;
    $("rk-line").value = r[0];
    $("rk-line-box").hidden = false;
    $("rk-create-msg").textContent = r[1] ? "Saved on your USB stick. Unplug it and keep it safe." : "Saved, but not on a USB stick: move the key file to one and delete it from this computer.";
  } catch (e) {
    $("rk-create-msg").textContent = String(e);
    $("rk-line-box").hidden = false;
  }
});
$("rk-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("rk-line").value).catch(() => {});
  $("rk-create-msg").textContent = "Copied. Send it to the person who builds releases.";
});
function paintBundle(v) {
  const box = $("rk-bundle");
  const files = v.files.map((f) => el("span", "mono small", f[0] + " · " + Math.max(1, Math.round(f[1] / 1e6)) + " MB · fingerprint " + f[2]));
  box.replaceChildren(
    el("span", "strong", "Sentinel " + (v.product === "app" ? "app" : "Pillar") + " " + v.version + " (" + v.platform + ")"),
    el("span", "small", v.notes || "No notes."),
    ...files,
    el("span", "muted small", v.signatures + " of " + v.needed + " signatures needed" + (v.valid ? ": apps already accept it." : ".")),
  );
  box.hidden = false;
}
$("rk-pick").addEventListener("click", async () => {
  $("rk-msg").textContent = "";
  try {
    const r = await invoke("release_pick_bundle");
    if (!r) return;
    S.rkBundle = r[0];
    paintBundle(r[1]);
    $("rk-sign").hidden = false;
    $("rk-revoke").hidden = false;
  } catch (e) {
    $("rk-msg").textContent = String(e);
  }
});
for (const [id, revoke] of [["rk-sign", false], ["rk-revoke", true]]) {
  $(id).addEventListener("click", async () => {
    $("rk-msg").textContent = "Plug in your USB stick and choose your key file…";
    try {
      const msg = await invoke("release_sign", { bundle: S.rkBundle, revoke });
      $("rk-msg").textContent = msg || "";
      const r = await invoke("release_pick_bundle").catch(() => null);
      if (r && r[0] === S.rkBundle) paintBundle(r[1]);
    } catch (e) {
      $("rk-msg").textContent = String(e);
    }
  });
}

/* unfollow */
$("user-unfollow").addEventListener("click", async () => {
  const u = S.user;
  if (!u) return;
  if (!S.unfollowArmed) {
    S.unfollowArmed = true;
    $("user-unfollow").textContent = "Press again to unfollow";
    return;
  }
  S.unfollowArmed = false;
  try {
    await invoke("unfollow", { author: u.author });
  } catch {}
  await refreshStatus();
  loadTimeline();
  openUser(u.author, u.name);
});

/* this device joins an account from another device */
$("welcome-link").addEventListener("click", () => {
  show("linkdev");
  $("linkdev-code").focus();
});
$("linkdev-back").addEventListener("click", () => show("welcome"));
$("linkdev-generate").addEventListener("click", async () => {
  const i = $("linkdev-pass");
  i.type = "text";
  i.value = await invoke("generate_passphrase");
});
$("linkdev-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setError("linkdev-error", "");
  try {
    const check = await invoke("link_join", { code: $("linkdev-code").value, device: $("linkdev-name").value, pass: $("linkdev-pass").value, mode: S.mode || "tor" });
    $("linkdev-pass").value = "";
    $("linkwait-code").textContent = check;
    show("linkwait");
    startConnecting();
  } catch (e) {
    setError("linkdev-error", String(e));
  }
});
async function waitForLink() {
  show("linkwait");
  $("linkwait-code").textContent = S.status.linking;
  $("linkwait-state").textContent = "Waiting for your other device to allow this one…";
  for (;;) {
    await new Promise((r) => setTimeout(r, 4000));
    await invoke("refresh_rooms").catch(() => {});
    await refreshStatus();
    if (!S.status.linking) {
      $("linkwait-state").textContent = "Linked.";
      enterApp();
      return;
    }
  }
}
$("linkwait-cancel").addEventListener("click", async () => {
  await invoke("link_join_cancel").catch(() => {});
  await invoke("panic_wipe", { confirm: "DELETE" }).catch(() => {});
});

/* this device links a new one */
async function paintDevices() {
  let list = [];
  let lv = null;
  try {
    list = await invoke("devices");
    lv = await invoke("link_view");
  } catch {
    return;
  }
  $("device-list").replaceChildren(
    ...list.map((d) => {
      const row = el("div", "device-row");
      row.append(el("span", "grow small", d.name + (d.this ? "" : d.lastSeenDays ? " · seen " + d.lastSeenDays + " days ago" : " · active")));
      if (!d.this) {
        const b = el("button", "btn ghost small-btn", "Remove");
        b.type = "button";
        b.title = "Stop sending to it. To cut a lost device off completely, also move your account to a new key (Recovery words).";
        b.addEventListener("click", async () => {
          await invoke("remove_device", { id: d.id }).catch(() => {});
          paintDevices();
        });
        row.append(b);
      }
      return row;
    }),
  );
  $("link-box").hidden = !lv.code;
  if (lv.code) {
    $("link-code").value = lv.code;
    const reqs = lv.requests.map(([i, name, check]) => {
      const box = el("div", "stack-4");
      box.append(el("span", "small", "\u201c" + name + "\u201d wants to use your account. Does it show this code?"), el("span", "check-code mono", check));
      const yes = el("button", "btn primary small-btn", "Allow");
      yes.type = "button";
      yes.addEventListener("click", async () => {
        yes.disabled = true;
        yes.textContent = "Sending your account…";
        try {
          await invoke("link_approve", { index: i });
        } catch (e) {
          yes.textContent = String(e);
        }
        paintDevices();
      });
      const row = el("div", "inline-actions");
      row.append(yes, el("span", "muted small", "If the code is different, don't allow it: press Stop."));
      box.append(row);
      return box;
    });
    $("link-requests").replaceChildren(...(reqs.length ? reqs : [el("span", "muted small", "Waiting for the new device…")]));
  }
}
$("link-start").addEventListener("click", async () => {
  try {
    await invoke("link_start");
  } catch (e) {
    $("link-requests").replaceChildren(el("span", "error small", String(e)));
  }
  paintDevices();
  // Keep checking for the new device's request while the code is shown.
  clearInterval(S.linkTimer);
  S.linkTimer = setInterval(async () => {
    if ($("link-box").hidden) return clearInterval(S.linkTimer);
    await invoke("refresh_rooms").catch(() => {});
    paintDevices();
  }, 8000);
});
$("link-copy").addEventListener("click", async () => {
  const ok = await invoke("copy_secret", { text: $("link-code").value });
  $("link-copy").textContent = ok ? "Copied · clears in 1 minute" : "Couldn't copy";
});
$("link-cancel").addEventListener("click", async () => {
  await invoke("link_cancel").catch(() => {});
  paintDevices();
});
document.querySelectorAll("[data-settings]").forEach((b) => b.addEventListener("click", paintDevices));

/* getting started: four steps, ticked off as they happen */
function noteShared() {
  S.sharedLink = true;
  try {
    localStorage.setItem("gs-link", "1");
  } catch {}
  setTimeout(paintGettingStarted, 300);
}
try {
  S.sharedLink = localStorage.getItem("gs-link") === "1";
} catch {}
async function paintGettingStarted() {
  let hidden = false;
  try {
    hidden = localStorage.getItem("gs-hidden") === "1";
  } catch {}
  const st = S.status;
  if (!st || !st.unlocked) return;
  let rec = S.recovery;
  try {
    rec = await invoke("recovery_status");
  } catch {}
  const posts = (S.posts || []).some((p) => p.mine);
  const steps = [
    [!!rec && rec.set && !rec.pending, "Write down your recovery words", () => { setTab("privacy"); S.settingsGroup = "safety"; paintSettings(); paintRecovery(); }],
    [!!S.sharedLink, "Send your follow link to a friend", () => setTab("profile")],
    [st.following > 0, "Follow someone with their link", () => { const i = $("follow-input"); i.scrollIntoView({ block: "center" }); i.focus(); }],
    [posts, "Write your first post", () => $("compose-text").focus()],
  ];
  const all = steps.every((x) => x[0]);
  $("getting-started").hidden = hidden || all;
  $("gs-list").replaceChildren(
    ...steps.map(([done, text, go]) => {
      const li = el("li", done ? "done" : "");
      const tick = el("span", "tick", done ? "✓" : "");
      const t = el("button", "link-btn gs-text", text);
      t.type = "button";
      t.addEventListener("click", go);
      li.append(tick, t);
      return li;
    }),
  );
}
$("gs-hide").addEventListener("click", () => {
  try {
    localStorage.setItem("gs-hidden", "1");
  } catch {}
  $("getting-started").hidden = true;
});
listen("timeline", paintGettingStarted);
listen("status", paintGettingStarted);

/* Safety, most important first: recovery words, devices, passphrase; the
 * advanced tools folded under "More protection"; backup and wipe last. */
(function arrangeSafety() {
  const form = $("pass-form");
  const block = form.parentElement;
  const header = block.firstElementChild;
  header.querySelector(".setting-title").textContent = "Your passphrase";
  header.querySelector(".muted").textContent = "Unlocks Sentinel on this device. It can't be reset, so keep it written down.";
  const keyfile = $("keyfile-state").closest(".stack-8");
  const emergency = $("emergency-form");
  const disguise = $("disguise-code").closest(".row-setting");
  const more = el("details", "advanced-inline more-protection");
  const sum = el("summary", "setting-title", "More protection: key file, emergency passphrase, calculator disguise");
  more.append(sum, keyfile, emergency, disguise);
  disguise.classList.remove("row-setting");
  block.prepend($("recovery-block"), $("devices-block"));
  form.after(more);
})();

// Phones: hide the tab bar while the keyboard is up (typing in a box).
document.addEventListener("focusin", (e) => {
  if (e.target.matches("input:not([type=checkbox]):not([type=radio]), textarea")) document.body.classList.add("typing");
});
document.addEventListener("focusout", () => {
  setTimeout(() => {
    if (!document.activeElement || !document.activeElement.matches("input, textarea")) document.body.classList.remove("typing");
  }, 50);
});

/* ---------- deleting messages in bulk ---------- */

S.sel = null; // { kind: "dm" | "room", ids: Set }

function selectable(row, kind, id) {
  if (!S.sel || S.sel.kind !== kind || !id) return;
  row.classList.add("selectable");
  if (S.sel.ids.has(id)) row.classList.add("selected");
  row.addEventListener("click", () => {
    if (S.sel.ids.has(id)) S.sel.ids.delete(id);
    else S.sel.ids.add(id);
    row.classList.toggle("selected", S.sel.ids.has(id));
    paintSelectCount();
  });
}

function paintSelectCount() {
  if (!S.sel) return;
  const n = S.sel.ids.size;
  $(S.sel.kind + "-select-count").textContent = n ? n + (n === 1 ? " message selected" : " messages selected") : "Tap messages to select them";
}

function startSelect(kind) {
  S.sel = { kind, ids: new Set() };
  $(kind + "-select-bar").hidden = false;
  paintSelectCount();
  if (kind === "dm") loadThread();
  else loadRoomThread();
}

function endSelect() {
  if (!S.sel) return;
  const kind = S.sel.kind;
  S.sel = null;
  $(kind + "-select-bar").hidden = true;
  if (kind === "dm") loadThread();
  else loadRoomThread();
}

// Two clicks to delete (the first one asks).
function armed(btn, label, run) {
  let armedAt = 0;
  btn.addEventListener("click", async () => {
    if (Date.now() - armedAt > 4000) {
      armedAt = Date.now();
      btn.dataset.label = btn.dataset.label || btn.textContent;
      btn.textContent = label;
      setTimeout(() => {
        if (btn.dataset.label) btn.textContent = btn.dataset.label;
      }, 4000);
      return;
    }
    armedAt = 0;
    btn.textContent = btn.dataset.label;
    await run();
  });
}

$("dm-select-btn").addEventListener("click", () => (S.sel ? endSelect() : startSelect("dm")));
$("room-select-btn").addEventListener("click", () => (S.sel ? endSelect() : startSelect("room")));
$("dm-select-done").addEventListener("click", endSelect);
$("room-select-done").addEventListener("click", endSelect);

async function deleteDm(all) {
  if (!S.thread || !S.sel) return;
  const ids = all ? [] : [...S.sel.ids];
  if (!all && !ids.length) return;
  try {
    const n = await invoke("delete_dm_messages", { author: S.thread.author, ids, theirs: $("dm-del-theirs").checked });
    setError("dm-error", "");
    S.sel.ids.clear();
    $("dm-select-count").textContent = "Deleted " + n + ($("dm-del-theirs").checked ? ". Their app was asked to delete them too." : ".");
    loadThread();
    loadConversations();
  } catch (e) {
    setError("dm-error", String(e));
  }
}
armed($("dm-del-sel"), "Delete them? Click again", () => deleteDm(false));
armed($("dm-del-all"), "Delete the whole conversation? Click again", () => deleteDm(true));

async function deleteRoom(all) {
  if (!S.room || !S.sel) return;
  const ids = all ? [] : [...S.sel.ids];
  if (!all && !ids.length) return;
  try {
    const n = await invoke("delete_room_messages", { id: S.room.id, ids });
    S.sel.ids.clear();
    $("room-select-count").textContent = "Deleted " + n + ".";
    loadRoomThread();
  } catch (e) {
    setError("room-error", String(e));
  }
}
armed($("room-del-sel"), "Delete them? Click again", () => deleteRoom(false));
armed($("room-del-all"), "Delete all of this room's messages? Click again", () => deleteRoom(true));

armed($("delete-all-msgs"), "Delete every message? Click again", async () => {
  try {
    const n = await invoke("delete_all_messages");
    $("delete-all-msg").textContent = "Deleted " + n + " messages.";
  } catch (e) {
    $("delete-all-msg").textContent = String(e);
  }
});

/* ---------- forgot passphrase ---------- */

$("unlock-forgot").addEventListener("click", () => {
  $("forgot-box").hidden = !$("forgot-box").hidden;
});

{
  let armedAt = 0;
  $("forgot-start-over").addEventListener("click", async () => {
    const b = $("forgot-start-over");
    if (Date.now() - armedAt > 5000) {
      armedAt = Date.now();
      b.textContent = "Remove the locked copy? Click again";
      setTimeout(() => (b.textContent = "Remove it and get my account back"), 5000);
      return;
    }
    armedAt = 0;
    b.disabled = true;
    try {
      await invoke("start_over");
      $("forgot-box").hidden = true;
      b.textContent = "Remove it and get my account back";
      show("welcome");
    } catch (e) {
      setError("forgot-msg", String(e));
    } finally {
      b.disabled = false;
    }
  });
}
