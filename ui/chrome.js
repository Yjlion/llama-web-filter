/*
 * WebFilter management UI — theming + responsive shell. Build-free, no deps.
 *
 * Mirrors i18n.js: a single shared script loaded by every page (before Alpine,
 * NOT deferred). Two jobs:
 *
 *   1. Resolve + apply the theme (data-theme / data-accent) before paint, build
 *      the sidebar theme picker, and turn the duplicated sidebar into an
 *      off-canvas drawer on small screens.
 *
 * Color utilities (canvas, card, gray.*, blue.*, sidebar.*) are baked into
 * management/ui/tailwind.css at build time — no CDN or runtime config needed.
 * To regenerate tailwind.css after adding new Tailwind classes, run:
 *   scripts/build_tailwind.ps1  (Windows)
 *   scripts/build_tailwind.sh   (Linux / macOS)
 *
 * Preferences are per-browser (localStorage): wf_theme = auto|light|dark,
 * wf_accent = blue|emerald|violet|rose.
 */
(function () {
  "use strict";

  // ── 1. Theme state ──
  var MODE_KEY = "wf_theme", ACCENT_KEY = "wf_accent";
  var MODES = ["auto", "light", "dark"];
  var ACCENTS = ["blue", "emerald", "violet", "rose"];
  // Solid swatch colours for the picker dots (accent-600, light values).
  var SWATCH = { blue: "#2563eb", emerald: "#059669", violet: "#7c3aed", rose: "#e11d48" };

  function read(key, allowed, dflt) {
    try { var x = localStorage.getItem(key); return allowed.indexOf(x) >= 0 ? x : dflt; }
    catch (e) { return dflt; }
  }
  function getMode() { return read(MODE_KEY, MODES, "auto"); }
  function getAccent() { return read(ACCENT_KEY, ACCENTS, "blue"); }

  function systemDark() {
    return !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  }
  function resolve(mode) {
    return mode === "dark" || (mode === "auto" && systemDark()) ? "dark" : "light";
  }

  function apply() {
    var root = document.documentElement;
    root.setAttribute("data-theme", resolve(getMode()));
    root.setAttribute("data-accent", getAccent());
  }
  apply(); // before paint — no flash

  // Follow the OS when the user left it on "auto".
  if (window.matchMedia) {
    try {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
        if (getMode() === "auto") { apply(); syncPicker(); }
      });
    } catch (e) { /* Safari < 14 */ }
  }

  function setMode(m) {
    if (MODES.indexOf(m) < 0) m = "auto";
    try { localStorage.setItem(MODE_KEY, m); } catch (e) {}
    apply(); syncPicker();
  }
  function setAccent(a) {
    if (ACCENTS.indexOf(a) < 0) a = "blue";
    try { localStorage.setItem(ACCENT_KEY, a); } catch (e) {}
    apply(); syncPicker();
  }

  // ── 2. Theme picker (injected into the sidebar bottom, like i18n's selects) ──
  var MODE_ICON = {
    auto: '<span class="text-[10px] font-semibold">A</span>',
    light: '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>',
    dark: '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>',
  };

  function buildPicker() {
    var aside = document.querySelector("aside");
    if (!aside || aside.querySelector(".wf-theme-picker")) return;

    var wrap = document.createElement("div");
    wrap.className = "wf-theme-picker px-3 pb-2";

    var label = document.createElement("span");
    label.className = "block text-xs text-sidebar-muted mb-1";
    label.setAttribute("data-i18n", "theme.mode");
    label.textContent = "Theme";
    wrap.appendChild(label);

    var modeRow = document.createElement("div");
    modeRow.className = "flex gap-1 mb-2";
    MODES.forEach(function (m) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "wf-mode-btn";
      b.dataset.wfMode = m;
      b.innerHTML = MODE_ICON[m];
      b.setAttribute("data-i18n-title", "theme." + m);
      b.title = m;
      b.addEventListener("click", function () { setMode(m); });
      modeRow.appendChild(b);
    });
    wrap.appendChild(modeRow);

    var swRow = document.createElement("div");
    swRow.className = "flex gap-2";
    swRow.setAttribute("data-i18n-title", "theme.accent");
    ACCENTS.forEach(function (a) {
      var s = document.createElement("button");
      s.type = "button";
      s.className = "wf-swatch";
      s.dataset.wfAccent = a;
      s.style.background = SWATCH[a];
      s.title = a;
      s.addEventListener("click", function () { setAccent(a); });
      swRow.appendChild(s);
    });
    wrap.appendChild(swRow);

    // Insert above the language <label> if present, else append.
    var langSel = aside.querySelector(".wf-lang-select");
    var anchor = langSel ? langSel.closest("label") : null;
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(wrap, anchor);
    else aside.appendChild(wrap);

    if (window.wfI18n && window.wfI18n.applyI18n) window.wfI18n.applyI18n(wrap);
    syncPicker();
  }

  function syncPicker() {
    var mode = getMode(), accent = getAccent();
    document.querySelectorAll(".wf-mode-btn").forEach(function (b) {
      b.classList.toggle("wf-active", b.dataset.wfMode === mode);
    });
    document.querySelectorAll(".wf-swatch").forEach(function (s) {
      s.classList.toggle("wf-active", s.dataset.wfAccent === accent);
    });
  }

  // ── 3. Mobile drawer: turn the duplicated sidebar into an off-canvas panel ──
  function buildMobileNav() {
    var aside = document.querySelector("aside");
    var main = document.querySelector("main");
    if (!aside || !main || main.querySelector(".wf-topbar")) return;
    aside.classList.add("wf-sidebar");

    var bar = document.createElement("div");
    bar.className = "wf-topbar";
    bar.innerHTML =
      '<button type="button" class="wf-burger" aria-label="Menu">' +
        '<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">' +
          '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>' +
        '</svg></button>' +
      '<span class="font-semibold text-sm text-gray-900">WebFilter Proxy</span>';
    main.insertBefore(bar, main.firstChild);

    var backdrop = document.createElement("div");
    backdrop.className = "wf-backdrop";
    document.body.appendChild(backdrop);

    function open() { aside.classList.add("wf-open"); backdrop.classList.add("wf-open"); }
    function close() { aside.classList.remove("wf-open"); backdrop.classList.remove("wf-open"); }

    bar.querySelector(".wf-burger").addEventListener("click", open);
    backdrop.addEventListener("click", close);
    aside.querySelectorAll("nav a").forEach(function (a) { a.addEventListener("click", close); });
    window.addEventListener("resize", function () { if (window.innerWidth >= 1024) close(); });
  }

  window.wfTheme = { setMode: setMode, setAccent: setAccent, getMode: getMode, getAccent: getAccent };

  document.addEventListener("DOMContentLoaded", function () {
    buildPicker();
    buildMobileNav();
  });
})();
