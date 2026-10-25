/* Mintkit: QR, barcode, password, random and UUID/hash generators. Everything runs locally; nothing is uploaded. */
(() => {
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const BASE = (document.body && document.body.dataset.base) || ""; // sub-folder prefix, set by build.js
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = String(text); return e; };
const store = { get(k) { try { return JSON.parse(localStorage.getItem("mintkit:" + k)); } catch { return null; } }, set(k, v) { try { localStorage.setItem("mintkit:" + k, JSON.stringify(v)); } catch { /* storage off */ } } };
const PAGES = window.MK_PAGES || [], WORDS = window.MK_WORDS || [];
const clampN = (v, lo, hi, d) => { v = Math.round(Number(v)); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
const fmt = n => n.toLocaleString("en-US");

/* ---------- secure randomness (unbiased rejection sampling) ---------- */
let pool = new Uint32Array(0), pi = 0;
const u32 = () => { if (pi >= pool.length) { pool = crypto.getRandomValues(new Uint32Array(256)); pi = 0; } return pool[pi++]; };
function randInt(n) { // uniform integer in [0, n), n <= 2^53
  if (!(n >= 1) || n > 2 ** 53) throw new RangeError("bad range");
  if (n <= 2 ** 32) { const lim = Math.floor(2 ** 32 / n) * n; let x; do x = u32(); while (x >= lim); return x % n; }
  const lim = Math.floor(2 ** 53 / n) * n; let x; do x = (u32() & 0x1fffff) * 2 ** 32 + u32(); while (x >= lim); return x % n;
}
const shuffle = a => { for (let i = a.length - 1; i > 0; i--) { const j = randInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };

/* ---------- UI helpers ---------- */
const toast = msg => { const t = $("#toast"); if (!t) return; t.textContent = msg; t.classList.add("on"); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("on"), 1600); };
async function copy(text, what = "Copied") { try { await navigator.clipboard.writeText(text); } catch { const ta = el("textarea"); ta.value = text; document.body.append(ta); ta.select(); try { document.execCommand("copy"); } catch { /* ignore */ } ta.remove(); } toast(what + " ✓"); }
function download(blob, name) { const u = URL.createObjectURL(blob); const a = el("a"); a.href = u; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 4000); }
function I(kind, attrs = {}) {
  const i = el(kind === "select" || kind === "textarea" ? kind : "input"); if (i.tagName === "INPUT") i.type = kind;
  for (const [k, v] of Object.entries(attrs)) { if (k === "options") v.forEach(o => { const op = el("option", null, Array.isArray(o) ? o[1] : o); op.value = Array.isArray(o) ? o[0] : o; i.append(op); }); else if (k === "value") i.value = v; else i.setAttribute(k, v); }
  if (i.tagName !== "SELECT" && !i.hasAttribute("maxlength") && !["color", "file", "checkbox", "range", "number"].includes(kind)) i.setAttribute("maxlength", kind === "textarea" ? "5000" : "300");
  return i;
}
function F(parent, label, input, cls = "") { const w = el("label", "field " + cls); w.append(el("span", "lab", label)); if (input.tagName === "TEXTAREA") w.append(input); else { const b = el("div", "inbox"); b.append(input); w.append(b); } parent.append(w); return input; }
function CK(parent, label, on) { const w = el("label", "field check"); const i = I("checkbox"); i.checked = !!on; w.append(i, el("span", null, label)); parent.append(w); return i; }
function seg(parent, items, cur, onPick) { const bar = el("div", "seg"); bar.setAttribute("role", "tablist"); items.forEach(([v, l]) => { const b = el("button", "segb" + (v === cur ? " on" : ""), l); b.type = "button"; b.dataset.v = v; b.setAttribute("role", "tab"); b.addEventListener("click", () => { bar.querySelectorAll(".segb").forEach(x => x.classList.toggle("on", x === b)); onPick(v); }); bar.append(b); }); parent.append(bar); return bar; }
function btn(parent, label, cls, fn) { const b = el("button", cls || "chip", label); b.type = "button"; b.addEventListener("click", fn); parent.append(b); return b; }
const sub = parent => { const s = el("div", "subform"); parent.append(s); return s; };
function colorPair(parent, fg, bg) { return { a: F(parent, "Foreground", I("color", { value: fg })), b: F(parent, "Background", I("color", { value: bg })) }; }
const lum = hx => { const c = [1, 3, 5].map(i => parseInt(hx.substr(i, 2), 16) / 255).map(v => v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
const contrast = (x, y) => { const [h, l] = [lum(x), lum(y)].sort((p, q) => q - p); return (h + 0.05) / (l + 0.05); };
function contrastNote(fg, bg, transparent) {
  if (transparent) return "Transparent background: place it on a light surface so it scans.";
  if (lum(fg) > lum(bg)) return "⚠ Light code on a dark background. Many scanners can't read inverted codes.";
  if (contrast(fg, bg) < 4) return "⚠ Low contrast. Use a darker foreground or lighter background so it scans reliably.";
  return "";
}

/* ---------- image file check (magic bytes, size cap, re-encode) ---------- */
const MIME = { png: "image/png", jpg: "image/jpeg", gif: "image/gif", webp: "image/webp" };
function sniff(h) {
  if (h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47) return "png";
  if (h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff) return "jpg";
  if (h[0] === 0x47 && h[1] === 0x49 && h[2] === 0x46 && h[3] === 0x38) return "gif";
  if (h[0] === 0x52 && h[1] === 0x49 && h[2] === 0x46 && h[3] === 0x46 && h[8] === 0x57 && h[9] === 0x45 && h[10] === 0x42 && h[11] === 0x50) return "webp";
  return null;
}
async function loadLogo(file) {
  if (!file) throw new Error("No file selected.");
  if (file.size > 5 * 1024 * 1024) throw new Error("That image is over 5 MB. Please use a smaller logo.");
  const kind = sniff(new Uint8Array(await file.slice(0, 12).arrayBuffer()));
  if (!kind) throw new Error("Logos must be PNG, JPEG, GIF or WebP images.");
  const url = URL.createObjectURL(new Blob([file], { type: MIME[kind] }));
  try {
    const img = new Image(); img.src = url;
    try { await img.decode(); } catch { throw new Error("Couldn't read that image."); }
    if (img.naturalWidth * img.naturalHeight > 40e6) throw new Error("That image is too large (over 40 megapixels).");
    const s = Math.min(1, 512 / Math.max(img.naturalWidth, img.naturalHeight)), c = el("canvas"); c.width = Math.max(1, Math.round(img.naturalWidth * s)); c.height = Math.max(1, Math.round(img.naturalHeight * s));
    c.getContext("2d").drawImage(img, 0, 0, c.width, c.height); // re-encode: strips metadata and caps size
    const dataUrl = c.toDataURL("image/png"), clean = new Image(); clean.src = dataUrl; await clean.decode();
    return { img: clean, dataUrl, w: c.width, h: c.height };
  } finally { URL.revokeObjectURL(url); }
}
const safeName = s => String(s).replace(/[^\w.\- ]+/g, "_").slice(0, 80);

/* ================= QR CODES ================= */
if (window.qrcode) qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
const QR_TYPES = [["url", "URL"], ["text", "Text"], ["wifi", "Wi-Fi"], ["vcard", "vCard"], ["email", "Email"], ["sms", "SMS"], ["tel", "Phone"]];
const QR_FIELDS = {
  url: [["url", "Website or link", "url", 2000, "wide", "https://example.com"]],
  text: [["text", "Text", "textarea", 2000, "wide", "Any text"]],
  wifi: [["ssid", "Network name (SSID)", "text", 32, "", "MyHomeWiFi"], ["pass", "Password", "text", 63, "", ""], ["enc", "Security", "select", 0, "", "", [["WPA", "WPA / WPA2 / WPA3"], ["WEP", "WEP"], ["nopass", "None (open)"]]], ["hidden", "Hidden network", "check"]],
  vcard: [["first", "First name", "text", 60], ["last", "Last name", "text", 60], ["phone", "Phone", "tel", 30], ["email", "Email", "email", 120], ["org", "Company", "text", 80], ["title", "Job title", "text", 80], ["web", "Website", "url", 200, "wide"], ["street", "Street", "text", 120, "wide"], ["city", "City", "text", 60], ["region", "State / region", "text", 60], ["zip", "Postal code", "text", 20], ["country", "Country", "text", 60]],
  email: [["to", "Email address", "email", 200, "wide"], ["subject", "Subject", "text", 200, "wide"], ["body", "Message", "textarea", 1000, "wide"]],
  sms: [["phone", "Phone number", "tel", 30, "wide"], ["msg", "Message", "textarea", 600, "wide"]],
  tel: [["phone", "Phone number", "tel", 30, "wide"]]
};
const QR_DEMO = { url: "https://example.com", text: "Hello from Mintkit!", ssid: "MyHomeWiFi", pass: "correct-horse-battery", enc: "WPA", hidden: false, first: "Jane", last: "Doe", phone: "+1 555 010 1234", email: "jane@example.com", org: "Acme Inc.", title: "Designer", web: "https://example.com", street: "1 Main St", city: "Springfield", region: "IL", zip: "62701", country: "USA", to: "hello@example.com", subject: "Hello", body: "", msg: "Hi!" };
const escWifi = s => s.replace(/([\\;,:"])/g, "\\$1");
const escV = s => s.replace(/\\/g, "\\\\").replace(/\r?\n/g, "\\n").replace(/([,;])/g, "\\$1");
function qrPayload(t, v) {
  const s = k => String(v[k] || "").trim();
  switch (t) {
    case "url": { let u = s("url"); if (u && !/^[a-z][a-z0-9+.-]*:/i.test(u)) u = "https://" + u; return u; }
    case "text": return String(v.text || "");
    case "wifi": return s("ssid") ? `WIFI:T:${v.enc};S:${escWifi(s("ssid"))};${v.enc !== "nopass" ? `P:${escWifi(String(v.pass || ""))};` : ""}${v.hidden ? "H:true;" : ""};` : "";
    case "vcard": {
      if (!s("first") && !s("last") && !s("org")) return "";
      const L = ["BEGIN:VCARD", "VERSION:3.0", `N:${escV(s("last"))};${escV(s("first"))};;;`, `FN:${escV([s("first"), s("last")].filter(Boolean).join(" ") || s("org"))}`];
      if (s("org")) L.push("ORG:" + escV(s("org")));
      if (s("title")) L.push("TITLE:" + escV(s("title")));
      if (s("phone")) L.push("TEL;TYPE=CELL:" + escV(s("phone")));
      if (s("email")) L.push("EMAIL:" + escV(s("email")));
      if (s("web")) L.push("URL:" + escV(s("web")));
      const A = ["street", "city", "region", "zip", "country"]; if (A.some(k => s(k))) L.push(`ADR;TYPE=WORK:;;${A.map(k => escV(s(k))).join(";")}`);
      L.push("END:VCARD"); return L.join("\r\n");
    }
    case "email": { if (!s("to")) return ""; const q = [["subject", s("subject")], ["body", String(v.body || "")]].filter(x => x[1]).map(([k, x]) => k + "=" + encodeURIComponent(x)).join("&"); return "mailto:" + s("to") + (q ? "?" + q : ""); }
    case "sms": return s("phone") ? `SMSTO:${s("phone").replace(/[^\d+]/g, "")}:${String(v.msg || "")}` : "";
    case "tel": return s("phone") ? "tel:" + s("phone").replace(/[^\d+*#]/g, "") : "";
  }
  return "";
}
function qrTool(form, out, p) {
  let type = p.t || "url", logo = null, last = null; const v = Object.assign({}, QR_DEMO);
  seg(form, QR_TYPES, type, t => { type = t; fields(); draw(); }).classList.add("wide");
  const fbox = sub(form);
  function fields() {
    fbox.textContent = "";
    for (const [k, label, kind, max, cls, ph, opts] of QR_FIELDS[type]) {
      if (kind === "check") { const c = CK(fbox, label, v[k]); c.dataset.k = k; c.addEventListener("change", () => { v[k] = c.checked; draw(); }); continue; }
      const i = kind === "select" ? I("select", { options: opts }) : I(kind === "textarea" ? "textarea" : kind, { maxlength: String(max), placeholder: ph || "", rows: "3", autocomplete: "off", spellcheck: "false" });
      i.value = v[k] || (kind === "select" ? opts[0][0] : ""); i.dataset.k = k;
      i.addEventListener("input", () => { v[k] = i.value; draw(); }); F(fbox, label, i, cls || "");
    }
  }
  const opt = sub(form); opt.classList.add("opts");
  const { a: fgI, b: bgI } = colorPair(opt, "#111827", "#ffffff");
  const ecI = F(opt, "Error correction", I("select", { options: [["L", "Low (7%)"], ["M", "Medium (15%)"], ["Q", "Quartile (25%)"], ["H", "High (30%)"]] })); ecI.value = "M";
  const sizeI = F(opt, "Size (px)", I("number", { min: "128", max: "2048", step: "16", value: "512" }));
  const marginI = F(opt, "Quiet zone (modules)", I("number", { min: "0", max: "10", value: "4" }));
  const transI = CK(opt, "Transparent background", false);
  const lbox = el("div", "field wide logo-row"); opt.append(lbox);
  lbox.append(el("span", "lab", "Logo in the center (optional · PNG, JPEG, GIF or WebP up to 5 MB)"));
  const lrow = el("div", "row"); lbox.append(lrow);
  const fileI = I("file", { accept: "image/png,image/jpeg,image/gif,image/webp", "aria-label": "Logo image" }); fileI.className = "file";
  const lname = el("span", "fname", "No logo");
  const lrm = btn(lrow, "Remove", "chip", () => { logo = null; fileI.value = ""; lname.textContent = "No logo"; lrm.hidden = true; draw(); });
  lrow.prepend(fileI, lname); lrm.hidden = true;
  const lsize = F(opt, "Logo size (% of code)", I("range", { min: "10", max: "28", value: "20" }));
  fileI.addEventListener("change", async () => { const f = fileI.files[0]; try { logo = await loadLogo(f); lname.textContent = safeName(f.name); lrm.hidden = false; draw(); } catch (e) { logo = null; fileI.value = ""; lname.textContent = "No logo"; lrm.hidden = true; toast(e.message); draw(); } });
  if (p.logo) lbox.classList.add("hl");
  [fgI, bgI, ecI, sizeI, marginI, transI, lsize].forEach(i => i.addEventListener("input", draw));

  const stage = el("div", "stage qrstage"), cv = el("canvas", "qr"); cv.setAttribute("role", "img"); stage.append(cv); out.append(stage);
  const meta = el("div", "meta"), warn = el("div", "warn"), errB = el("div", "err"); out.append(errB, meta, warn);
  const tools = el("div", "rtools"); out.append(tools);
  btn(tools, "⬇ PNG", "btn sm", () => last && cv.toBlob(b => download(b, "qr-code.png"), "image/png"));
  btn(tools, "⬇ SVG", "chip", () => last && download(new Blob([qrSvg()], { type: "image/svg+xml" }), "qr-code.svg"));
  btn(tools, "Copy content", "chip", () => last && copy(last.text, "Content copied"));
  const det = el("details", "payload"); det.append(el("summary", null, "What's inside this code")); const pre = el("pre", "mono"); det.append(pre); out.append(det);

  function draw() {
    const text = qrPayload(type, v); errB.textContent = ""; warn.textContent = "";
    const ec = logo ? "H" : ecI.value; ecI.disabled = !!logo; if (logo) ecI.value = "H";
    if (!text) { last = null; cv.width = cv.height = 0; stage.classList.add("empty"); meta.textContent = "Fill in the fields to create your code."; pre.textContent = ""; return; }
    stage.classList.remove("empty");
    let q; try { q = qrcode(0, ec); q.addData(text, "Byte"); q.make(); } catch { last = null; cv.width = cv.height = 0; errB.textContent = "That's too much data for one QR code at this error-correction level. Shorten it or lower error correction."; meta.textContent = ""; return; }
    const n = q.getModuleCount(), m = clampN(marginI.value, 0, 10, 4), tot = n + 2 * m, size = clampN(sizeI.value, 128, 2048, 512), cell = Math.max(1, Math.floor(size / tot)), px = cell * tot;
    const fg = fgI.value, bg = bgI.value, tr = transI.checked, ctx = cv.getContext("2d");
    cv.width = cv.height = px; ctx.clearRect(0, 0, px, px); if (!tr) { ctx.fillStyle = bg; ctx.fillRect(0, 0, px, px); }
    ctx.fillStyle = fg; for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) ctx.fillRect((c + m) * cell, (r + m) * cell, cell, cell);
    let lg = null;
    if (logo) {
      const box = Math.round(n * cell * clampN(lsize.value, 10, 28, 20) / 100), sc = Math.min(box / logo.w, box / logo.h), w = logo.w * sc, h = logo.h * sc, x = (px - w) / 2, y = (px - h) / 2, pad = cell;
      ctx.fillStyle = tr ? "#ffffff" : bg; ctx.beginPath(); ctx.roundRect(x - pad, y - pad, w + 2 * pad, h + 2 * pad, pad * 1.5); ctx.fill(); ctx.drawImage(logo.img, x, y, w, h);
      lg = { x: x / cell, y: y / cell, w: w / cell, h: h / cell };
    }
    last = { q, n, m, tot, px, fg, bg, tr, text, lg };
    cv.setAttribute("aria-label", "QR code"); cv.dataset.payload = text;
    meta.textContent = `Version ${(n - 17) / 4} · ${n}×${n} modules · ${px}×${px} px · error correction ${ec}${logo ? " (raised to High for the logo)" : ""}`;
    warn.textContent = contrastNote(fg, bg, tr); pre.textContent = text;
  }
  function qrSvg() {
    const { q, n, m, tot, px, fg, bg, tr, lg } = last; let d = "";
    for (let r = 0; r < n; r++) { let c = 0; while (c < n) { if (q.isDark(r, c)) { const s = c; while (c < n && q.isDark(r, c)) c++; d += `M${s + m} ${r + m}h${c - s}v1h-${c - s}z`; } else c++; } }
    const f3 = x => x.toFixed(3);
    const L = lg ? `<rect x="${f3(lg.x - 1)}" y="${f3(lg.y - 1)}" width="${f3(lg.w + 2)}" height="${f3(lg.h + 2)}" rx="1.5" fill="${tr ? "#ffffff" : bg}"/><image href="${logo.dataUrl}" x="${f3(lg.x)}" y="${f3(lg.y)}" width="${f3(lg.w)}" height="${f3(lg.h)}" preserveAspectRatio="xMidYMid meet"/>` : "";
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${tot} ${tot}" width="${px}" height="${px}" shape-rendering="crispEdges">${tr ? "" : `<rect width="${tot}" height="${tot}" fill="${bg}"/>`}<path fill="${fg}" d="${d}"/>${L}</svg>`;
  }
  fields(); draw();
}

/* ================= BARCODES (own encoders) ================= */
const C128 = "212222 222122 222221 121223 121322 131222 122213 122312 132212 221213 221312 231212 112232 122132 122231 113222 123122 123221 223211 221132 221231 213212 223112 312131 311222 321122 321221 312212 322112 322211 212123 212321 232121 111323 131123 131321 112313 132113 132311 211313 231113 231311 112133 112331 132131 113123 113321 133121 313121 211331 231131 213113 213311 213131 311123 311321 331121 312113 312311 332111 314111 221411 431111 111224 111422 121124 121421 141122 141221 112214 112412 122114 122411 142112 142211 241211 221114 413111 241112 134111 111242 121142 121241 114212 124112 124211 411212 421112 421211 212141 214121 412121 111143 111341 131141 114113 114311 411113 411311 113141 114131 311141 411131 211412 211214 211232 2331112".split(" ");
const widthsToBits = w => { let s = ""; for (let i = 0; i < w.length; i++) s += (i % 2 ? "0" : "1").repeat(+w[i]); return s; };
function code128(s) {
  if (!s.length) throw new Error("Enter some text to encode.");
  if (s.length > 80) throw new Error("Code 128 is limited to 80 characters here.");
  if (/[^\x20-\x7e]/.test(s)) throw new Error("Code 128 here supports printable ASCII only (letters, digits, spaces and symbols on a US keyboard).");
  const run = j => { let k = j; while (k < s.length && s.charCodeAt(k) >= 48 && s.charCodeAt(k) <= 57) k++; return k - j; };
  const codes = []; let i = 0, set; const r0 = run(0);
  if (r0 >= 4 || (r0 === s.length && r0 >= 2 && r0 % 2 === 0)) { set = "C"; codes.push(105); } else { set = "B"; codes.push(104); }
  while (i < s.length) {
    if (set === "C") { if (run(i) >= 2) { codes.push(+s.substr(i, 2)); i += 2; } else { codes.push(100); set = "B"; } }
    else { const r = run(i); if (r >= 4 && (i + r === s.length || r >= 6)) { if (r % 2) { codes.push(s.charCodeAt(i) - 32); i++; } codes.push(99); set = "C"; } else { codes.push(s.charCodeAt(i) - 32); i++; } }
  }
  let sum = codes[0]; for (let k = 1; k < codes.length; k++) sum += codes[k] * k;
  codes.push(sum % 103);
  return { bits: codes.map(c => widthsToBits(C128[c])).join("") + widthsToBits(C128[106]), text: s };
}
const EAN_L = "0001101 0011001 0010011 0111101 0100011 0110001 0101111 0111011 0110111 0001011".split(" ");
const EAN_G = "0100111 0110011 0011011 0100001 0011101 0111001 0000101 0010001 0001001 0010111".split(" ");
const EAN_R = "1110010 1100110 1101100 1000010 1011100 1001110 1010000 1000100 1001000 1110100".split(" ");
const EAN_P = "LLLLLL LLGLGG LLGGLG LLGGGL LGLLGG LGGLLG LGGGLL LGLGLG LGLGGL LGGLGL".split(" ");
function gs1(d) { let s = 0; for (let i = d.length - 1, w = 3; i >= 0; i--, w = 4 - w) s += +d[i] * w; return (10 - s % 10) % 10; }
function digitsWithCheck(raw, len, name) {
  const d = raw.replace(/[\s-]/g, "");
  if (!/^\d*$/.test(d)) throw new Error(`${name} uses digits only.`);
  if (d.length === len - 1) return { d: d + gs1(d), added: true };
  if (d.length === len) { const c = gs1(d.slice(0, -1)); if (+d[len - 1] !== c) throw new Error(`Check digit should be ${c}, not ${d[len - 1]}. Enter ${len - 1} digits to have it calculated for you.`); return { d, added: false }; }
  throw new Error(`${name} needs ${len - 1} digits (check digit added automatically) or ${len} digits including the check digit. You entered ${d.length}.`);
}
function ean13(raw, name = "EAN-13") {
  const { d, added } = digitsWithCheck(raw, 13, name), par = EAN_P[+d[0]];
  let b = "101"; for (let i = 1; i <= 6; i++) b += (par[i - 1] === "L" ? EAN_L : EAN_G)[+d[i]];
  b += "01010"; for (let i = 7; i <= 12; i++) b += EAN_R[+d[i]]; b += "101";
  return { bits: b, text: d, added, ean: true };
}
function upca(raw) { const { d, added } = digitsWithCheck(raw, 12, "UPC-A"); const r = ean13("0" + d, "UPC-A"); return { bits: r.bits, text: d, added, upc: true }; }
const C39 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%";
const C39P = "000110100 100100001 001100001 101100000 000110001 100110000 001110000 000100101 100100100 001100100 100001001 001001001 101001000 000011001 100011000 001011000 000001101 100001100 001001100 000011100 100000011 001000011 101000010 000010011 100010010 001010010 000000111 100000110 001000110 000010110 110000001 011000001 111000000 010010001 110010000 011010000 010000101 110000100 011000100 010101000 010100010 010001010 000101010".split(" ");
const C39STAR = "010010100";
function code39(raw, check) {
  const s = raw.toUpperCase();
  if (!s.length) throw new Error("Enter some text to encode.");
  if (s.length > 40) throw new Error("Code 39 is limited to 40 characters here.");
  const bad = [...s].find(c => C39.indexOf(c) < 0);
  if (bad != null) throw new Error(`Code 39 can't encode “${bad}”. Use A–Z, 0–9, space and - . $ / + %`);
  let body = s; if (check) body += C39[[...s].reduce((a, c) => a + C39.indexOf(c), 0) % 43];
  const ch = c => { const p = c === "*" ? C39STAR : C39P[C39.indexOf(c)]; let b = ""; for (let i = 0; i < 9; i++) b += (i % 2 ? "0" : "1").repeat(p[i] === "1" ? 3 : 1); return b; };
  return { bits: ["*", ...body, "*"].map(ch).join("0"), text: "*" + body + "*", value: body };
}
const ITF = "00110 10001 01001 11000 00101 10100 01100 00011 10010 01010".split(" ");
function itf14(raw) {
  const { d, added } = digitsWithCheck(raw, 14, "ITF-14");
  let b = "1010";
  for (let i = 0; i < 14; i += 2) { const p = ITF[+d[i]], q = ITF[+d[i + 1]]; for (let k = 0; k < 5; k++) b += "1".repeat(p[k] === "1" ? 3 : 1) + "0".repeat(q[k] === "1" ? 3 : 1); }
  return { bits: b + "11101", text: d.replace(/^(\d)(\d\d)(\d{5})(\d{5})(\d)$/, "$1 $2 $3 $4 $5"), added, itf: true };
}
const BC_FORMATS = [["code128", "Code 128"], ["ean13", "EAN-13"], ["upca", "UPC-A"], ["code39", "Code 39"], ["itf14", "ITF-14"]];
const BC_DEMO = { code128: "MINTKIT-2026", ean13: "590123412345", upca: "03600029145", code39: "MINTKIT 39", itf14: "1540014128876" };
const BC_HINT = { code128: "Any printable ASCII text up to 80 characters. Long digit runs are packed automatically.", ean13: "12 digits: the 13th (check digit) is calculated for you. Or type all 13 to verify.", upca: "11 digits: the 12th (check digit) is calculated for you. Or type all 12 to verify.", code39: "A–Z, 0–9, space and - . $ / + %. Lowercase is converted to uppercase.", itf14: "13 digits: the 14th (check digit) is calculated for you. Used on shipping cartons." };
function bcGeometry(r, f, o) {
  const bits = r.bits, q = f === "ean13" || f === "upca" ? Math.max(o.quiet, 9) : o.quiet, bear = r.itf ? 4 : 0;
  const total = bits.length + 2 * q + 2 * bear, bars = [];
  const guard = new Set(); if (r.ean || r.upc) { [[0, 3], [45, 50], [92, 95]].forEach(([a, b]) => { for (let i = a; i < b; i++) guard.add(i); }); if (r.upc) for (let i = 3; i < 10; i++) { guard.add(i); guard.add(i + 82); } }
  for (let i = 0; i < bits.length;) { if (bits[i] === "1") { const s = i; const g = guard.has(i); while (i < bits.length && bits[i] === "1") i++; bars.push({ x: s + q + bear, w: i - s, g }); } else i++; }
  const texts = [], x0 = q + bear;
  if (o.text) {
    if (r.ean) { texts.push({ x: x0 - 4, s: r.text[0], small: false }); for (let k = 0; k < 6; k++) { texts.push({ x: x0 + 3 + k * 7 + 3.5, s: r.text[1 + k] }); texts.push({ x: x0 + 50 + k * 7 + 3.5, s: r.text[7 + k] }); } }
    else if (r.upc) { texts.push({ x: x0 - 4, s: r.text[0], small: true }); for (let k = 0; k < 5; k++) { texts.push({ x: x0 + 10 + k * 7 + 3.5, s: r.text[1 + k] }); texts.push({ x: x0 + 50 + k * 7 + 3.5, s: r.text[6 + k] }); } texts.push({ x: x0 + 99, s: r.text[11], small: true }); }
    else texts.push({ x: total / 2, s: r.text });
  }
  return { total, bars, texts, bear, split: !!(r.ean || r.upc) };
}
function bcTool(form, out, p) {
  let f = p.f || "code128", last = null; const vals = Object.assign({}, BC_DEMO);
  seg(form, BC_FORMATS, f, x => { f = x; dataI.value = vals[f]; hint.textContent = BC_HINT[f]; chk.closest("label").hidden = f !== "code39"; draw(); }).classList.add("wide");
  const dataI = F(form, "Data to encode", I("text", { maxlength: "80", autocomplete: "off", spellcheck: "false" }), "wide"); dataI.value = vals[f];
  const hint = el("p", "hint wide", BC_HINT[f]); form.append(hint);
  const opt = sub(form); opt.classList.add("opts");
  const { a: fgI, b: bgI } = colorPair(opt, "#000000", "#ffffff");
  const modI = F(opt, "Bar width (px per module)", I("number", { min: "1", max: "8", value: "3" }));
  const hI = F(opt, "Bar height (px)", I("number", { min: "30", max: "400", value: "120" }));
  const qI = F(opt, "Quiet zone (modules)", I("number", { min: "4", max: "30", value: "10" }));
  const txtI = CK(opt, "Show human-readable text", true), chk = CK(opt, "Add mod-43 check character", false); chk.closest("label").hidden = f !== "code39";
  dataI.addEventListener("input", () => { vals[f] = dataI.value; draw(); });
  [fgI, bgI, modI, hI, qI, txtI, chk].forEach(i => i.addEventListener("input", draw));
  const stage = el("div", "stage bcstage"), cv = el("canvas", "bc"); cv.setAttribute("role", "img"); stage.append(cv); out.append(stage);
  const errB = el("div", "err"), meta = el("div", "meta"), warn = el("div", "warn"); out.append(errB, meta, warn);
  const tools = el("div", "rtools"); out.append(tools);
  btn(tools, "⬇ PNG", "btn sm", () => last && cv.toBlob(b => download(b, `barcode-${f}.png`), "image/png"));
  btn(tools, "⬇ SVG", "chip", () => last && download(new Blob([svg()], { type: "image/svg+xml" }), `barcode-${f}.svg`));
  btn(tools, "Copy value", "chip", () => last && copy(last.r.value != null ? last.r.value : last.r.text.replace(/\s/g, ""), "Value copied"));
  function draw() {
    errB.textContent = ""; warn.textContent = ""; let r;
    try { r = f === "code128" ? code128(dataI.value) : f === "ean13" ? ean13(dataI.value) : f === "upca" ? upca(dataI.value) : f === "code39" ? code39(dataI.value.trim(), chk.checked) : itf14(dataI.value); }
    catch (e) { last = null; cv.width = cv.height = 0; stage.classList.add("empty"); errB.textContent = e.message; meta.textContent = ""; return; }
    stage.classList.remove("empty");
    const o = { quiet: clampN(qI.value, 4, 30, 10), text: txtI.checked }, g = bcGeometry(r, f, o), m = clampN(modI.value, 1, 8, 3), H = clampN(hI.value, 30, 400, 120);
    const fs = Math.max(10, Math.round(m * (g.split ? 9 : 8))), th = o.text ? Math.round(fs * 1.25) : 0, pad = Math.round(m * 4), bear = g.bear * m;
    const W = g.total * m, Ht = H + th + pad * 2 + bear * 2, ctx = cv.getContext("2d");
    cv.width = W; cv.height = Ht; ctx.fillStyle = bgI.value; ctx.fillRect(0, 0, W, Ht); ctx.fillStyle = fgI.value;
    const ext = g.split ? Math.round(fs * 0.6) : 0;
    for (const b of g.bars) ctx.fillRect(b.x * m, pad + bear, b.w * m, H + (b.g ? ext : 0));
    if (bear) { const x1 = bear, x2 = W - bear; ctx.fillRect(x1 - bear, pad, x2 - x1 + 2 * bear, bear); ctx.fillRect(x1 - bear, pad + bear + H, x2 - x1 + 2 * bear, bear); ctx.fillRect(x1 - bear, pad, bear, H + 2 * bear); ctx.fillRect(x2, pad, bear, H + 2 * bear); }
    ctx.textAlign = "center"; ctx.textBaseline = "top";
    for (const t of g.texts) { ctx.font = `${t.small ? Math.round(fs * 0.75) : fs}px ui-monospace, Menlo, Consolas, monospace`; ctx.fillText(t.s, t.x * m, pad + bear * 2 + H + (g.split ? 2 : Math.round(m * 1.5))); }
    last = { r, g, m, H, fs, th, pad, bear, W, Ht, fg: fgI.value, bg: bgI.value, o };
    cv.dataset.value = r.value != null ? r.value : r.text.replace(/\s/g, ""); cv.dataset.format = f; cv.setAttribute("aria-label", `${f} barcode for ${r.text}`);
    meta.textContent = `${BC_FORMATS.find(x => x[0] === f)[1]} · ${r.bits.length} modules · ${W}×${Ht} px${r.added ? " · check digit " + r.text.replace(/\s/g, "").slice(-1) + " added" : ""}`;
    warn.textContent = contrastNote(fgI.value, bgI.value, false);
  }
  function svg() {
    const { g, m, H, fs, pad, bear, W, Ht, fg, bg, o } = last, ext = g.split ? Math.round(fs * 0.6) : 0;
    const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    let d = g.bars.map(b => `M${b.x * m} ${pad + bear}h${b.w * m}v${H + (b.g ? ext : 0)}h-${b.w * m}z`).join("");
    if (bear) { const x1 = bear - bear, x2 = W - bear, w = x2 - x1 + bear; d += `M${x1} ${pad}h${w}v${bear}h-${w}z M${x1} ${pad + bear + H}h${w}v${bear}h-${w}z M${x1} ${pad}h${bear}v${H + 2 * bear}h-${bear}z M${x2} ${pad}h${bear}v${H + 2 * bear}h-${bear}z`; }
    const ty = pad + bear * 2 + H + (g.split ? 2 : Math.round(m * 1.5));
    const t = g.texts.map(x => `<text x="${x.x * m}" y="${ty}" font-size="${x.small ? Math.round(fs * 0.75) : fs}">${esc(x.s)}</text>`).join("");
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${Ht}" width="${W}" height="${Ht}" shape-rendering="crispEdges"><rect width="${W}" height="${Ht}" fill="${bg}"/><path fill="${fg}" d="${d}"/><g fill="${fg}" font-family="ui-monospace, Menlo, Consolas, monospace" text-anchor="middle" dominant-baseline="hanging">${t}</g></svg>`;
  }
  draw();
}

/* ================= PASSWORDS / PASSPHRASES / PINS ================= */
const SETS = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#$%^&*()-_=+[]{};:,.?/~" };
const LOOKALIKE = /[Il1O0o|`'"]/g;
function strength(bits) {
  const lv = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  const sec = 2 ** bits / 2 / 1e11; // average guesses at 100 billion/second (offline attack)
  const t = sec < 1 ? "instantly" : sec < 3600 ? Math.round(sec / 60) + " minutes" : sec < 86400 * 2 ? Math.round(sec / 3600) + " hours" : sec < 3.15e7 * 2 ? Math.round(sec / 86400) + " days" : sec < 3.15e7 * 1e3 ? fmt(Math.round(sec / 3.15e7)) + " years" : sec < 3.15e7 * 1e12 ? "millions+ of years" : "longer than the age of the universe";
  return { lv, label: ["", "Weak", "Fair", "Strong", "Very strong"][lv], t };
}
function makePassword(o) {
  const sets = Object.keys(SETS).filter(k => o[k]).map(k => o.noLook ? SETS[k].replace(LOOKALIKE, "") : SETS[k]).filter(Boolean);
  if (!sets.length) throw new Error("Pick at least one character set.");
  const all = sets.join("");
  if (o.each && o.len < sets.length) throw new Error("Length is shorter than the number of required character sets.");
  const bits = o.len * Math.log2(all.length);
  for (let guard = 0; guard < 1000; guard++) {
    let pw = ""; for (let i = 0; i < o.len; i++) pw += all[randInt(all.length)];
    if (!o.each || sets.every(s => [...pw].some(c => s.includes(c)))) return { pw, bits };
  }
  throw new Error("Couldn't satisfy the rules. Try a longer length.");
}
function makePhrase(o) {
  if (WORDS.length < 1000) throw new Error("Wordlist failed to load.");
  const w = []; for (let i = 0; i < o.words; i++) { let x = WORDS[randInt(WORDS.length)]; if (o.cap === "first") x = x[0].toUpperCase() + x.slice(1); else if (o.cap === "upper") x = x.toUpperCase(); else if (o.cap === "random" && randInt(2)) x = x.toUpperCase(); w.push(x); }
  let bits = o.words * Math.log2(WORDS.length) + (o.cap === "random" ? o.words : 0);
  if (o.num) { const i = randInt(w.length); w[i] += randInt(10); bits += Math.log2(10 * w.length); }
  return { pw: w.join(o.sep), bits };
}
const WEAK_PIN = p => /^(\d)\1+$/.test(p) || "0123456789012345678901234567890".includes(p) || "9876543210987654321098765432109".includes(p) || /^(19|20)\d\d$/.test(p) || /^(\d\d)\1+$/.test(p);
function makePin(o) {
  for (let guard = 0; guard < 1000; guard++) { let p = ""; for (let i = 0; i < o.len; i++) p += randInt(10); if (!o.noWeak || !WEAK_PIN(p)) return { pw: p, bits: o.len * Math.log2(10) }; }
  throw new Error("Couldn't build a PIN.");
}
function pwTool(form, out, p) {
  let mode = p.m || "pw"; const S = Object.assign({ len: 20, lower: true, upper: true, digits: true, symbols: true, noLook: false, each: true, words: 5, sep: "-", cap: "first", num: true, plen: 6, noWeak: true, count: 1 }, store.get("pw") || {});
  seg(form, [["pw", "Password"], ["pp", "Passphrase"], ["pin", "PIN"]], mode, m => { mode = m; fields(); gen(); }).classList.add("wide");
  const box = sub(form);
  const countI = F(form, "How many", I("number", { min: "1", max: "100", value: String(S.count) }));
  const tools = el("div", "row wide"); form.append(tools);
  btn(tools, "↻ Generate", "btn", gen);
  const big = el("div", "pwbig mono"); big.setAttribute("aria-live", "polite");
  const meter = el("div", "meter"), mbar = el("i"); meter.append(mbar); const mlab = el("div", "mlab");
  const list = el("ol", "pwlist mono"); const rt = el("div", "rtools");
  out.append(big, meter, mlab, rt, list);
  btn(rt, "Copy", "btn sm", () => cur.length && copy(cur[0], "Copied"));
  btn(rt, "Copy all", "chip", () => cur.length && copy(cur.join("\n"), `${cur.length} copied`));
  btn(rt, "⬇ .txt", "chip", () => cur.length && download(new Blob([cur.join("\n") + "\n"], { type: "text/plain" }), "passwords.txt"));
  let cur = [];
  function fields() {
    box.textContent = "";
    const bind = (i, k, num, lo, hi) => { i.addEventListener("input", () => { S[k] = i.type === "checkbox" ? i.checked : num ? clampN(i.value, lo, hi, S[k]) : i.value; store.set("pw", S); gen(); }); return i; };
    if (mode === "pw") {
      const r = F(box, "Length", I("range", { min: "4", max: "128", value: String(S.len) }), "wide"); const n = el("b", "rv", S.len); r.parentNode.append(n);
      r.addEventListener("input", () => { n.textContent = r.value; }); bind(r, "len", 1, 4, 128);
      bind(CK(box, "Lowercase a–z", S.lower), "lower"); bind(CK(box, "Uppercase A–Z", S.upper), "upper"); bind(CK(box, "Digits 0–9", S.digits), "digits"); bind(CK(box, "Symbols !@#…", S.symbols), "symbols");
      bind(CK(box, "Exclude look-alikes (I l 1 O 0 o)", S.noLook), "noLook"); bind(CK(box, "Use every selected set", S.each), "each");
    } else if (mode === "pp") {
      const r = F(box, "Words", I("range", { min: "3", max: "12", value: String(S.words) }), "wide"); const n = el("b", "rv", S.words); r.parentNode.append(n);
      r.addEventListener("input", () => { n.textContent = r.value; }); bind(r, "words", 1, 3, 12);
      const sep = F(box, "Separator", I("select", { options: [["-", "Hyphen -"], [" ", "Space"], [".", "Dot ."], ["_", "Underscore _"], [",", "Comma ,"], ["", "None"]] })); sep.value = S.sep; bind(sep, "sep");
      const cap = F(box, "Capitalization", I("select", { options: [["lower", "lowercase"], ["first", "Capitalize Each"], ["upper", "UPPERCASE"], ["random", "rAnDoM words"]] })); cap.value = S.cap; bind(cap, "cap");
      bind(CK(box, "Add a number", S.num), "num");
      box.append(el("p", "hint wide", `Words come from the EFF short wordlist (${fmt(WORDS.length)} words, ${Math.log2(WORDS.length || 1).toFixed(1)} bits each), bundled with the page.`));
    } else {
      const r = F(box, "Digits", I("range", { min: "4", max: "12", value: String(S.plen) }), "wide"); const n = el("b", "rv", S.plen); r.parentNode.append(n);
      r.addEventListener("input", () => { n.textContent = r.value; }); bind(r, "plen", 1, 4, 12);
      bind(CK(box, "Avoid easy PINs (1234, 0000, years, repeats)", S.noWeak), "noWeak");
    }
  }
  countI.addEventListener("input", () => { S.count = clampN(countI.value, 1, 100, 1); store.set("pw", S); gen(); });
  function gen() {
    const n = clampN(countI.value, 1, 100, 1); cur = []; list.textContent = "";
    try {
      let bits = 0;
      for (let i = 0; i < n; i++) { const r = mode === "pw" ? makePassword(S) : mode === "pp" ? makePhrase(S) : makePin({ len: S.plen, noWeak: S.noWeak }); cur.push(r.pw); bits = r.bits; }
      big.textContent = ""; [...cur[0]].forEach(c => big.append(el("span", /\d/.test(c) ? "d" : /[A-Za-z]/.test(c) ? "" : "s", c)));
      if (mode === "pin" && S.noWeak) bits = Math.log2(10 ** S.plen * 0.98);
      const st = strength(bits); meter.className = "meter l" + st.lv; mbar.style.width = Math.min(100, bits / 1.28) + "%";
      mlab.textContent = `${st.label} · ${Math.round(bits)} bits of entropy · ~${st.t} to crack at 100 billion guesses/second${mode === "pin" ? " (PINs are meant for rate-limited devices)" : ""}`;
      big.dataset.bits = Math.round(bits);
      if (n > 1) cur.forEach(x => list.append(el("li", null, x)));
    } catch (e) { cur = []; big.textContent = ""; mlab.textContent = e.message; meter.className = "meter"; mbar.style.width = "0"; }
  }
  fields(); gen();
}

/* ================= RANDOM: numbers, wheel, teams, dice, coin ================= */
const parseNames = s => s.split(/\r?\n|,/).map(x => x.trim()).filter(Boolean).slice(0, 500).map(x => x.slice(0, 60));
const DEMO_NAMES = "Ava\nBen\nChloe\nDiego\nElla\nFinn\nGrace\nHiro";
const reduced = () => window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
function randTool(form, out, p) {
  const m = p.m || "num";
  if (m === "num") return numTool(form, out);
  if (m === "wheel") return wheelTool(form, out);
  if (m === "teams") return teamTool(form, out);
  if (m === "dice") return diceTool(form, out);
  return coinTool(form, out);
}
function numTool(form, out) {
  const minI = F(form, "Minimum", I("number", { value: "1", min: "-1000000000000", max: "1000000000000" }));
  const maxI = F(form, "Maximum", I("number", { value: "100", min: "-1000000000000", max: "1000000000000" }));
  const cI = F(form, "How many", I("number", { value: "1", min: "1", max: "1000" }));
  const uI = CK(form, "No repeats (unique)", true), sI = CK(form, "Sort results", false);
  const row = el("div", "row wide"); form.append(row); btn(row, "🎲 Generate", "btn", gen);
  const big = el("div", "rbig mono"), err = el("div", "err"), list = el("div", "numlist mono"), meta = el("div", "meta"), rt = el("div", "rtools");
  out.append(big, err, meta, list, rt);
  let cur = [];
  btn(rt, "Copy", "chip", () => cur.length && copy(cur.join(", "), "Copied"));
  btn(rt, "⬇ .txt", "chip", () => cur.length && download(new Blob([cur.join("\n") + "\n"], { type: "text/plain" }), "random-numbers.txt"));
  function gen() {
    err.textContent = ""; list.textContent = ""; big.textContent = ""; meta.textContent = "";
    const lo = Math.ceil(Number(minI.value)), hi = Math.floor(Number(maxI.value)), n = clampN(cI.value, 1, 1000, 1);
    if (!Number.isSafeInteger(lo) || !Number.isSafeInteger(hi) || Math.abs(lo) > 1e12 || Math.abs(hi) > 1e12) { err.textContent = "Use whole numbers between −1,000,000,000,000 and 1,000,000,000,000."; return; }
    if (lo > hi) { err.textContent = "Minimum must be less than or equal to maximum."; return; }
    const span = hi - lo + 1;
    if (uI.checked && n > span) { err.textContent = `Only ${fmt(span)} unique numbers exist in that range.`; return; }
    if (uI.checked && span <= 100000) { const a = Array.from({ length: span }, (_, i) => lo + i); for (let i = 0; i < n; i++) { const j = i + randInt(span - i); [a[i], a[j]] = [a[j], a[i]]; } cur = a.slice(0, n); }
    else if (uI.checked) { const s = new Set(); while (s.size < n) s.add(lo + randInt(span)); cur = [...s]; }
    else cur = Array.from({ length: n }, () => lo + randInt(span));
    if (sI.checked) cur.sort((a, b) => a - b);
    if (n === 1) { big.textContent = fmt(cur[0]); big.classList.remove("pop"); void big.offsetWidth; big.classList.add("pop"); }
    else cur.forEach(x => list.append(el("span", null, x)));
    meta.textContent = `${n} number${n > 1 ? "s" : ""} from ${fmt(lo)} to ${fmt(hi)}${uI.checked ? ", no repeats" : ""} · each value equally likely (crypto RNG, rejection sampling)`;
    out.dataset.result = cur.join(",");
  }
  gen();
}
function wheelTool(form, out) {
  const ta = F(form, "Names (one per line or comma-separated, up to 500)", I("textarea", { rows: "8", maxlength: "20000", spellcheck: "false" }), "wide"); ta.value = store.get("names") || DEMO_NAMES;
  const rmI = CK(form, "Remove the winner after each spin", false);
  const row = el("div", "row wide"); form.append(row);
  const spinB = btn(row, "🎡 Spin", "btn", spin); btn(row, "Shuffle list", "chip", () => { ta.value = shuffle(parseNames(ta.value)).join("\n"); upd(); }); btn(row, "Reset", "chip", () => { ta.value = DEMO_NAMES; upd(); });
  const wrap = el("div", "wheelwrap"), cv = el("canvas", "wheel"), ptr = el("div", "ptr"); cv.width = cv.height = 880; cv.setAttribute("role", "img"); cv.setAttribute("aria-label", "Name wheel"); wrap.append(cv, ptr);
  const win = el("div", "winner"); win.setAttribute("aria-live", "polite"); const meta = el("div", "meta"), hist = el("ol", "items");
  out.append(wrap, win, meta, hist);
  const COLORS = ["#2dd4bf", "#a855f7", "#f59e0b", "#3b82f6", "#ef4444", "#22c55e", "#ec4899", "#14b8a6", "#8b5cf6", "#f97316"];
  let names = [], angle = 0, spinning = false;
  function upd() { names = parseNames(ta.value); store.set("names", ta.value.slice(0, 20000)); meta.textContent = `${names.length} name${names.length === 1 ? "" : "s"} on the wheel`; spinB.disabled = names.length < 2 || spinning; render(); }
  ta.addEventListener("input", upd);
  function render() {
    const c = cv.getContext("2d"), R = 430, C = 440, n = names.length; c.clearRect(0, 0, 880, 880);
    if (!n) { c.fillStyle = "#64748b"; c.beginPath(); c.arc(C, C, R, 0, 7); c.fill(); return; }
    const seg = 2 * Math.PI / n;
    for (let i = 0; i < n; i++) {
      const a0 = angle + i * seg - Math.PI / 2; c.beginPath(); c.moveTo(C, C); c.arc(C, C, R, a0, a0 + seg); c.closePath();
      c.fillStyle = COLORS[(n % COLORS.length === 1 && i === n - 1) ? 2 : i % COLORS.length]; c.fill(); c.strokeStyle = "rgba(0,0,0,.25)"; c.lineWidth = 2; c.stroke();
      c.save(); c.translate(C, C); c.rotate(a0 + seg / 2); c.textAlign = "right"; c.textBaseline = "middle"; c.fillStyle = "#0b1020";
      const fs = Math.max(12, Math.min(34, 900 / n)); c.font = `600 ${fs}px system-ui, sans-serif`;
      let t = names[i]; while (t.length > 1 && c.measureText(t).width > R - 90) t = t.slice(0, -1); if (t !== names[i]) t = t.slice(0, -1) + "…";
      c.fillText(t, R - 24, 0); c.restore();
    }
    c.beginPath(); c.arc(C, C, 46, 0, 7); c.fillStyle = "#0b1020"; c.fill(); c.strokeStyle = "#fff"; c.lineWidth = 6; c.stroke();
  }
  function spin() {
    if (spinning || names.length < 2) return;
    spinning = true; spinB.disabled = true; win.textContent = ""; win.classList.remove("on");
    const n = names.length, seg = 2 * Math.PI / n, idx = randInt(n), off = (0.1 + 0.8 * randInt(1000) / 1000) * seg;
    // final angle so the pointer (top) sits inside segment idx
    const want = -(idx * seg + off), base = angle - (angle % (2 * Math.PI)), target = base + 2 * Math.PI * (reduced() ? 1 : 6) + ((want % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
    const start = angle, dur = reduced() ? 250 : 4600, t0 = performance.now();
    const step = now => {
      const t = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - t, 4); angle = start + (target - start) * e; render();
      if (t < 1) return requestAnimationFrame(step);
      angle = target % (2 * Math.PI); spinning = false; const w = names[idx];
      const under = Math.floor((((-angle) % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI) / seg) % n;
      win.textContent = "🎉 " + w; win.classList.add("on"); out.dataset.winner = w; out.dataset.under = names[under];
      hist.prepend(el("li", null, w)); while (hist.children.length > 20) hist.lastChild.remove();
      if (rmI.checked) { const arr = parseNames(ta.value); arr.splice(idx, 1); ta.value = arr.join("\n"); }
      upd();
    };
    requestAnimationFrame(step);
  }
  upd();
}
function teamTool(form, out) {
  const ta = F(form, "Names (one per line or comma-separated)", I("textarea", { rows: "8", maxlength: "20000", spellcheck: "false" }), "wide"); ta.value = store.get("names") || DEMO_NAMES;
  const modeI = F(form, "Split by", I("select", { options: [["teams", "Number of teams"], ["size", "People per team"]] }));
  const nI = F(form, "Number", I("number", { min: "2", max: "100", value: "2" }));
  const row = el("div", "row wide"); form.append(row); btn(row, "🔀 Make teams", "btn", gen);
  const err = el("div", "err"), box = el("div", "teams"), rt = el("div", "rtools"); out.append(err, box, rt);
  let txt = ""; btn(rt, "Copy teams", "chip", () => txt && copy(txt, "Teams copied"));
  function gen() {
    err.textContent = ""; box.textContent = ""; txt = "";
    const names = shuffle(parseNames(ta.value)), k = clampN(nI.value, 1, 100, 2);
    if (names.length < 2) { err.textContent = "Add at least two names."; return; }
    const teams = modeI.value === "teams" ? Math.min(Math.max(2, k), names.length) : Math.max(1, Math.ceil(names.length / Math.max(1, k)));
    const T = Array.from({ length: teams }, () => []); names.forEach((x, i) => T[i % teams].push(x));
    T.forEach((t, i) => { const d = el("div", "team"); d.append(el("h3", null, `Team ${i + 1} · ${t.length}`)); const ul = el("ul"); t.forEach(x => ul.append(el("li", null, x))); d.append(ul); box.append(d); });
    txt = T.map((t, i) => `Team ${i + 1}: ${t.join(", ")}`).join("\n"); out.dataset.teams = String(teams);
  }
  gen();
}
function diceTool(form, out) {
  const nI = F(form, "Number of dice", I("number", { min: "1", max: "50", value: "2" }));
  const sI = F(form, "Sides", I("select", { options: [["4", "d4"], ["6", "d6"], ["8", "d8"], ["10", "d10"], ["12", "d12"], ["20", "d20"], ["100", "d100"]] })); sI.value = "6";
  const modI = F(form, "Modifier (+/-)", I("number", { min: "-100", max: "100", value: "0" }));
  const row = el("div", "row wide"); form.append(row); btn(row, "🎲 Roll", "btn", roll);
  const dice = el("div", "dice"), big = el("div", "rbig mono"), meta = el("div", "meta"), hist = el("ol", "items"); out.append(dice, big, meta, hist);
  function roll() {
    const n = clampN(nI.value, 1, 50, 2), s = +sI.value, md = clampN(modI.value, -100, 100, 0), r = Array.from({ length: n }, () => 1 + randInt(s)), tot = r.reduce((a, b) => a + b, 0) + md;
    dice.textContent = ""; r.forEach(x => { const d = el("span", "die" + (s === 6 ? " d6" : ""), x); dice.append(d); });
    big.textContent = fmt(tot); big.classList.remove("pop"); void big.offsetWidth; big.classList.add("pop");
    const desc = `${n}d${s}${md ? (md > 0 ? "+" : "") + md : ""}`;
    meta.textContent = `${desc} · rolls: ${r.join(" + ")}${md ? ` ${md > 0 ? "+" : "−"} ${Math.abs(md)}` : ""} = ${tot} · range ${n + md}–${n * s + md}`;
    hist.prepend(el("li", null, `${desc} → ${tot}`)); while (hist.children.length > 15) hist.lastChild.remove(); out.dataset.total = String(tot);
  }
  roll();
}
function coinTool(form, out) {
  const nI = F(form, "Coins per flip", I("number", { min: "1", max: "100", value: "1" }));
  const row = el("div", "row wide"); form.append(row); btn(row, "🪙 Flip", "btn", flip); btn(row, "Reset tally", "chip", () => { H = T = 0; tally(); });
  const coin = el("div", "coin"), face = el("span", null, "?"); coin.append(face); const res = el("div", "rbig"), meta = el("div", "meta"); out.append(coin, res, meta);
  let H = 0, T = 0;
  const tally = () => { meta.textContent = `Tally: ${H} heads · ${T} tails${H + T ? ` · ${(100 * H / (H + T)).toFixed(1)}% heads` : ""}`; };
  function flip() {
    const n = clampN(nI.value, 1, 100, 1), r = Array.from({ length: n }, () => randInt(2) === 0), h = r.filter(Boolean).length; H += h; T += n - h;
    coin.classList.remove("flip", "tails"); void coin.offsetWidth; coin.classList.add("flip"); if (!r[0]) coin.classList.add("tails");
    face.textContent = r[0] ? "H" : "T";
    res.textContent = n === 1 ? (r[0] ? "Heads" : "Tails") : `${h} heads · ${n - h} tails`; out.dataset.result = r.map(x => x ? "H" : "T").join(""); tally();
  }
  tally();
}

/* ================= UUIDs ================= */
const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
let v7last = 0, v7seq = 0;
function uuidBytes(ver) {
  const b = crypto.getRandomValues(new Uint8Array(16));
  if (ver === 7) {
    let ms = Date.now();
    if (ms <= v7last) { ms = v7last; v7seq++; if (v7seq > 0xfff) { ms = ++v7last; v7seq = randInt(0x800); } } else { v7last = ms; v7seq = randInt(0x800); }
    const hi = Math.floor(ms / 2 ** 16), lo = ms % 2 ** 16;
    b[0] = hi >>> 24 & 255; b[1] = hi >>> 16 & 255; b[2] = hi >>> 8 & 255; b[3] = hi & 255; b[4] = lo >>> 8; b[5] = lo & 255;
    b[6] = 0x70 | (v7seq >>> 8); b[7] = v7seq & 255;
  } else b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80; return b;
}
const fmtUuid = h => `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
function inspectUuid(s) {
  const h = s.trim().replace(/^[{"']+|[}"',]+$/g, "").replace(/^urn:uuid:/i, "").replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(h)) return "Not a valid UUID (expected 32 hex digits, with or without hyphens).";
  if (/^0{32}$/.test(h)) return "Nil UUID (all zeros).";
  if (/^f{32}$/.test(h)) return "Max UUID (all ones).";
  const ver = parseInt(h[12], 16), vb = parseInt(h[16], 16), variant = vb < 8 ? "NCS (legacy)" : vb < 12 ? "RFC 9562 / RFC 4122" : vb < 14 ? "Microsoft (legacy)" : "Reserved";
  let r = `Version ${ver} · variant ${variant}`;
  if (ver === 7) { const ms = parseInt(h.slice(0, 12), 16); r += ` · created ${new Date(ms).toISOString()} (Unix ms ${ms})`; }
  if (ver === 4) r += " · random (122 random bits)";
  if (ver === 1 || ver === 6) r += " · time-based with node ID";
  return r;
}
function uuidTool(form, out) {
  let ver = 4;
  seg(form, [["4", "UUID v4 (random)"], ["7", "UUID v7 (time-ordered)"]], "4", v => { ver = +v; gen(); }).classList.add("wide");
  const nI = F(form, "How many", I("number", { min: "1", max: "1000", value: "5" }));
  const fI = F(form, "Wrap", I("select", { options: [["none", "None"], ["braces", "{braces}"], ["quotes", "\"quotes\","], ["urn", "urn:uuid:"]] }));
  const upI = CK(form, "UPPERCASE", false), hyI = CK(form, "Hyphens", true);
  const row = el("div", "row wide"); form.append(row); btn(row, "↻ Generate", "btn", gen);
  const ta = I("textarea", { rows: "10", readonly: "", spellcheck: "false", "aria-label": "Generated UUIDs" }); ta.className = "uuidout mono"; ta.removeAttribute("maxlength");
  const rt = el("div", "rtools"), meta = el("div", "meta"); out.append(ta, meta, rt);
  btn(rt, "Copy all", "btn sm", () => ta.value && copy(ta.value, "UUIDs copied")); btn(rt, "⬇ .txt", "chip", () => ta.value && download(new Blob([ta.value + "\n"], { type: "text/plain" }), "uuids.txt"));
  const ins = el("div", "card inspect"); ins.append(el("h3", null, "Inspect a UUID")); const ii = I("text", { maxlength: "60", placeholder: "Paste any UUID", spellcheck: "false", "aria-label": "UUID to inspect" }); const ib = el("div", "inbox"); ib.append(ii); const ir = el("p", "meta"); ins.append(ib, ir); out.append(ins);
  ii.addEventListener("input", () => { ir.textContent = ii.value.trim() ? inspectUuid(ii.value) : ""; });
  [nI, fI, upI, hyI].forEach(i => i.addEventListener("input", gen));
  function gen() {
    const n = clampN(nI.value, 1, 1000, 5), L = [];
    for (let i = 0; i < n; i++) {
      let s = hex(uuidBytes(ver)); if (hyI.checked) s = fmtUuid(s); if (upI.checked) s = s.toUpperCase();
      L.push(fI.value === "braces" ? `{${s}}` : fI.value === "quotes" ? `"${s}",` : fI.value === "urn" ? "urn:uuid:" + s : s);
    }
    ta.value = L.join("\n"); meta.textContent = `${n} × UUID v${ver}${ver === 7 ? " · sorted by creation time; first 48 bits are a Unix-ms timestamp" : " · 122 random bits each"}`;
    if (!ii.value) { ii.placeholder = L[0]; }
  }
  gen();
}

/* ================= HASHES ================= */
const MD5K = new Int32Array(64).map((_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) | 0);
const MD5S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
class MD5 {
  constructor() { this.h = new Int32Array([0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476]); this.buf = new Uint8Array(64); this.bl = 0; this.len = 0; this.X = new Int32Array(16); }
  update(d) {
    let i = 0; this.len += d.length;
    if (this.bl) { const n = Math.min(64 - this.bl, d.length); this.buf.set(d.subarray(0, n), this.bl); this.bl += n; i = n; if (this.bl < 64) return this; this.blk(this.buf, 0); this.bl = 0; }
    for (; i + 64 <= d.length; i += 64) this.blk(d, i);
    if (i < d.length) { this.buf.set(d.subarray(i), 0); this.bl = d.length - i; }
    return this;
  }
  blk(d, o) {
    const X = this.X; for (let k = 0; k < 16; k++) X[k] = d[o + 4 * k] | d[o + 4 * k + 1] << 8 | d[o + 4 * k + 2] << 16 | d[o + 4 * k + 3] << 24;
    let [a, b, c, e] = this.h;
    for (let i = 0; i < 64; i++) {
      let f, g; const r = i >> 4;
      if (r === 0) { f = (b & c) | (~b & e); g = i; } else if (r === 1) { f = (e & b) | (~e & c); g = (5 * i + 1) & 15; } else if (r === 2) { f = b ^ c ^ e; g = (3 * i + 5) & 15; } else { f = c ^ (b | ~e); g = (7 * i) & 15; }
      const s = MD5S[r * 4 + (i & 3)], x = (a + f + MD5K[i] + X[g]) | 0; a = e; e = c; c = b; b = (b + (x << s | x >>> (32 - s))) | 0;
    }
    const h = this.h; h[0] += a; h[1] += b; h[2] += c; h[3] += e;
  }
  digest() {
    const bits = this.len * 8, padLen = (this.bl < 56 ? 56 : 120) - this.bl, pad = new Uint8Array(padLen + 8); pad[0] = 0x80;
    const dv = new DataView(pad.buffer); dv.setUint32(padLen, bits >>> 0, true); dv.setUint32(padLen + 4, Math.floor(bits / 2 ** 32), true);
    this.update(pad); const out = new Uint8Array(16), ov = new DataView(out.buffer); for (let k = 0; k < 4; k++) ov.setInt32(4 * k, this.h[k], true); return out;
  }
}
const md5 = d => new MD5().update(d).digest();
function hmacMd5(key, msg) {
  if (key.length > 64) key = md5(key); const k = new Uint8Array(64); k.set(key);
  const ip = k.map(x => x ^ 0x36), op = k.map(x => x ^ 0x5c);
  return new MD5().update(op).update(new MD5().update(ip).update(msg).digest()).digest();
}
const ALGOS = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"];
const b64 = b => { let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); };
async function digestAll(data, key) {
  const r = {};
  for (const a of ALGOS) {
    if (a === "MD5") r[a] = key ? hmacMd5(key, data) : md5(data);
    else if (key) { const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: a }, false, ["sign"]); r[a] = new Uint8Array(await crypto.subtle.sign("HMAC", k, data)); }
    else r[a] = new Uint8Array(await crypto.subtle.digest(a, data));
  }
  return r;
}
async function md5File(file, onProg) { const h = new MD5(), CH = 4 * 1024 * 1024; for (let o = 0; o < file.size; o += CH) { h.update(new Uint8Array(await file.slice(o, o + CH).arrayBuffer())); onProg && onProg(Math.min(1, (o + CH) / file.size)); } return h.digest(); }
function hashTool(form, out, p) {
  let mode = p.file ? "file" : "text", file = null, token = 0, res = null; const prim = p.a || "SHA-256", enc = new TextEncoder();
  seg(form, [["text", "Text"], ["file", "File"]], mode, m => { mode = m; tbox.hidden = m !== "text"; drop.hidden = m !== "file"; run(); }).classList.add("wide");
  const tbox = el("div", "field wide"); form.append(tbox);
  const ta = I("textarea", { rows: "6", maxlength: "1000000", spellcheck: "false", placeholder: "Type or paste text to hash", "aria-label": "Text to hash" }); ta.value = p.hmac ? "The quick brown fox jumps over the lazy dog" : "abc"; tbox.append(el("span", "lab", "Text (UTF-8)"), ta);
  const drop = el("label", "drop wide"); const fI = I("file", { "aria-label": "File to hash" }); fI.className = "file"; const fn = el("span", "fname", "Drop a file here or click to choose (up to 512 MB, never uploaded)"); drop.append(fI, el("b", null, "📄"), fn); form.append(drop);
  tbox.hidden = mode !== "text"; drop.hidden = mode !== "file";
  let keyI = null; if (p.hmac) { keyI = F(form, "Secret key (UTF-8)", I("text", { maxlength: "1000", spellcheck: "false", autocomplete: "off", value: "key" }), "wide"); keyI.addEventListener("input", run); }
  const encI = F(form, "Output", I("select", { options: [["hex", "hex (lowercase)"], ["HEX", "HEX (uppercase)"], ["b64", "Base64"]] }));
  const cmpI = F(form, "Compare with expected hash (optional)", I("text", { maxlength: "200", spellcheck: "false", placeholder: "Paste a published checksum" }), "wide");
  const status = el("div", "meta"), verdict = el("div", "verdict"), box = el("div", "hashes"); out.append(status, box, verdict);
  ta.addEventListener("input", run); encI.addEventListener("input", show); cmpI.addEventListener("input", show);
  const pick = f => { if (!f) return; if (f.size > 512 * 1024 * 1024) { toast("Files up to 512 MB only."); return; } file = f; fn.textContent = `${safeName(f.name)} · ${fmt(f.size)} bytes`; run(); };
  fI.addEventListener("change", () => pick(fI.files[0]));
  ["dragenter", "dragover"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", ev => pick(ev.dataTransfer && ev.dataTransfer.files[0]));
  const fmtH = b => encI.value === "b64" ? b64(b) : encI.value === "HEX" ? hex(b).toUpperCase() : hex(b);
  async function run() {
    const my = ++token; res = null; box.textContent = ""; verdict.textContent = ""; verdict.className = "verdict";
    let key = null; if (p.hmac) { if (!keyI.value) { status.textContent = "Enter a secret key to compute an HMAC."; return; } key = enc.encode(keyI.value); }
    try {
      let data, r;
      if (mode === "text") { data = enc.encode(ta.value); status.textContent = `${fmt(data.length)} bytes of UTF-8 text${key ? " · HMAC with your key" : ""}`; r = await digestAll(data, key); }
      else {
        if (!file) { status.textContent = "Choose a file to hash. It's read locally and never uploaded."; return; }
        status.textContent = "Reading file…"; const t0 = performance.now();
        if (key) { data = new Uint8Array(await file.arrayBuffer()); r = await digestAll(data, key); }
        else { const m = await md5File(file, x => { if (my === token) status.textContent = `Hashing… ${Math.round(x * 100)}%`; }); if (my !== token) return; data = await file.arrayBuffer(); r = { MD5: m }; for (const a of ALGOS.slice(1)) r[a] = new Uint8Array(await crypto.subtle.digest(a, data)); }
        status.textContent = `${safeName(file.name)} · ${fmt(file.size)} bytes · ${Math.round(performance.now() - t0)} ms`;
      }
      if (my !== token) return; res = r; show();
    } catch (e) { if (my === token) status.textContent = "Couldn't hash that input: " + (e && e.message ? e.message : "error"); }
  }
  function show() {
    if (!res) return; box.textContent = "";
    const order = [prim, ...ALGOS.filter(a => a !== prim)];
    for (const a of order) {
      const v = fmtH(res[a]), row = el("div", "hrow" + (a === prim ? " prim" : "")); row.dataset.algo = a; row.dataset.hex = hex(res[a]);
      const hh = el("div", "hhead"); hh.append(el("b", null, (p.hmac ? "HMAC-" : "") + a), el("small", null, `${res[a].length * 8} bits${a === "MD5" || a === "SHA-1" ? " · not collision-safe" : ""}`)); btn(hh, "Copy", "chip xs", () => copy(v, a + " copied"));
      row.append(hh, el("code", "hval mono", v)); box.append(row);
    }
    const want = cmpI.value.trim().replace(/\s+/g, ""); verdict.className = "verdict";
    if (!want) { verdict.textContent = ""; return; }
    const hit = ALGOS.find(a => hex(res[a]) === want.toLowerCase() || b64(res[a]) === want);
    box.querySelectorAll(".hrow").forEach(r => r.classList.toggle("match", !!hit && r.dataset.algo === hit));
    if (hit) { verdict.classList.add("ok"); verdict.textContent = `✓ Match: ${hit}. The input is identical to the one the checksum was made from.`; }
    else { verdict.classList.add("no"); verdict.textContent = "✗ No match. The input differs, or the checksum uses another algorithm."; }
  }
  run();
}

/* ================= page wiring ================= */
const TOOLS = { qr: qrTool, bc: bcTool, barcode: bcTool, pw: pwTool, password: pwTool, rand: randTool, random: randTool, uuid: uuidTool, hash: hashTool };
function adSlot(name, kind) { const d = el("div", "ad ad-" + kind); d.dataset.slot = name; d.append(el("span", null, "Advertisement")); return d; }
const setTheme = t => { document.documentElement.dataset.theme = t; store.set("theme", t); const b = $("#theme"); if (b) b.textContent = t === "light" ? "🌙" : "☀️"; };
setTheme(store.get("theme") || (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
$("#theme") && $("#theme").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));
if ($("#year")) $("#year").textContent = new Date().getFullYear();

const PAGE_ID = document.body.dataset.tool || "", IS_DOC = document.body.dataset.doc === "1";
if (PAGE_ID) {
  const pg = PAGES.find(x => x.id === PAGE_ID);
  if (pg && TOOLS[pg.tool]) {
    $("#home") && ($("#home").hidden = true); $("#tool").hidden = false;
    $("#t-icon").textContent = pg.icon; $("#t-cat").textContent = pg.cat; $("#t-name").textContent = pg.name; $("#t-desc").textContent = pg.desc;
    const form = $("#t-form"), out = $("#t-out");
    try { TOOLS[pg.tool](form, out, Object.assign({}, pg.p || {})); }
    catch (e) { out.textContent = ""; out.append(el("div", "err", "This tool couldn't start in your browser: " + (e && e.message || "error"))); }
    const rec = (store.get("recent") || []).filter(x => x !== pg.id); rec.unshift(pg.id); store.set("recent", rec.slice(0, 6));
  }
} else if (!IS_DOC && $("#grid") && $("#grid").tagName === "SECTION") {
  const CATS = ["All", ...new Set(PAGES.map(x => x.cat))]; let curCat = "All";
  const grid = $("#grid"), search = $("#search"), recent = store.get("recent") || [];
  const render = () => {
    const q = search.value.trim().toLowerCase().slice(0, 60);
    const list = PAGES.filter(c => (curCat === "All" || c.cat === curCat) && (!q || (c.name + " " + c.desc + " " + c.cat).toLowerCase().includes(q)));
    grid.textContent = "";
    list.forEach((c, i) => { const a = el("a", "tile"); a.href = BASE + "/" + c.id + "/"; a.append(el("span", "ti", c.icon), el("b", null, c.name), el("p", null, c.desc), el("small", null, c.cat + (recent.includes(c.id) ? " · recent" : ""))); grid.append(a); if (i === 5) grid.append(adSlot("in-grid", "rect")); });
    if (!list.length) grid.append(el("p", "empty", "No tools match “" + q + "”."));
    $("#count").textContent = `${list.length} tool${list.length === 1 ? "" : "s"}${curCat !== "All" ? " in " + curCat : ""}`;
  };
  CATS.forEach(c => { const b = el("button", "pill" + (c === "All" ? " on" : ""), c); b.type = "button"; b.addEventListener("click", () => { curCat = c; document.querySelectorAll(".pill").forEach(p => p.classList.toggle("on", p === b)); render(); }); $("#cats").append(b); });
  search.addEventListener("input", render);
  document.addEventListener("keydown", e => { if (e.key === "/" && document.activeElement !== search && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); search.focus(); } });
  render();
}

/* cookie / ad consent (ads load only after a choice; non-personalized if rejected) */
window.mintkitConsent = () => store.get("consent");
if (!store.get("consent")) {
  const bar = el("div", "consent"); bar.setAttribute("role", "dialog"); bar.setAttribute("aria-label", "Cookie consent");
  const t = el("p"); t.append("We use cookies only to show ads that keep Mintkit free. Everything you generate stays on your device. "); const a = el("a", null, "Privacy policy"); a.href = BASE + "/privacy/"; t.append(a);
  const acc = el("button", "btn sm", "Accept"), rej = el("button", "chip", "Only necessary"); [acc, rej].forEach(b => { b.type = "button"; });
  const done = v => { store.set("consent", { ads: v, at: Date.now() }); bar.remove(); document.dispatchEvent(new CustomEvent("mintkit:consent", { detail: v, bubbles: true })); };
  acc.addEventListener("click", () => done(true)); rej.addEventListener("click", () => done(false));
  const bx = el("div", "cbtns"); bx.append(rej, acc); bar.append(t, bx); document.body.append(bar);
}
// Ad loading hook: after approval, load the network's script here, e.g.
// document.addEventListener("mintkit:consent", e => { /* e.detail === true → personalized, false → non-personalized */ });

window.MK_TEST = { randInt, md5: s => hex(md5(new TextEncoder().encode(s))), hmacMd5: (k, m) => hex(hmacMd5(new TextEncoder().encode(k), new TextEncoder().encode(m))), code128, ean13, upca, code39, itf14, gs1, qrPayload, inspectUuid };
})();
