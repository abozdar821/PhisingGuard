/* In-browser file readers for the device build: .eml, text, and PDF (via pdf.js, loaded on first use). */
(function (root) {
"use strict";
const ADDR = /([^<>\n]*?<\s*[^<>@\s]+@[^<>\s]+\s*>)/;
function parseMailPrint(text) {
  const lines = String(text || "").split(/\r?\n/).map(l => l.replace(/\s+$/, ""));
  for (let i = 0; i < Math.min(lines.length, 25); i++) {
    const m = ADDR.exec(lines[i].trim());
    if (!m || /^\s*(?:to|cc|bcc|reply-to)\s*:/i.test(lines[i])) continue;
    const sender = m[1].replace(/^\s*from:\s*/i, "").trim();
    let subject = "";
    for (let k = i - 1; k >= 0; k--) {
      const p = lines[k].trim();
      if (p && !/^(?:\d+ messages?|gmail\b.*|outlook\b.*|inbox|print)$/i.test(p) && !p.includes("@")) { subject = p; break; }
    }
    let replyTo = "", j = i + 1;
    while (j < lines.length && (!lines[j].trim() || /^\s*(?:reply-to|to|cc|bcc|date|sent|subject)\s*:/i.test(lines[j]))) {
      const rm = /^\s*reply-to\s*:\s*(.+)$/i.exec(lines[j]); if (rm) replyTo = rm[1].trim();
      const sm = /^\s*subject\s*:\s*(.+)$/i.exec(lines[j]); if (sm && !subject) subject = sm[1].trim();
      j++;
    }
    const body = lines.slice(j).map(l => l.trim()).join("\n").replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
    return {mode: "email", sender: sender.slice(0, 200), subject: subject.slice(0, 300), body: body.slice(0, 5000),
            headers: replyTo ? {reply_to: replyTo} : null};
  }
  return null;
}
function decodeQP(s) {
  const bytes = [];
  s = s.replace(/=\r?\n/g, "");
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { bytes.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
    else { const c = s.charCodeAt(i); if (c < 128) bytes.push(c); else bytes.push(...new TextEncoder().encode(s[i])); }
  }
  return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
}
function decodeB64(s) {
  try { const bin = atob(s.replace(/\s+/g, "")); return new TextDecoder("utf-8").decode(Uint8Array.from(bin, c => c.charCodeAt(0))); }
  catch (e) { return ""; }
}
function decodeWords(v) {  // =?utf-8?B?...?= header words
  return v.replace(/=\?([^?]+)\?([BQ])\?([^?]*)\?=/gi, (_, cs, enc, txt) =>
    enc.toUpperCase() === "B" ? decodeB64(txt) : decodeQP(txt.replace(/_/g, " ")));
}
function splitHeaders(raw) {
  const idx = raw.search(/\r?\n\r?\n/);
  const head = idx < 0 ? raw : raw.slice(0, idx), body = idx < 0 ? "" : raw.slice(idx).replace(/^\r?\n\r?\n/, "");
  const h = {};
  head.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach(line => {
    const m = /^([\w-]+):\s*(.*)$/.exec(line);
    if (m) { const k = m[1].toLowerCase(); (h[k] = h[k] || []).push(decodeWords(m[2])); }
  });
  return {h, body};
}
function partText(raw) {
  const {h, body} = splitHeaders(raw);
  const ct = (h["content-type"] || ["text/plain"])[0], enc = ((h["content-transfer-encoding"] || [""])[0] || "").toLowerCase();
  const bm = /boundary="?([^";]+)"?/i.exec(ct);
  if (/^multipart\//i.test(ct) && bm) {
    const parts = body.split("--" + bm[1]).slice(1).filter(p => !p.startsWith("--"));
    let html = null;
    for (const p of parts) {
      const r = partText(p.replace(/^\r?\n/, ""));
      if (r.type === "plain" && r.text.trim()) return r;
      if (r.type === "html" && !html) html = r;
    }
    return html || {type: "plain", text: ""};
  }
  let text = enc === "base64" ? decodeB64(body) : enc === "quoted-printable" ? decodeQP(body) : body;
  if (/text\/html/i.test(ct)) {
    const doc = new DOMParser().parseFromString(text, "text/html");
    doc.querySelectorAll("script,style").forEach(n => n.remove());
    doc.querySelectorAll("br,p,div,tr,li").forEach(n => n.append("\n"));
    return {type: "html", text: doc.body ? doc.body.textContent : ""};
  }
  return {type: /text\/plain/i.test(ct) ? "plain" : "other", text};
}
function parseEml(raw) {
  const {h} = splitHeaders(raw);
  const body = partText(raw).text.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  const auth = (h["authentication-results"] || h["arc-authentication-results"] || []).join(" ; ");
  const headers = {};
  if (h["reply-to"]) headers.reply_to = h["reply-to"][0];
  if (auth) headers.auth = auth.slice(0, 2000);
  return {mode: "email", sender: ((h.from || [""])[0]).slice(0, 200), subject: ((h.subject || [""])[0]).slice(0, 300),
          body: body.slice(0, 5000), headers: Object.keys(headers).length ? headers : null};
}
function looksLikeEml(raw) {
  const head = raw.slice(0, 4000);
  return /^[\w-]+:\s/.test(head.trimStart()) && /^from:\s/im.test(head) && /^(?:subject|received|mime-version|message-id|date):\s/im.test(head);
}
function parsePlain(text) {
  const p = parseMailPrint(text);
  if (p) return p;
  const lines = String(text).split(/\r?\n/);
  let sender = "", subject = ""; const keep = [];
  for (const l of lines) {
    const f = /^\s*from:\s*(.+)$/i.exec(l), s = /^\s*subject:\s*(.+)$/i.exec(l);
    if (f && !sender) sender = f[1].trim(); else if (s && !subject) subject = s[1].trim(); else keep.push(l);
  }
  return {mode: sender.includes("@") ? "email" : "sms", sender, subject, body: keep.join("\n").replace(/[ \t]+/g, " ").trim().slice(0, 5000), headers: null};
}
let pdfjsPromise = null;
const PDFJS = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js";
function loadPdfJs() {
  if (root.pdfjsLib) return Promise.resolve(root.pdfjsLib);
  if (!pdfjsPromise) pdfjsPromise = new Promise((res, rej) => {
    const s = document.createElement("script"); s.src = PDFJS; s.async = true;
    s.onload = () => { if (!root.pdfjsLib) return rej(new Error("PDF reader didn't load"));
      root.pdfjsLib.GlobalWorkerOptions.workerSrc = PDFJS.replace("pdf.min.js", "pdf.worker.min.js"); res(root.pdfjsLib); };
    s.onerror = () => { pdfjsPromise = null; rej(new Error("Couldn't load the PDF reader. Check your connection and try again.")); };
    document.head.appendChild(s);
  });
  return pdfjsPromise;
}
async function pdfText(buf) {
  const lib = await loadPdfJs();
  const doc = await lib.getDocument({data: new Uint8Array(buf), isEvalSupported: false}).promise;
  const out = [];
  for (let p = 1; p <= Math.min(doc.numPages, 10); p++) {
    const tc = await (await doc.getPage(p)).getTextContent();
    let line = "", lastY = null;
    for (const it of tc.items) {
      const y = it.transform ? Math.round(it.transform[5]) : lastY;
      if (lastY !== null && y !== lastY) { out.push(line); line = ""; }
      line += (line && !line.endsWith(" ") && it.str && !it.str.startsWith(" ") ? " " : "") + it.str;
      lastY = y;
      if (it.hasEOL) { out.push(line); line = ""; lastY = null; }
    }
    if (line) out.push(line);
  }
  return out.join("\n");
}
/* ── Screenshots without Claude: Tesseract.js reads them on this device (same parsing as the server's offline reader) ── */
const TIME = "\\d{1,2}:\\d{2}(?:\\s?[ap]\\.?m\\.?)?";
const UI_NOISE = new RegExp(`^(?:${TIME}|(?:today|yesterday|now|(?:mon|tue|wed|thu|fri|sat|sun)\\w*,?)(?:\\s.*?${TIME})?|` +
  "text message(?:\\s*[•·-]\\s*.*)?|imessage|sms|mms|rcs|chat|delivered|read\\b.*|seen\\b.*|sent\\b.*|" +
  "reply|reply all|forward|archive|delete|inbox|details|\\W*)$", "i");
const SENDER_LINE = /^(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$|^\d{4,6}$|^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$/;
const MAIL_WARNING = /why is this message in spam|identified as spam|be careful with this message|suspected spam|this message (?:seems|looks) (?:dangerous|suspicious)|report not spam|report junk|similar to messages that were/i;
const MAIL_CHROME = /^(?:\S{1,2}\s+)?(?:standard encryption.*|view security details|to me\b.*|to\s+\S+@\S+|date\s+.*\d{4}.*|report not spam.*|reply all|get the .* app)$/i;
const SADDR = "([\\w.+|-]+@[\\w-]+(?:\\.[\\w-]+)+)";
const cleanAddr = a => a.replace(/\|/g, "l").replace(/^[.,;:]+|[.,;:]+$/g, "").toLowerCase();
function junk(ln) {
  const words = (ln.match(/[A-Za-zÀ-ɏ؀-ۿऀ-ॿ]{3,}/g) || []).length;
  if (/^\d{1,2}:\d{2}\b/.test(ln) && words < 2) return true;  // the phone's status bar
  return words < 2 && !/@|https?:\/\/|\.\w{2,}\/|\d{3}/.test(ln);
}
function joinWrapped(lines) {
  let out = "";
  for (const ln of lines) out = !out ? ln : out.endsWith("-") && /^[A-Za-z0-9]/.test(ln) ? out + ln : out + " " + ln;
  return out.replace(/[ \t]+/g, " ").trim();
}
function parseScreen(text) {
  const lines = String(text || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  let sender = "", subject = "", replyTo = "", appWarning = "", mode = "sms", keep = [];
  const gRe = new RegExp("^from:?\\s+(.*?)\\s*[-•·]\\s*" + SADDR + "\\s*$", "i"), rtRe = new RegExp("^reply-?to:?\\s+(?:.*?[-•·]\\s*)?" + SADDR + "\\s*$", "i");
  lines.forEach((ln, i) => {
    if (MAIL_WARNING.test(ln)) { appWarning = appWarning || "The mail app put this message in Spam"; return; }
    if (MAIL_CHROME.test(ln)) return;
    const m = /^from:\s*(.+)$/i.exec(ln), s = /^subject:\s*(.+)$/i.exec(ln), g = gRe.exec(ln), rt = rtRe.exec(ln);
    if (rt) { replyTo = cleanAddr(rt[1]); mode = "email"; }
    else if (g && !sender) {
      const name = g[1].replace(/^[^A-Za-z0-9]+/, "").trim();
      sender = name ? `${name} <${cleanAddr(g[2])}>` : cleanAddr(g[2]); mode = "email";
      let row = -1;
      for (let j = keep.length - 1; j >= 0; j--) if (/\b(?:yesterday|today|\d{1,2}:\d{2}|\d+ ?(?:min|h|d)\b|(?:mon|tue|wed|thu|fri|sat|sun)\w*)/i.test(keep[j])) { row = j; break; }
      if (row >= 0 && !subject) {
        const head = keep.slice(0, row).filter(x => !junk(x)).map(x => x.replace(/\s+\S{1,2}$/, ""));
        subject = head.join(" ").replace(/\s*\|?\s*(?:spam|inbox|promotions|updates)\s*$/i, "").trim();
        keep = [];
      }
    } else if (m && !sender) { sender = m[1].trim(); mode = "email"; if (!subject && keep.length) subject = keep.pop(); }
    else if (s && !subject) { subject = s[1].trim(); mode = "email"; }
    else if (!sender && i < 6 && SENDER_LINE.test(ln.includes("@") ? ln.replace(/ /g, "") : ln)) { sender = ln; mode = ln.includes("@") ? "email" : "sms"; }
    else if (UI_NOISE.test(ln) || /^(?:to|cc):\s/i.test(ln)) return;
    else keep.push(ln);
  });
  const body = joinWrapped(keep.filter(x => !junk(x))).slice(0, 5000);
  return {mode, sender, subject, body, app: "", app_warning: appWarning, headers: replyTo ? {reply_to: replyTo} : null,
          readable: !!body, notes: body ? "" : "No message text found in the image."};
}
// The reader's files are published next to the page (ocr/…): the page can fetch its own files, but nothing else.
const OCR_BASE = () => new URL("ocr/", location.href).href;
const TJS_CDN = "https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js";
const OCR_LANGS = {es: "spa", ur: "urd", hi: "hin"};
let tjsPromise = null; const workers = {};
const say = text => { try { document.dispatchEvent(new CustomEvent("pg-progress", {detail: text})); } catch (e) {} };
function addScript(src) {
  return new Promise((res, rej) => { const s = document.createElement("script"); s.src = src; s.async = true; s.onload = res; s.onerror = rej; document.head.appendChild(s); });
}
function loadTesseract() {
  if (root.Tesseract) return Promise.resolve(root.Tesseract);
  if (!tjsPromise) tjsPromise = addScript(OCR_BASE() + "tesseract.min.js").catch(() => addScript(TJS_CDN))
    .then(() => { if (!root.Tesseract) throw new Error("The on-device reader didn't load"); return root.Tesseract; })
    .catch(e => { tjsPromise = null; throw new Error("Couldn't load the on-device reader. Check your connection, or paste the text instead."); });
  return tjsPromise;
}
// Gives up when the reader makes no progress for `idleMs` (a blocked download or an engine that can't start reports nothing).
let lastBeat = 0;
const beat = () => { lastBeat = Date.now(); };
function watchdog(p, idleMs, msg) {
  beat();
  return new Promise((res, rej) => {
    const iv = setInterval(() => { if (Date.now() - lastBeat > idleMs) { clearInterval(iv); rej(new Error(msg)); } }, 1000);
    p.then(v => { clearInterval(iv); res(v); }, e => { clearInterval(iv); rej(e); });
  });
}
const STATUS = {"loading tesseract core": "Starting the reader…", "initializing tesseract": "Starting the reader…",
                "loading language traineddata": "Downloading the reader (first time only)… {p}%",
                "initializing api": "Starting the reader…", "recognizing text": "Reading the text… {p}%"};
async function screenCanvas(blob) {
  const bmp = await createImageBitmap(blob);
  const k = bmp.width < 1200 ? 2 : Math.min(1, 2400 / Math.max(bmp.width, bmp.height));
  const c = document.createElement("canvas"); c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
  const g = c.getContext("2d", {willReadFrequently: true}); g.drawImage(bmp, 0, 0, c.width, c.height);
  const d = g.getImageData(0, 0, c.width, c.height), px = d.data;
  let sum = 0; for (let i = 0; i < px.length; i += 4) { const y = 0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2]; px[i] = px[i + 1] = px[i + 2] = y; sum += y; }
  if (sum / (px.length / 4) < 128) for (let i = 0; i < px.length; i += 4) px[i] = px[i + 1] = px[i + 2] = 255 - px[i];  // dark mode → dark text on light
  g.putImageData(d, 0, 0);
  return c;
}
async function startWorker(langs) {
  const T = await loadTesseract(), base = OCR_BASE();
  say({key: "Starting the reader…"});
  return T.createWorker(langs.join("+"), 1, {workerPath: base + "worker.min.js", corePath: base, langPath: base, workerBlobURL: false,
    logger: m => { beat(); const k = m && STATUS[m.status]; if (k) say({key: k, vars: {p: Math.round((m.progress || 0) * 100)}}); },
    errorHandler: () => {}});
}
async function ocrImage(blob, uiLang) {
  const langs = ["eng"].concat(OCR_LANGS[uiLang] ? [OCR_LANGS[uiLang]] : []), key = langs.join("+");
  if (!workers[key]) workers[key] = watchdog(startWorker(langs), 30000,
    "The on-device reader took too long to start. Check your connection and try again, or paste the text instead.")
    .catch(e => { delete workers[key]; throw e; });
  let worker;
  try { worker = await workers[key]; }
  catch (e) { throw new Error(/took too long|Couldn't load/.test(e.message) ? e.message : "Couldn't start the on-device reader here. Open PhishGuard in the Claude app, or paste the text instead."); }
  const {data} = await watchdog(worker.recognize(await screenCanvas(blob)), 30000, "Reading the screenshot took too long. Try a smaller screenshot, or paste the text instead.");
  return parseScreen(data.text || "");
}
root.FileText = {parseMailPrint, parseEml, looksLikeEml, parsePlain, pdfText, parseScreen, ocrImage};
})(typeof window !== "undefined" ? window : globalThis);
