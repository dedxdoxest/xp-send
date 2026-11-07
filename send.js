// ХП — «Безопасная передача», страница расшифровки (формат 1, см. tools/send_vectors.py).
// Всё происходит в браузере: ключ находится во фрагменте ссылки (после «#»), который браузер
// не отправляет на сервер. Страница не загружает ничего стороннего (см. CSP в index.html).

const TAG = new TextEncoder().encode("XP-SEND-1");

function unb64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export class SendError extends Error {
  constructor(code) { super(code); this.code = code; }
}

/** Parses "1.<secret>.<blob>" (with or without the leading "#"). */
export function parse(fragment) {
  const parts = fragment.replace(/^#/, "").split(".");
  if (parts.length !== 3 || parts[0] !== "1") throw new SendError("FORMAT");
  let secret, blob;
  try { secret = unb64(parts[1]); blob = unb64(parts[2]); } catch { throw new SendError("FORMAT"); }
  if (secret.length !== 32 || blob.length < 1 + 12 + 16) throw new SendError("FORMAT");
  const flags = blob[0];
  if (flags & ~1) throw new SendError("FORMAT");
  const withPassword = (flags & 1) === 1;
  const headerLen = withPassword ? 1 + 16 + 4 : 1;
  if (blob.length < headerLen + 12 + 16) throw new SendError("FORMAT");
  const header = blob.slice(0, headerLen);
  const salt = withPassword ? blob.slice(1, 17) : null;
  const iterations = withPassword ? new DataView(blob.buffer, blob.byteOffset + 17, 4).getUint32(0) : 0;
  if (withPassword && (iterations < 1000 || iterations > 10_000_000)) throw new SendError("FORMAT");
  return { secret, header, salt, iterations, withPassword,
    iv: blob.slice(headerLen, headerLen + 12), ciphertext: blob.slice(headerLen + 12) };
}

/** Decrypts a fragment. Throws SendError NEEDS_PASSWORD, WRONG (key or password), EXPIRED, FORMAT. */
export async function open(fragment, password, now = Date.now()) {
  const p = parse(fragment);
  const subtle = globalThis.crypto.subtle;
  let material = concat(TAG, p.secret);
  if (p.withPassword) {
    if (!password) throw new SendError("NEEDS_PASSWORD");
    const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: p.salt, iterations: p.iterations }, base, 256));
    material = concat(material, bits);
  }
  const keyBytes = new Uint8Array(await subtle.digest("SHA-256", material));
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  let plain;
  try {
    plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: p.iv, additionalData: concat(TAG, p.header) }, key, p.ciphertext));
  } catch { throw new SendError("WRONG"); }
  let m;
  try { m = JSON.parse(new TextDecoder().decode(plain)); } catch { throw new SendError("FORMAT"); }
  if (m.v !== 1 || !Array.isArray(m.fields)) throw new SendError("FORMAT");
  if (typeof m.exp === "number" && now > m.exp) throw new SendError("EXPIRED");
  return m;
}

// ------------------------------------------------------------------ page UI ---------
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
const MESSAGES = {
  FORMAT: "Ссылка повреждена или неполная. Попросите отправителя прислать её заново.",
  WRONG: "Неверный пароль или ссылка повреждена.",
  EXPIRED: "Срок действия ссылки истёк. Попросите отправителя создать новую.",
};

function show(m) {
  const root = document.getElementById("content");
  root.replaceChildren();
  root.append(el("h2", null, m.title || "Сообщение"));
  for (const f of m.fields) {
    const row = el("div", "field");
    row.append(el("div", "label", f.n));
    const value = el("div", f.s ? "value secret" : "value", f.s ? "•".repeat(Math.min(f.v.length, 16)) : f.v);
    row.append(value);
    const actions = el("div", "actions");
    if (f.s) {
      const reveal = el("button", "link", "Показать");
      reveal.onclick = () => { const shown = value.classList.toggle("shown"); value.textContent = shown ? f.v : "•".repeat(Math.min(f.v.length, 16)); reveal.textContent = shown ? "Скрыть" : "Показать"; };
      actions.append(reveal);
    }
    const copy = el("button", "link", "Копировать");
    copy.onclick = async () => { try { await navigator.clipboard.writeText(f.v); copy.textContent = "Скопировано"; } catch { copy.textContent = "Не удалось"; } };
    actions.append(copy);
    row.append(actions);
    root.append(row);
  }
  if (m.note) { const n = el("div", "field"); n.append(el("div", "label", "Заметка"), el("div", "value note", m.note)); root.append(n); }
  if (typeof m.exp === "number") root.append(el("p", "hint", "Ссылка действует до " + new Date(m.exp).toLocaleString("ru-RU") + "."));
}

async function main() {
  const fragment = location.hash;
  // Out of the address bar and history: the key is not left on screen or in "back".
  if (fragment) history.replaceState(null, "", location.pathname + location.search);
  const status = document.getElementById("status");
  const form = document.getElementById("password-form");
  if (!fragment) { status.textContent = "Эта страница открывает ссылки «Безопасной передачи» из ХП. В ссылке нет данных."; return; }
  const attempt = async (password) => {
    status.textContent = "Расшифровываю…";
    try { show(await open(fragment, password)); status.textContent = ""; form.hidden = true; }
    catch (e) {
      if (e.code === "NEEDS_PASSWORD") { status.textContent = "Ссылка защищена паролем. Отправитель должен был передать его отдельно."; form.hidden = false; return; }
      status.textContent = MESSAGES[e.code] || "Не удалось открыть ссылку.";
      if (e.code === "WRONG" && !form.hidden) return;
    }
  };
  form.onsubmit = (ev) => { ev.preventDefault(); attempt(document.getElementById("password").value); };
  await attempt(null);
}

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", main);
