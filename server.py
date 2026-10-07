#!/usr/bin/env python3
"""
TopGift — безпечний бекенд (лише стандартна бібліотека Python 3.10+).

Що захищає:
  * кожен запит від Mini App перевіряється за підписом Telegram initData (HMAC-SHA256);
  * ціна / назва / тип товару визначає СЕРВЕР, клієнт може лише вибрати з білого списку;
  * зірки зараховуються ТІЛЬКИ після успішного платежу, який Telegram підтвердив
    у вебхуку (successful_payment), і лише один раз (унікальний charge_id);
  * приз у кейсі за справжні зірки розігрує сервер (secrets), а не браузер;
  * вебхук приймає тільки запити з секретним заголовком Telegram;
  * ліміт запитів, ліміт розміру тіла, суворий CORS, заголовки безпеки,
    параметризовані SQL-запити, транзакції.

Змінні середовища: BOT_TOKEN, WEBHOOK_SECRET (A-Za-z0-9_-, 32+ символи),
ALLOWED_ORIGIN (напр. https://you.github.io), DB_PATH, PORT.
"""
import base64
import decimal
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "")
DB_PATH = os.environ.get("DB_PATH", "topgift.db")
PORT = int(os.environ.get("PORT", "8080"))
TON_RECEIVER = os.environ.get("TON_RECEIVER", "")          # ваш TON-гаманець для депозитів
TONCENTER_URL = os.environ.get("TONCENTER_URL", "https://toncenter.com/api/v2")
TONCENTER_KEY = os.environ.get("TONCENTER_KEY", "")        # необов'язково, але збільшує ліміти
TON_MIN_NANO, TON_MAX_NANO = 100_000_000, 100_000_000_000  # 0.1 … 100 TON
DEPOSIT_TTL = 3600                                         # заявка діє 1 годину

INIT_DATA_MAX_AGE = 3600          # сек. Старіші підписи відхиляємо (захист від replay)
MAX_BODY = 4096                   # байт
RATE_LIMIT = (30, 60)             # 30 запитів / 60 сек. на користувача
IP_RATE_LIMIT = (120, 60)

DONATE_AMOUNTS = {25, 50, 100, 250, 500, 1000}

# Кейси за справжні Stars: призи — ТІЛЬКИ зірки, кратні ціні кейсу, а шанси підібрані
# так, щоб повернення гравцям (RTP) дорівнювало TARGET_RTP. Змінюєш TARGET_RTP — таблиці
# перераховуються самі. Ці ж шанси треба показувати гравцям (вимога магазинів/Telegram).
TARGET_RTP = 0.75
_TIERS = [  # (множник до ціни, шанс %, рідкість); решта шансу ділиться між двома нижніми
    (20, 0.1, "legendary"), (5, 1.5, "epic"), (2, 10.0, "rare")]


def _zirok(n):
    d, t = n % 10, n % 100
    return "зірка" if d == 1 and t != 11 else "зірки" if 2 <= d <= 4 and not 12 <= t <= 14 else "зірок"


def build_real_case(cost, target=TARGET_RTP):
    amt = lambda m: max(1, round(cost * m))
    fixed = [(amt(m), p, r) for m, p, r in _TIERS]
    low_a, mid_a = amt(0.4), amt(1)                     # «втішний» і «повернення ціни»
    rest = 100.0 - sum(p for _, p, _ in fixed)
    ev_fixed = sum(a * p / 100 for a, p, _ in fixed)
    # p_mid + p_low = rest ; ev = ev_fixed + (p_mid*mid + p_low*low)/100 = target*cost
    p_mid = (target * cost - ev_fixed - rest / 100 * low_a) / ((mid_a - low_a) / 100)
    p_mid = min(max(p_mid, 0.0), rest)
    tiers = [(low_a, rest - p_mid, "common"), (mid_a, p_mid, "common")] + fixed[::-1]
    return {"cost": cost, "prizes": [
        {"kind": "stars", "name": f"{a} {_zirok(a)}", "emoji": "⭐", "rarity": r,
         "weight": round(p, 4), "amount": a} for a, p, r in tiers if p > 0]}


def rtp(case):
    w = sum(p["weight"] for p in case["prizes"])
    return sum(p["weight"] * p["amount"] for p in case["prizes"]) / w / case["cost"]


REAL_CASES = {f"realstars{c}": build_real_case(c) for c in (3, 5, 10, 25)}

_rng = secrets.SystemRandom()
_db_lock = threading.Lock()


# ----------------------------- БАЗА ДАНИХ -----------------------------

def db():
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with db() as c:
        try:
            c.execute("ALTER TABLE payments ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # колонка вже є / таблиці ще немає
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, stars INTEGER NOT NULL DEFAULT 0 CHECK(stars >= 0),
            ton_nano INTEGER NOT NULL DEFAULT 0 CHECK(ton_nano >= 0), created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS invoices(
            nonce TEXT PRIMARY KEY, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
            kind TEXT NOT NULL, case_key TEXT, used INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS payments(
            charge_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
            kind TEXT NOT NULL, created INTEGER NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS ton_deposits(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, comment TEXT NOT NULL UNIQUE,
            amount_nano INTEGER NOT NULL, created INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            tx_hash TEXT UNIQUE, received_nano INTEGER, delivered INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS case_results(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, case_key TEXT NOT NULL,
            prize TEXT NOT NULL, claimed INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
        """)


# ----------------------------- TELEGRAM -----------------------------

def validate_init_data(init_data, bot_token=None, max_age=INIT_DATA_MAX_AGE, now=None):
    """Повертає dict користувача або None, якщо підпис хибний / прострочений."""
    bot_token = bot_token or BOT_TOKEN
    if not init_data or len(init_data) > 4096 or not bot_token:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
    except ValueError:
        return None
    received_hash = pairs.pop("hash", "")
    pairs.pop("signature", None)  # у перевірці HMAC не бере участі
    check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, received_hash):
        return None
    try:
        auth_date = int(pairs.get("auth_date", "0"))
        user = json.loads(pairs.get("user", "null"))
        uid = int(user["id"])
    except (ValueError, KeyError, TypeError):
        return None
    if (now or time.time()) - auth_date > max_age or auth_date > (now or time.time()) + 60:
        return None
    return {"id": uid, "first_name": str(user.get("first_name", ""))[:64]}


def tg_call(method, payload):
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# ----------------------------- ЛІМІТИ -----------------------------

_hits = {}
_hits_lock = threading.Lock()


def rate_ok(key, limit):
    max_hits, window = limit
    now = time.time()
    with _hits_lock:
        q = [t for t in _hits.get(key, []) if now - t < window]
        if len(q) >= max_hits:
            _hits[key] = q
            return False
        q.append(now)
        _hits[key] = q
        if len(_hits) > 50000:  # захист пам'яті
            _hits.clear()
    return True


# ----------------------------- БІЗНЕС-ЛОГІКА -----------------------------

def ensure_user(c, uid):
    c.execute("INSERT OR IGNORE INTO users(id, created) VALUES(?, ?)", (uid, int(time.time())))


def pick_weighted(prizes):
    total = sum(p["weight"] for p in prizes)
    roll = _rng.uniform(0, total)
    acc = 0.0
    for p in prizes:
        acc += p["weight"]
        if roll <= acc:
            return p
    return prizes[-1]


def create_invoice(user, body):
    kind = body.get("kind")
    if kind == "donate":
        amount = body.get("amount")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount not in DONATE_AMOUNTS:
            return 400, {"error": "bad_amount"}
        title, desc, case_key = f"Донат {amount} ⭐", "Підтримка проєкту TopGift", None
    elif kind == "case":
        case_key = body.get("caseKey")
        cfg = REAL_CASES.get(case_key) if isinstance(case_key, str) else None
        if not cfg:
            return 400, {"error": "bad_case"}
        amount = cfg["cost"]
        title, desc = f"Кейс за {amount} ⭐", "Відкриття кейсу TopGift"
    else:
        return 400, {"error": "bad_kind"}

    nonce = secrets.token_urlsafe(24)
    with _db_lock, db() as c:
        ensure_user(c, user["id"])
        c.execute("INSERT INTO invoices(nonce,user_id,amount,kind,case_key,created) VALUES(?,?,?,?,?,?)",
                  (nonce, user["id"], amount, kind, case_key, int(time.time())))
    try:
        res = tg_call("createInvoiceLink", {
            "title": title, "description": desc, "payload": nonce,
            "provider_token": "", "currency": "XTR",
            "prices": [{"label": title, "amount": amount}]})
    except Exception as e:
        print("TG ERR createInvoiceLink:", type(e).__name__, getattr(e, "code", ""))
        return 502, {"error": "telegram_error"}
    if not res.get("ok"):
        return 502, {"error": "telegram_error"}
    return 200, {"invoiceLink": res["result"]}


def handle_pre_checkout(q):
    with db() as c:
        inv = c.execute("SELECT * FROM invoices WHERE nonce=?", (q.get("invoice_payload", ""),)).fetchone()
    ok = bool(inv and not inv["used"] and inv["user_id"] == q["from"]["id"]
              and inv["amount"] == q.get("total_amount") and q.get("currency") == "XTR"
              and time.time() - inv["created"] < 86400)
    out = {"pre_checkout_query_id": q["id"], "ok": ok}
    if not ok:
        out["error_message"] = "Рахунок недійсний або вже використаний"
    tg_call("answerPreCheckoutQuery", out)


def handle_successful_payment(msg):
    sp = msg["successful_payment"]
    charge_id = str(sp.get("telegram_payment_charge_id", ""))
    uid = msg["from"]["id"]
    with _db_lock, db() as c:
        c.execute("BEGIN IMMEDIATE")
        try:
            inv = c.execute("SELECT * FROM invoices WHERE nonce=?", (sp.get("invoice_payload", ""),)).fetchone()
            valid = (charge_id and inv and not inv["used"] and inv["user_id"] == uid
                     and sp.get("currency") == "XTR" and sp.get("total_amount") == inv["amount"])
            if not valid:
                c.execute("ROLLBACK")
                return False
            try:  # UNIQUE(charge_id) — друге зарахування того ж платежу неможливе
                c.execute("INSERT INTO payments(charge_id,user_id,amount,kind,created) VALUES(?,?,?,?,?)",
                          (charge_id, uid, inv["amount"], inv["kind"], int(time.time())))
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")
                return False
            c.execute("UPDATE invoices SET used=1 WHERE nonce=?", (inv["nonce"],))
            ensure_user(c, uid)
            if inv["kind"] == "donate":
                c.execute("UPDATE users SET stars=stars+? WHERE id=?", (inv["amount"], uid))
            else:
                prize = pick_weighted(REAL_CASES[inv["case_key"]]["prizes"])
                if prize["kind"] == "stars":
                    c.execute("UPDATE users SET stars=stars+? WHERE id=?", (prize["amount"], uid))
                else:
                    c.execute("UPDATE users SET ton_nano=ton_nano+? WHERE id=?",
                              (round(prize["amount"] * 1e9), uid))
                c.execute("INSERT INTO case_results(user_id,case_key,prize,created) VALUES(?,?,?,?)",
                          (uid, inv["case_key"], json.dumps(prize, ensure_ascii=False), int(time.time())))
            c.execute("COMMIT")
            return True
        except Exception:
            c.execute("ROLLBACK")
            raise


def get_state(user, q=None):
    with db() as c:
        ensure_user(c, user["id"])
        u = c.execute("SELECT stars, ton_nano FROM users WHERE id=?", (user["id"],)).fetchone()
    return 200, {"stars": u["stars"], "ton": u["ton_nano"] / 1e9}


def claim_donations(user, q=None):
    """Сума донатів, які оплачено, але ще не показано в застосунку (віддається один раз)."""
    with _db_lock, db() as c:
        c.execute("BEGIN IMMEDIATE")
        total = c.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE user_id=? AND kind='donate' AND delivered=0",
                          (user["id"],)).fetchone()[0]
        c.execute("UPDATE payments SET delivered=1 WHERE user_id=? AND kind='donate' AND delivered=0", (user["id"],))
        c.execute("COMMIT")
    return 200, {"stars": total}


def claim_case(user, q=None):
    """Віддає найстаріший ще не показаний результат кейсу (або pending=true)."""
    with _db_lock, db() as c:
        row = c.execute("SELECT id, prize FROM case_results WHERE user_id=? AND claimed=0 ORDER BY id LIMIT 1",
                        (user["id"],)).fetchone()
        if not row:
            return 200, {"pending": True}
        c.execute("UPDATE case_results SET claimed=1 WHERE id=?", (row["id"],))
    prize = json.loads(row["prize"])
    prize.pop("weight", None)
    return 200, {"prize": prize}


# ----------------------------- ПОПОВНЕННЯ TON -----------------------------

def comment_payload_b64(text):
    """BOC-клітинка з текстовим коментарем (opcode 0 + UTF-8) для TonConnect."""
    data = b"\x00\x00\x00\x00" + text.encode()
    assert len(data) <= 127
    cell = bytes([0, len(data) * 2]) + data
    boc = b"\xb5\xee\x9c\x72" + bytes([0x01, 0x01, 0x01, 0x01, 0x00, len(cell), 0x00]) + cell
    return base64.b64encode(boc).decode()


def valid_ton_address(addr):
    """Перевіряє user-friendly адресу (EQ…/UQ…): довжина, контрольна сума CRC16, воркчейн."""
    try:
        raw = base64.urlsafe_b64decode(addr + "=" * (-len(addr) % 4))
    except Exception:
        return False
    if len(addr) != 48 or len(raw) != 36 or raw[0] not in (0x11, 0x51, 0x91, 0xD1) or raw[1] not in (0, 0xFF):
        return False
    crc = 0
    for b in raw[:-2]:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc.to_bytes(2, "big") == raw[-2:]


def parse_ton_amount(v):
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        return None
    try:
        d = decimal.Decimal(str(v).replace(",", ".").strip())
    except decimal.InvalidOperation:
        return None
    if not d.is_finite() or d != d.quantize(decimal.Decimal("0.000000001")):
        return None
    nano = int(d * 10**9)
    return nano if TON_MIN_NANO <= nano <= TON_MAX_NANO else None


def create_deposit_intent(user, body):
    if not TON_RECEIVER:
        return 503, {"error": "deposits_disabled"}
    nano = parse_ton_amount(body.get("amount"))
    if nano is None:
        return 400, {"error": "bad_amount"}
    now = int(time.time())
    comment = f"tg{user['id']}-{secrets.token_hex(6)}"
    with _db_lock, db() as c:
        ensure_user(c, user["id"])
        n = c.execute("SELECT COUNT(*) FROM ton_deposits WHERE user_id=? AND status='pending' AND created>?",
                      (user["id"], now - DEPOSIT_TTL)).fetchone()[0]
        if n >= 5:
            return 429, {"error": "too_many_pending"}
        cur = c.execute("INSERT INTO ton_deposits(user_id,comment,amount_nano,created) VALUES(?,?,?,?)",
                        (user["id"], comment, nano, now))
    return 200, {"id": cur.lastrowid, "address": TON_RECEIVER, "amountNano": nano,
                 "payload": comment_payload_b64(comment), "expiresIn": DEPOSIT_TTL}


def fetch_transactions():
    req = urllib.request.Request(
        f"{TONCENTER_URL}/getTransactions?" + urlencode({"address": TON_RECEIVER, "limit": 50}),
        headers={"X-API-Key": TONCENTER_KEY} if TONCENTER_KEY else {})
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.loads(r.read())
    return d.get("result", []) if d.get("ok") else []


_scan_lock = threading.Lock()
_last_scan = [0.0]


def scan_deposits(txs=None, min_interval=3.0):
    """Шукає в останніх транзакціях гаманця вхідні перекази з нашим коментарем і зараховує їх."""
    with _scan_lock:
        if txs is None:
            if time.time() - _last_scan[0] < min_interval:
                return 0
            _last_scan[0] = time.time()
            txs = fetch_transactions()
        credited = 0
        with _db_lock, db() as c:
            pend = {r["comment"]: r for r in c.execute("SELECT * FROM ton_deposits WHERE status='pending'")}
        for tx in txs:
            m = tx.get("in_msg") or {}
            dep = pend.get(m.get("message")) if isinstance(m.get("message"), str) else None
            if not dep or not m.get("source"):
                continue                                   # не наш коментар / не внутрішнє повідомлення
            try:
                value, utime = int(m.get("value", 0)), int(tx.get("utime", 0))
                h = str(tx["transaction_id"]["hash"])
            except (ValueError, KeyError, TypeError):
                continue
            if value < dep["amount_nano"] or not (dep["created"] - 60 <= utime <= dep["created"] + DEPOSIT_TTL):
                continue
            with _db_lock, db() as c:
                c.execute("BEGIN IMMEDIATE")
                try:
                    r = c.execute("UPDATE ton_deposits SET status='confirmed', tx_hash=?, received_nano=? "
                                  "WHERE id=? AND status='pending'", (h, value, dep["id"]))
                    if r.rowcount != 1:
                        c.execute("ROLLBACK")
                        continue
                    c.execute("UPDATE users SET ton_nano=ton_nano+? WHERE id=?", (value, dep["user_id"]))
                    c.execute("COMMIT")
                    credited += 1
                except sqlite3.IntegrityError:             # цей tx_hash уже використано
                    c.execute("ROLLBACK")
        return credited


def deposit_status(user, q):
    try:
        dep_id = int((q.get("id") or [""])[0])
    except ValueError:
        return 400, {"error": "bad_id"}
    with db() as c:
        row = c.execute("SELECT * FROM ton_deposits WHERE id=? AND user_id=?", (dep_id, user["id"])).fetchone()
    if not row:
        return 404, {"error": "not_found"}
    if row["status"] == "pending" and time.time() < row["created"] + DEPOSIT_TTL + 60:
        try:
            scan_deposits()
        except Exception as e:
            print("SCAN ERR", type(e).__name__)
        with db() as c:
            row = c.execute("SELECT * FROM ton_deposits WHERE id=?", (dep_id,)).fetchone()
    if row["status"] == "confirmed":
        with _db_lock, db() as c:                          # «видаємо» зарахування клієнту рівно один раз
            first = c.execute("UPDATE ton_deposits SET delivered=1 WHERE id=? AND delivered=0", (dep_id,)).rowcount == 1
        return 200, {"status": "confirmed", "ton": row["received_nano"] / 1e9, "credited": first}
    expired = time.time() > row["created"] + DEPOSIT_TTL + 60
    return 200, {"status": "expired" if expired else "pending"}


def _scan_loop():
    while True:
        time.sleep(15)
        try:
            scan_deposits(min_interval=0)
        except Exception as e:
            print("SCAN ERR", type(e).__name__)


# ----------------------------- HTTP -----------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "TopGift"
    sys_version = ""

    def log_message(self, fmt, *args):  # без query/заголовків у логах
        print(f"{self.address_string()} {self.command} {urlparse(self.path).path} -> {args[1] if len(args) > 1 else ''}")

    def _send(self, code, obj=None):
        data = json.dumps(obj or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        if ALLOWED_ORIGIN and self.headers.get("Origin") == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        if ALLOWED_ORIGIN and self.headers.get("Origin") == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "GET, POST")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Telegram-Init-Data")
            self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def _body(self, limit=MAX_BODY):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if n < 0 or n > limit:
            return None
        raw = self.rfile.read(n) if n else b"{}"
        try:
            obj = json.loads(raw or b"{}")
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None

    def _auth(self):
        if not rate_ok("ip:" + self.client_address[0], IP_RATE_LIMIT):
            self._send(429, {"error": "rate_limited"})
            return None
        user = validate_init_data(self.headers.get("X-Telegram-Init-Data", ""))
        if not user:
            self._send(401, {"error": "unauthorized"})
            return None
        if not rate_ok(f"u:{user['id']}", RATE_LIMIT):
            self._send(429, {"error": "rate_limited"})
            return None
        return user

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send(200, {"ok": True})
        routes = {"/api/state": get_state, "/api/claim-case": claim_case, "/api/claim-donations": claim_donations,
                  "/api/ton/deposit-status": deposit_status}
        fn = routes.get(path)
        if not fn:
            return self._send(404, {"error": "not_found"})
        user = self._auth()
        if user:
            try:
                self._send(*fn(user, parse_qs(urlparse(self.path).query)))
            except Exception as e:
                print("ERR", type(e).__name__)
                self._send(500, {"error": "server_error"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == f"/webhook/{WEBHOOK_SECRET}" and WEBHOOK_SECRET:
            return self._webhook()
        routes = {"/api/create-star-invoice": create_invoice, "/api/ton/deposit-intent": create_deposit_intent}
        if path not in routes:
            return self._send(404, {"error": "not_found"})
        user = self._auth()
        if not user:
            return
        body = self._body()
        if body is None:
            return self._send(400, {"error": "bad_request"})
        try:
            self._send(*routes[path](user, body))
        except Exception as e:
            print("ERR", type(e).__name__)
            self._send(500, {"error": "server_error"})

    def _webhook(self):
        token = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not hmac.compare_digest(token.encode(), WEBHOOK_SECRET.encode()):
            return self._send(403, {"error": "forbidden"})
        update = self._body(limit=65536)
        if update is None:
            return self._send(200, {})
        try:
            if "pre_checkout_query" in update:
                handle_pre_checkout(update["pre_checkout_query"])
            elif "successful_payment" in update.get("message", {}):
                handle_successful_payment(update["message"])
        except Exception as e:
            print("WEBHOOK ERR", type(e).__name__)
        self._send(200, {})  # завжди 200, щоб Telegram не повторював апдейт безкінечно


def main():
    if not BOT_TOKEN or len(WEBHOOK_SECRET) < 32 or not re.fullmatch(r"[A-Za-z0-9_-]+", WEBHOOK_SECRET):
        raise SystemExit("Задайте BOT_TOKEN та WEBHOOK_SECRET (32+ символів A-Za-z0-9_-)")
    if TON_RECEIVER and not valid_ton_address(TON_RECEIVER):
        raise SystemExit("TON_RECEIVER: некоректна адреса гаманця (перевірте, що скопійовано повністю)")
    init_db()
    if TON_RECEIVER:
        threading.Thread(target=_scan_loop, daemon=True).start()
    print(f"TopGift backend на :{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
