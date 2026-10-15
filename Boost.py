#!/usr/bin/env python3
"""
Registration by referral + launch codes (/codes page).

Wallets from Wallet.txt (seed,derivation path,private key,address,proxy[,session][,done]):
  MODE 1 - only wallets without done: bind a referral code from Ref.txt — each code in turn gets a random
    REGS_MIN..REGS_MAX wallets (POST /referral/bind/, as the site does after a
    ?ref= link) -> present a code from code.txt at the gate (POST /launch/gate/, captcha) ->
    daily check-in -> all quests (as login_wallets.py: Follow on X, Discord, ..., first crate) ->
    its own 3 codes (/launch/codes/, issued right away) go to code.txt -> ",done" is appended;
  MODE 2 - only wallets with done: daily check-in.
Session: the saved session (cookies, as in Accounts.txt) is reused - no SIWE login, no captcha;
if it expired, a fresh login is done (private key) and the new session is written into the line.
Dead proxy -> replaced by the next one from Proxy.txt (deleted from that file, never reused);
the new proxy is written into the wallet's line in Wallet.txt.
Every step checks the current state first, so a re-run skips what is already done.

GET /launch/codes/ -> {"admitted": bool, "codes": [{"index", "code", "redeemed"}]}.
- Only unspent codes are kept in code.txt, without duplicates: a code that is already in the file
  is skipped, a code saved earlier that is now spent is removed. A code taken for the gate is
  deleted from the file right away; it is put back if the site did not use it (captcha failed,
  dead proxy, locked out, ...) and dropped for good once it admitted a wallet or turned out dead.
"""

import os
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from eth_account import Account

import cap
import config
from login_wallets import (PROXY_FAIL_EXCEPTIONS, WALLET_FILE, daily_checkin, do_quests, internet_up,
                           write_lines)
from siwe_login import SiweSession

Account.enable_unaudited_hdwallet_features()

MODE = 2   # 1 — только регистрация кошельков без done (done не трогаем); 2 — только чек-ин у кошельков с done
THREADS = 10   # сколько кошельков обрабатывать одновременно
REGS_MIN = 50   # сколько новых кошельков привязать к одному реф-коду из Ref.txt: случайное число
REGS_MAX = 130   # от REGS_MIN до REGS_MAX для каждого кода (меньше, если кошельков без done не хватает)
CAPTCHA_RETRIES = 3   # сколько раз повторить вход, если сайт ответил CAPTCHA_FAILED

CODES_ENDPOINT = f"{config.API_BASE}/launch/codes/"
GATE_ENDPOINT = f"{config.API_BASE}/launch/gate/"
REFERRAL_BIND_ENDPOINT = f"{config.API_BASE}/referral/bind/"
REF_FILE = "Ref.txt"   # реф-коды, по одному на строку; новые кошельки привязываются к ним по кругу

# Gate errors: the code itself is unusable -> drop it and try the next one
CODE_DEAD_ERRORS = ("CODE_NOT_FOUND", "CODE_ALREADY_BOUND", "CODE_NOT_REDEEMABLE_HERE",
                    "CODE_MALFORMED", "VALIDATION_ERROR")
GATE_ATTEMPTS = 8          # codes / retries per wallet at the gate (CAPTCHA_FAILED counts too)
NOT_READY_DELAY = 10       # s, ACCOUNT_NOT_READY -> present the same code again after a pause


def fetch_codes(session):
    """Returns {"unspent": [...], "spent": [...], "admitted": bool} or {"error": code}."""
    r = session.get(CODES_ENDPOINT, headers={"Referer": f"{config.BASE_URL}/codes"},
                    timeout=config.API_TIMEOUT)
    try:
        body = r.json()
    except ValueError:
        return {"error": r.status_code}
    if r.status_code != 200 or not body.get("success"):
        err = (body.get("error") or {}).get("code", r.status_code)
        if err == "LAUNCH_PHASE_GATED":
            return {"unspent": [], "spent": [], "admitted": False, "gated": True}
        return {"error": err}
    d = body.get("data") or {}
    codes = sorted(d.get("codes") or [], key=lambda c: c.get("index") or 0)
    return {
        "unspent": [c["code"] for c in codes if c.get("code") and not c.get("redeemed")],
        "spent": [c["code"] for c in codes if c.get("code") and c.get("redeemed")],
        "admitted": bool(d.get("admitted")),
    }


class CodeStore:
    """code.txt: unspent launch codes, one per line; thread-safe, rewritten atomically.

    `held` counts codes taken by wallets that are still being registered: each of them may bring
    3 new codes, so take() waits for those instead of giving up on an empty file."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Condition()
        self.held = 0
        self.codes = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    c = line.strip()
                    if c and c not in self.codes:
                        self.codes.append(c)

    def sync(self, unspent, spent):
        """Adds unspent codes that are not in the file yet (codes already there are skipped),
        drops spent ones. Returns the number of codes added."""
        with self.lock:
            spent = set(spent)
            before = len(self.codes)
            self.codes = [c for c in self.codes if c not in spent]
            removed = before != len(self.codes)
            added = [c for c in unspent if c not in self.codes]
            self.codes.extend(added)
            if added or removed:
                self._flush()
            if added:
                self.lock.notify_all()
            return len(added)

    def take(self, own=0):
        """Removes the first code from the file and returns it (give_back() returns an unused one). If the file is empty,
        waits while other wallets (not counting `own` codes held by the caller) are still being
        registered; None once nobody can bring new codes."""
        with self.lock:
            while not self.codes and self.held - own > 0:
                self.lock.wait()
            if not self.codes:
                return None
            code = self.codes.pop(0)
            self.held += 1
            self._flush()
            return code

    def give_back(self, codes):
        """Puts taken codes the site did not use back at the head of the file (next to be taken)."""
        with self.lock:
            back = [c for c in dict.fromkeys(codes) if c not in self.codes]
            if back:
                self.codes = back + self.codes
                self._flush()
                self.lock.notify_all()

    def release(self, n):
        """The caller is done with `n` taken codes (its own new codes are already synced)."""
        if n:
            with self.lock:
                self.held -= n
                self.lock.notify_all()

    def count(self):
        with self.lock:
            return len(self.codes)

    def _flush(self):
        write_lines(self.path, self.codes)


def gate_code(code):
    """As the site's code field: upper case, no separators, no "LC" prefix, groups of 4 —
    "LC-E8X9-MGN7-S5ZT" -> "E8X9-MGN7-S5ZT"."""
    c = re.sub(r"[\s\-_.]+", "", code.upper())
    if len(c) != 12 and c.startswith("LC") and len(c) - 2 == 12:
        c = c[2:]
    return "-".join(c[i:i + 4] for i in range(0, len(c), 4))


def _api(session, method, url, body=None, referer="/", captcha=False):
    """Request with CSRF (+ captcha) like the frontend. Returns (ok, data | error code)."""
    headers = {"Referer": f"{config.BASE_URL}{referer}"}
    if method != "GET":
        headers["X-CSRFToken"] = session.cookies.get("csrftoken")
    if captcha:
        headers["X-Captcha-Token"] = cap.solve(session)
    r = session.request(method, url, json=body if method != "GET" else None,
                        headers=headers, timeout=config.API_TIMEOUT)
    try:
        b = r.json()
    except ValueError:
        return False, r.status_code
    if r.status_code not in (200, 201) or not b.get("success"):
        return False, (b.get("error") or {}).get("code", r.status_code)
    return True, b.get("data") or {}


class ProxyPool:
    """Spare proxies from Proxy.txt. A taken proxy is deleted from the file for good,
    so the same one is never handed out twice (also across runs)."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._pool = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            self._pool = []

    def take(self):
        with self.lock:
            if not self._pool:
                return None
            proxy = self._pool.pop(0)
            write_lines(self.path, self._pool)
            return proxy

    def remaining(self):
        with self.lock:
            return len(self._pool)


class KeySession(SiweSession):
    """SiweSession that signs with the private key from Wallet.txt instead of deriving from the seed."""

    def __init__(self, private_key, address, proxy):
        super().__init__(seed_phrase="", expected_address=address, proxy=proxy, verbose=False)
        self.private_key = private_key

    def _derive_account(self):
        self.account = Account.from_key(self.private_key)
        self.address = self.account.address
        if self.expected_address and self.address.lower() != self.expected_address.lower():
            raise RuntimeError(f"private key is for {self.address}, not {self.expected_address}")


def _login(siwe):
    """SIWE login; CAPTCHA_FAILED -> up to CAPTCHA_RETRIES more tries (new nonce + captcha each time)."""
    for i in range(CAPTCHA_RETRIES + 1):
        try:
            return siwe.login()
        except RuntimeError as e:
            if "CAPTCHA_FAILED" not in str(e) or i == CAPTCHA_RETRIES:
                raise


def with_session(job, wallet, pool, wallet_file):
    """Saved session (or SIWE login) -> session saved into the wallet's line -> job(siwe).
    Dead proxy -> next one from Proxy.txt (saved into the line) and run again (jobs check the
    current state first, so a repeat is safe)."""
    proxy, last_error = wallet["proxy"], None
    for attempt in range(1, config.MAX_PROXY_ATTEMPTS + 1):
        if not proxy or proxy.strip().lower() == "noproxy":
            proxy = pool.take()
            if not proxy:
                last_error = "no spare proxies left"
                break
            wallet_file.set_field(wallet["address"], "proxy", proxy)
        try:
            siwe = KeySession(wallet["key"], wallet["address"], proxy)
            token = wallet["token"]
            user = siwe.resume(token) if token else None
            via, created = "session", False
            if user is None:
                via, created = "login", _login(siwe).get("created")
            if siwe.cookie_string() != token:
                wallet_file.set_field(wallet["address"], "token", siwe.cookie_string())
            return {"ok": True, "via": via, "created": created, **job(siwe)}
        except PROXY_FAIL_EXCEPTIONS as e:
            # a request failed: check the internet first. If the machine is offline, every proxy fails
            # the same way — it is not this proxy's fault, so don't burn a spare, just report it
            if not internet_up():
                return {"ok": False, "net_down": True, "error": f"net down: {type(e).__name__}"}
            last_error = f"proxy dead ({attempt}/{config.MAX_PROXY_ATTEMPTS}): {e}"
            proxy = None
        except Exception as e:
            last_error = str(e)
            break
    return {"ok": False, "error": last_error}


def load_refs(path):
    """Ref.txt: referral codes, one per line (duplicates and empty lines skipped)."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return list(dict.fromkeys(l.strip() for l in f if l.strip()))


def plan_refs(wallets, refs):
    """Each ref code in turn gets a random REGS_MIN..REGS_MAX of the wallets (or all that are left).
    Returns ([(wallet, ref code)], {ref code: count}, wallets left over once every code got its share)."""
    plan, counts, i = [], {}, 0
    for code in refs:
        if i >= len(wallets):
            break
        n = min(random.randint(REGS_MIN, REGS_MAX), len(wallets) - i)
        plan += [(w, code) for w in wallets[i:i + n]]
        counts[code] = n
        i += n
    return plan, counts, wallets[i:]


def bind_referral(session, code):
    """Returns "<code> bound" / "no ref code" / "<code> <error code>" (e.g. already has a referrer)."""
    if not code:
        return "no ref code"
    ok, d = _api(session, "POST", REFERRAL_BIND_ENDPOINT, {"code": code})
    return f"{code} bound" if ok else f"{code} {d}"


def pass_gate(session, codes_store, held, burned):
    """Present codes from code.txt until one admits the wallet. Returns (admitted, info).
    Every taken code is appended to `held` (the caller releases them when the wallet is done).
    A code that admitted the wallet or is dead (CODE_DEAD_ERRORS) goes to `burned`; the caller
    puts every other taken code back into code.txt (captcha failed, dead proxy, locked out, ...)."""
    ok, st = _api(session, "GET", GATE_ENDPOINT, referer="/codes")
    if not ok:
        return False, f"gate status: {st}"
    if st.get("admitted"):
        return True, "already admitted"

    tried = []
    code = None
    for _ in range(GATE_ATTEMPTS):
        if code is None:
            code = codes_store.take(own=len(held))
            if code is None:
                return False, f"no codes left in {config.CODES_FILE}" + (f" (tried {tried})" if tried else "")
            held.append(code)
        try:
            ok, d = _api(session, "POST", GATE_ENDPOINT, {"code": gate_code(code)},
                         referer="/codes", captcha=True)
        except PROXY_FAIL_EXCEPTIONS:
            raise  # dead proxy -> code goes back, with_session swaps the proxy and runs again
        except Exception as e:
            raise RuntimeError(f"gate {code}: {e}") from e
        if ok:
            burned.add(code)
            return True, code
        if d == "ACCOUNT_ALREADY_ATTESTED":
            return True, f"already admitted ({code} not used)"
        tried.append(f"{code}:{d}")
        if d in CODE_DEAD_ERRORS:
            burned.add(code)
            code = None                  # spent/unknown code -> next one
        elif d == "CAPTCHA_FAILED":
            pass                         # code was not checked -> same code, fresh captcha
        elif d == "ACCOUNT_NOT_READY":
            time.sleep(NOT_READY_DELAY)  # same code again
        else:                            # REDEMPTION_LOCKED_OUT, gated, ...
            return False, f"gate: {tried}"
    return False, f"gate: {tried}"


def register_job(codes_store, ref):
    """Registration of one wallet, bound to the referral code `ref` (None -> no referral)."""
    def job(siwe):
        s = siwe.session
        held = []   # codes taken by this wallet: other threads wait for its new codes until released
        burned = set()   # of them: used or dead; the rest go back into code.txt
        try:
            res = {"ref": bind_referral(s, ref)}
            admitted, res["gate"] = pass_gate(s, codes_store, held, burned)
            if not admitted:
                raise RuntimeError(f"ref={res['ref']} | {res['gate']}")
            res["checkin"] = checkin(s)
            res["quests"] = do_quests(s)
            codes = fetch_codes(s)
            if "error" in codes:
                raise RuntimeError(f"gate={res['gate']} | codes: {codes['error']}")
            codes["added"] = codes_store.sync(codes["unspent"], codes["spent"])
            return {**res, **codes}
        finally:
            codes_store.give_back([c for c in held if c not in burned])
            codes_store.release(len(held))
    return job


def checkin(session):
    """daily_checkin; CAPTCHA_FAILED -> up to CAPTCHA_RETRIES more tries (it re-checks the state first)."""
    for i in range(CAPTCHA_RETRIES + 1):
        ci = daily_checkin(session)
        if ci.get("error") != "CAPTCHA_FAILED" or i == CAPTCHA_RETRIES:
            return ci


def checkin_job(siwe):
    return {"checkin": checkin(siwe.session)}


def _describe_checkin(ci):
    if ci.get("done"):
        return f"✅ check-in +{ci.get('reward')}QE (streak {ci.get('streak')})"
    if ci.get("error") is not None:
        return f"check-in failed: {ci.get('error')}"
    return f"check-in already done (streak {ci.get('streak')})"


def _describe_quests(q):
    parts = []
    fc = q.get("first_crate")
    if fc:
        parts.append(f"first crate failed: {fc['error']}" if "error" in fc
                     else f"🎁 first crate {fc.get('reward_qe')}QE" + (f"/{fc['award']}" if fc.get("award") else ""))
    if q.get("done"):
        parts.append("📋 " + ", ".join(q["done"]))
    if q.get("failed"):
        parts.append("quests failed: " + ", ".join(q["failed"]))
    return " | ".join(parts) or "quests: nothing new"


def _describe(res):
    if not res.get("ok"):
        return f"FAIL {res.get('error')}"
    head = f"OK   {res['via']}{' (new account)' if res.get('created') else ''}"
    if "gate" not in res:   # done wallet: check-in only
        return f"{head} | {_describe_checkin(res['checkin'])}"
    gate = res["gate"] if res["gate"].startswith("already admitted") else f"admitted with {res['gate']}"
    codes = (f"🔑 +{res['added']} code(s): {', '.join(res['unspent'])}" if res["unspent"]
             else "no unspent codes")
    return (f"{head} | ref: {res['ref']} | {gate} | {_describe_checkin(res['checkin'])} | "
            f"{_describe_quests(res['quests'])} | {codes}")


KEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _parse_wallet(fields):
    """seed,derivation path,private key,address,proxy[,session][,done] -> wallet dict (fields found
    by shape, so the order does not matter). Without a private key the seed + path are used."""
    w = {"key": None, "address": None, "proxy": "", "proxy_idx": None, "token": "", "token_idx": None,
         "seed": None, "path": None}
    for i, f in enumerate(fields):
        if KEY_RE.match(f):
            w["key"] = f
        elif ADDRESS_RE.match(f):
            w["address"] = f
        elif f.startswith("m/"):
            w["path"] = f
        elif "=" in f:   # session cookies: csrftoken=...; sessionid=...
            w["token"], w["token_idx"] = f, i
        elif " " in f:
            w["seed"] = f
        elif f and f.lower() != "done":
            w["proxy"], w["proxy_idx"] = f, i
    if not w["key"]:
        if not w["seed"]:
            return None
        acct = Account.from_mnemonic(w["seed"], account_path=w["path"] or config.DERIVATION_PATH)
        w["key"] = acct.key.hex()
    w["address"] = w["address"] or Account.from_key(w["key"]).address
    return w


class WalletFile:
    """Wallet.txt, one wallet per line: seed,derivation path,private key,address,proxy[,session].
    A registered wallet gets ",done" at the end of its line (next runs: check-in only); a replaced
    proxy and the session are written into the line. Rewritten atomically, other lines as they are."""

    def __init__(self, path):
        if not os.path.exists(path):
            raise SystemExit(f"[!] {path} not found (format: seed,derivation path,private key,address,proxy)")
        self.path = path
        self.lock = threading.Lock()
        with open(path, "r", encoding="utf-8") as f:
            self.lines = [l.rstrip("\r\n") for l in f]
        self.wallets = {}   # line index -> wallet dict
        for i, line in enumerate(self.lines):
            w = _parse_wallet([p.strip() for p in line.split(",")]) if line.strip() else None
            if w:
                self.wallets[i] = w

    def _fields(self, i):
        return [p.strip() for p in self.lines[i].split(",")]

    def _done(self, i):
        return self._fields(i)[-1].lower() == "done"

    def split(self):
        """(wallets to register, done wallets), file order, one entry per address."""
        done_addrs = {w["address"].lower() for i, w in self.wallets.items() if self._done(i)}
        todo, done, seen = [], [], set()
        for w in self.wallets.values():
            a = w["address"].lower()
            if a not in seen:
                seen.add(a)
                (done if a in done_addrs else todo).append(w)
        return todo, done

    def mark_done(self, addr):
        self._edit(addr, lambda i, f: f + ["done"] if f[-1].lower() != "done" else f)

    def set_field(self, addr, name, value):
        """name: "proxy" | "token" - replaced in place, or inserted before a trailing "done"."""
        def edit(i, f):
            w = self.wallets[i]
            j = w[name + "_idx"]
            if j is None:
                j = len(f) - (1 if f[-1].lower() == "done" else 0)
                f.insert(j, value)
                for k in ("proxy_idx", "token_idx"):   # fields after the insert point moved right
                    if w[k] is not None and w[k] >= j:
                        w[k] += 1
                w[name + "_idx"] = j
            else:
                f[j] = value
            w[name] = value
            return f
        self._edit(addr, edit)

    def _edit(self, addr, edit):
        with self.lock:
            for i, w in self.wallets.items():
                if w["address"].lower() == addr.lower():
                    self.lines[i] = ",".join(edit(i, self._fields(i)))
            write_lines(self.path, self.lines)


def run(codes_store):
    wallet_file = WalletFile(WALLET_FILE)
    todo, done = wallet_file.split()
    pool = ProxyPool(config.PROXY_FILE)
    if MODE not in (1, 2):
        raise SystemExit(f"[!] MODE = {MODE}: must be 1 or 2")
    if MODE == 2:   # check-in only: wallets without done are not touched
        plan = []
        print(f"[*] MODE 2 - {WALLET_FILE}: {len(done)} done (check-in only), {len(todo)} not done skipped | "
              f"{THREADS} threads | {pool.remaining()} spare proxies\n")
    else:
        refs = load_refs(REF_FILE)
        if refs:
            plan, counts, left = plan_refs(todo, refs)
        else:   # no Ref.txt -> register without a referral
            plan, counts, left = [(w, None) for w in todo], {}, []
        print(f"[*] MODE 1 - {WALLET_FILE}: {len(todo)} to register, {len(done)} done skipped | "
              f"{THREADS} threads")
        done = []   # registration only: done wallets are not touched
        print(f"[*] {len(refs)} ref code(s) in {REF_FILE}, {REGS_MIN}-{REGS_MAX} per code -> "
              + (", ".join(f"{c}: {n}" for c, n in counts.items()) or "no referral"))
        if left:
            print(f"[!] every ref code got its share: {len(left)} wallet(s) are not registered this run")
        print(f"[*] {codes_store.count()} code(s) in {config.CODES_FILE} | {pool.remaining()} spare proxies\n")

    stats = {"registered": 0, "checkin": 0, "fail": 0}

    def tally(res, addr):
        if not res.get("ok"):
            stats["fail"] += 1
        elif "gate" in res:
            stats["registered"] += 1
            wallet_file.mark_done(addr)
        else:
            stats["checkin"] += 1
        return _describe(res)

    tasks = [(lambda w=w, r=r: with_session(register_job(codes_store, r), w, pool, wallet_file), w["address"])
             for w, r in plan]
    tasks += [(lambda w=w: with_session(checkin_job, w, pool, wallet_file), w["address"]) for w in done]
    _run_pool(tasks, tally)
    print(f"\n[*] DONE - registered: {stats['registered']}  check-in only: {stats['checkin']}  "
          f"FAIL: {stats['fail']}  spare proxies left: {pool.remaining()}")


# ----------------------------------------------------------------

def _run_pool(tasks, describe):
    """tasks: [(fn, address)]; prints describe(result, address) as each one finishes."""
    total, done = len(tasks), 0
    ex = ThreadPoolExecutor(max_workers=THREADS)
    try:
        futs = {ex.submit(fn): addr for fn, addr in tasks}
        for fut in as_completed(futs):
            done += 1
            addr = futs[fut]
            res = fut.result()
            print(f"  [{done}/{total}] {addr} | {describe(res, addr)}")
    except KeyboardInterrupt:
        print("\n[*] Stopping: finishing accounts already in progress...")
        ex.shutdown(wait=True, cancel_futures=True)
        raise
    ex.shutdown(wait=True)


def main():
    codes_store = CodeStore(config.CODES_FILE)
    run(codes_store)
    print(f"[*] {codes_store.count()} unspent code(s) in {config.CODES_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[*] Stopped (codes collected so far are in {config.CODES_FILE})")
        sys.exit(0)
