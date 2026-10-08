#!/usr/bin/env python3
"""
Mass SIWE login + daily check-in + daily crates for every wallet.

Source of wallets — config.SOURCE:
    1 -> Accounts.txt (+ new wallets from Wallet.txt), format below;
    2 -> Boost.txt, one JSON per line {"address", "proxy", "seed_phrase", ...};
         the session token and a swapped proxy are written back into the same line.

Wallet.txt format (one wallet per line):
    user:pass@host:port,seed word seed word ...
i.e. proxy first, then a comma, then the mnemonic.

- Login only (accounts already exist -> `created` is False). No registration step.
- Reuses SiweSession from siwe_login.py: browser headers + proxy are enforced
  there (it refuses to run without a proxy and verifies the exit IP first).
- Dead proxy (ProxyError/timeout/SSL EOF) -> swap for a spare from Proxy.txt
  (in-memory, thread-safe) and retry, up to MAX_PROXY_ATTEMPTS. Wallet.txt itself
  is never rewritten.
- Every launch processes ALL wallets again (login + open daily crates);
  results go to a new wallet_login_results_<YYYYmmdd_HHMMSS>.jsonl per run.
- Sessions are kept in Accounts.txt, one account per line:
      seed word seed word ...,user:pass@host:port,name=value; name=value
  (seed, proxy, session-cookie token). If the token is still valid the account
  works through it (no SIWE login, no captcha); otherwise a fresh login is done
  and the new token (and a swapped proxy, if any) is written back. Accounts.txt
  is created from Wallet.txt on first run; new wallets in Wallet.txt are appended.
"""

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from eth_account import Account

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import cap
import config
from siwe_login import SiweSession

Account.enable_unaudited_hdwallet_features()

WALLET_FILE = "Wallet.txt"
ACCOUNTS_FILE = "Accounts.txt"
# Fresh results file per launch -> every run processes all wallets again.
RESULTS_FILE = f"wallet_login_results_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"

CRATES_ENDPOINT = f"{config.API_BASE}/crates/"
DAILY_OPEN_ENDPOINT = f"{config.API_BASE}/crates/daily/open/"
CHECKIN_ENDPOINT = f"{config.API_BASE}/checkin/"
ACTIVITIES_ENDPOINT = f"{config.API_BASE}/activities/"
ENTRIES_ENDPOINT = f"{config.API_BASE}/activities/entries/"
FIRST_CRATE_SLUG = "open-first-crate"

PROXY_FAIL_EXCEPTIONS = (
    requests.exceptions.ProxyError,
    requests.exceptions.ConnectTimeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.SSLError,
)


def _parse_line(line):
    """Accounts.txt: seed,proxy,token  |  Wallet.txt: proxy,seed. Returns (seed, proxy, token)."""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 2:
        return None
    if " " in parts[0]:
        return parts[0], parts[1], ",".join(parts[2:]).strip()
    return parts[1], parts[0], ""


class AccountStore:
    """address -> [seed, proxy, token]; every update rewrites Accounts.txt atomically."""

    def __init__(self, accounts_path, wallet_path):
        self.path = accounts_path
        self.lock = threading.Lock()
        self.rows = {}
        for path in (accounts_path, wallet_path):
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    parsed = _parse_line(line.strip())
                    if not parsed:
                        continue
                    seed, proxy, token = parsed
                    addr = Account.from_mnemonic(seed, account_path=config.DERIVATION_PATH).address
                    self.rows.setdefault(addr, [seed, proxy, token])
        self._flush()

    def wallets(self):
        """[(index, proxy, seed, address, token)]"""
        return [(i, p, s, a, t) for i, (a, (s, p, t)) in enumerate(self.rows.items())]

    def update(self, addr, proxy, token):
        with self.lock:
            self.rows[addr][1:] = [proxy, token]
            self._flush()

    def _flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for seed, proxy, token in self.rows.values():
                f.write(f"{seed},{proxy},{token}\n")
        os.replace(tmp, self.path)

    def close(self):
        pass


class BoostStore:
    """Boost.txt: one JSON object per line ({"address", "proxy", "seed_phrase", ...}).

    Same role as AccountStore: the session token and a swapped proxy are written back into the
    wallet's own line ("token" / "proxy"), other fields are kept as they are. The file is big
    (thousands of wallets), so it is rewritten at most every BOOST_FLUSH_SECONDS and on close().
    """

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.entries = []          # every line, in file order (unparsable lines kept as raw text)
        self.by_addr = {}          # address -> [entry indices] (duplicates updated together)
        self.order = []            # unique addresses, first occurrence order
        with open(path, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    self.entries.append(line)
                    continue
                if not isinstance(e, dict) or not e.get("seed_phrase"):
                    self.entries.append(line)
                    continue
                addr = e.get("address") or Account.from_mnemonic(
                    e["seed_phrase"], account_path=config.DERIVATION_PATH).address
                if addr not in self.by_addr:
                    self.by_addr[addr] = []
                    self.order.append(addr)
                self.by_addr[addr].append(len(self.entries))
                self.entries.append(e)
        self._dirty = False
        self._last_flush = time.monotonic()

    def wallets(self):
        """[(index, proxy, seed, address, token)]"""
        out = []
        for i, addr in enumerate(self.order):
            e = self.entries[self.by_addr[addr][0]]
            out.append((i, e.get("proxy") or "", e["seed_phrase"], addr, e.get("token") or ""))
        return out

    def update(self, addr, proxy, token):
        with self.lock:
            for i in self.by_addr[addr]:
                self.entries[i]["proxy"] = proxy
                self.entries[i]["token"] = token
            self._dirty = True
            if time.monotonic() - self._last_flush >= config.BOOST_FLUSH_SECONDS:
                self._flush()

    def _flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write((json.dumps(e) if isinstance(e, dict) else e) + "\n")
        os.replace(tmp, self.path)
        self._dirty = False
        self._last_flush = time.monotonic()

    def close(self):
        with self.lock:
            if self._dirty:
                self._flush()


class ProxyPool:
    def __init__(self, proxy_file):
        self.lock = threading.Lock()
        try:
            with open(proxy_file, "r", encoding="utf-8") as f:
                self._pool = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            self._pool = []

    def take(self):
        with self.lock:
            return self._pool.pop(0) if self._pool else None

    def remaining(self):
        with self.lock:
            return len(self._pool)


class Results:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.done = set()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        if rec.get("ok") and rec.get("address"):
                            self.done.add(rec["address"].lower())
                    except Exception:
                        pass

    def is_done(self, addr):
        return bool(addr) and addr.lower() in self.done

    def write(self, rec):
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            if rec.get("ok") and rec.get("address"):
                self.done.add(rec["address"].lower())


def _to_int(v, default=0):
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return default


def open_chests(session, limit):
    """Open up to `limit` daily crates while there are opens left today and enough QE. Returns summary."""
    csrf = session.cookies.get("csrftoken")
    headers = {"X-CSRFToken": csrf, "Referer": f"{config.BASE_URL}/crate"}

    me = session.get(config.ME_ENDPOINT, timeout=config.API_TIMEOUT).json().get("data") or {}
    qe = _to_int(me.get("qe_balance"))
    crates = session.get(CRATES_ENDPOINT, timeout=config.API_TIMEOUT).json().get("data") or {}
    daily = crates.get("daily") or {}
    remaining = min(_to_int(daily.get("remaining")), limit)
    cost = _to_int(daily.get("cost"), default=999999)

    opened, rewards = 0, []
    while remaining > 0 and qe >= cost:
        r = session.post(DAILY_OPEN_ENDPOINT, headers=headers, timeout=config.API_TIMEOUT)
        try:
            body = r.json()
        except ValueError:
            break
        if r.status_code != 200 or not body.get("success"):
            rewards.append({"error": (body.get("error") or {}).get("code", r.status_code)})
            break
        d = body.get("data") or {}
        rewards.append({"id": d.get("id"), "reward_qe": d.get("reward_qe"),
                        "tier": d.get("tier"), "award": d.get("award")})
        opened += 1
        remaining -= 1
        # refresh balance (reward may top it up)
        me = session.get(config.ME_ENDPOINT, timeout=config.API_TIMEOUT).json().get("data") or {}
        qe = _to_int(me.get("qe_balance"))

    return {"opened": opened, "rewards": rewards, "qe_final": qe, "cost": cost}


def _post(session, url, body=None):
    """POST с CSRF как у фронтенда. Returns (ok, data | error code)."""
    headers = {"X-CSRFToken": session.cookies.get("csrftoken"), "Referer": f"{config.BASE_URL}/"}
    r = session.post(url, json=body if body is not None else {}, headers=headers, timeout=config.API_TIMEOUT)
    try:
        b = r.json()
    except ValueError:
        return False, r.status_code
    if r.status_code not in (200, 201) or not b.get("success"):
        return False, (b.get("error") or {}).get("code", r.status_code)
    return True, b.get("data") or {}


def _entries(session):
    """(entries, crates_opened) из /activities/entries/."""
    d = session.get(ENTRIES_ENDPOINT, timeout=config.API_TIMEOUT).json().get("data") or {}
    return d.get("entries") or [], _to_int((d.get("chain_stats") or {}).get("crates_opened"))


def _entry_state(slug, period, entries):
    """Как G6 во фронтенде: ('done'|'pending'|'available', entry_id)."""
    mine = [e for e in entries if e.get("activity") == slug
            and (not period or not e.get("period") or e.get("period") == period)]
    for e in mine:
        if e.get("status") in ("completed", "settled"):
            return "done", e.get("id")
    for e in mine:
        if e.get("status") == "entered":
            return "pending", e.get("id")
    return "available", None


def _claim(session, act, state, entry_id):
    """Засчитать задание: pending -> complete; available -> enter (+ complete для zero-entry)."""
    if state == "pending":
        return _post(session, f"{ENTRIES_ENDPOINT}{entry_id}/complete/")
    ok, d = _post(session, f"{ACTIVITIES_ENDPOINT}{act['slug']}/enter/", {"attempt_key": "once"})
    if ok and act.get("is_zero_entry") and d.get("status") == "entered":
        return _post(session, f"{ENTRIES_ENDPOINT}{d.get('id')}/complete/")
    return ok, d


def do_quests(session):
    """Разовые задания-ссылки (follow-x, join-discord, ...) + «открыть первый сундук».

    Задания с verify=link засчитываются просто по переходу, как кнопка на сайте. Если сундуков
    ещё не открывали — пробуем открыть один (даже если QE меньше цены: возможно, первый бесплатный;
    сервер сам откажет, ответ пишется в лог). Задания с постом/привязкой соцсети пропускаются.
    """
    acts = session.get(ACTIVITIES_ENDPOINT, timeout=config.API_TIMEOUT).json().get("data") or {}
    acts = acts.get("activities") or []
    entries, crates_opened = _entries(session)

    done, failed, first_crate = [], [], None
    for act in acts:
        slug = act.get("slug")
        disp = act.get("display") or {}
        state, entry_id = _entry_state(slug, act.get("period"), entries)
        if state == "done":
            continue
        if disp.get("verify") == "link" or state == "pending":
            pass
        elif slug == FIRST_CRATE_SLUG:
            if crates_opened < max(_to_int(disp.get("threshold"), 1), 1):
                ok, d = _post(session, DAILY_OPEN_ENDPOINT)
                first_crate = ({"reward_qe": d.get("reward_qe"), "award": d.get("award")}
                               if ok else {"error": d})
                if not ok:
                    continue
        else:
            continue  # post_url / social:* / email / progress — не автоматизируем
        ok, d = _claim(session, act, state, entry_id)
        if ok:
            done.append(f"{slug}+{(act.get('reward') or {}).get('base', '?')}")
        else:
            failed.append(f"{slug}:{d}")
    return {"done": done, "failed": failed, "first_crate": first_crate}


def daily_checkin(session):
    """Ежедневный чек-ин: POST только если сегодня ещё можно (иначе капча тратится зря). Returns summary."""
    st = session.get(CHECKIN_ENDPOINT, timeout=config.API_TIMEOUT).json().get("data") or {}
    if not st.get("can_check_in"):
        return {"done": False, "already": bool(st.get("checked_in_today")), "streak": st.get("streak")}

    headers = {"X-CSRFToken": session.cookies.get("csrftoken"), "Referer": f"{config.BASE_URL}/",
               "X-Captcha-Token": cap.solve(session)}
    r = session.post(CHECKIN_ENDPOINT, json={}, headers=headers, timeout=config.API_TIMEOUT)
    try:
        body = r.json()
    except ValueError:
        return {"done": False, "error": r.status_code}
    if r.status_code not in (200, 201) or not body.get("success"):
        return {"done": False, "error": (body.get("error") or {}).get("code", r.status_code)}
    d = body.get("data") or {}
    return {"done": True, "streak": d.get("streak"), "reward": st.get("daily_reward")}


def process(idx, proxy, seed, address, token, pool, results, store):
    if results.is_done(address):
        return {"address": address, "ok": True, "skipped": True}

    last_error = None
    for attempt in range(1, config.MAX_PROXY_ATTEMPTS + 1):
        if not proxy or proxy.strip().lower() == "noproxy":
            proxy = pool.take()
            if not proxy:
                last_error = "no spare proxies left"
                break
        try:
            siwe = SiweSession(seed_phrase=seed, expected_address=address,
                               proxy=proxy, verbose=False)
            user = siwe.resume(token) if token else None
            via, created = "token", False
            if user is None:
                if token:  # saved session expired -> drop it before trying a fresh login
                    token = ""
                    store.update(address, proxy, token)
                r = siwe.login()
                user, via, created = r["user"], "login", r.get("created")
            token = siwe.cookie_string()
            store.update(address, proxy, token)
            checkin = daily_checkin(siwe.session) if config.CHECKIN else None
            quests = do_quests(siwe.session) if config.QUESTS else None
            chest = open_chests(siwe.session, config.OPEN_BOX) if config.OPEN_BOX > 0 else None
            rec = {
                "ok": True, "address": siwe.address, "via": via,
                "user_id": user.get("id"), "status": user.get("status"),
                "created": created, "proxy": proxy, "checkin": checkin, "quests": quests,
            }
            if chest:
                rec.update(opened=chest["opened"], rewards=chest["rewards"], qe_final=chest["qe_final"])
            results.write(rec)
            return rec
        except PROXY_FAIL_EXCEPTIONS as e:
            last_error = f"proxy dead ({attempt}/{config.MAX_PROXY_ATTEMPTS}): {e}"
            proxy = pool.take()
            if not proxy:
                last_error += " — no spare proxies left"
                break
            continue
        except Exception as e:
            last_error = str(e)
            break

    rec = {"ok": False, "address": address, "error": last_error, "proxy": proxy}
    results.write(rec)
    return rec


def _print_result(res, addr, done, total):
    if res.get("skipped"):
        return
    if not res.get("ok"):
        print(f"  [{done}/{total}] FAIL {addr}: {res.get('error')}")
        return
    parts = [f"{res.get('via')}✓"]
    ci = res.get("checkin")
    if ci is not None:
        if ci.get("done"):
            parts.append(f"✅ check-in +{ci.get('reward')}QE (streak {ci.get('streak')})")
        elif ci.get("error") is not None:
            parts.append(f"check-in failed: {ci.get('error')}")
        else:
            parts.append(f"check-in already done (streak {ci.get('streak')})")
    q = res.get("quests")
    if q:
        fc = q.get("first_crate")
        if fc:
            parts.append(f"first crate failed: {fc['error']}" if "error" in fc
                         else f"🎁 first crate {fc.get('reward_qe')}QE"
                              + (f"/{fc['award']}" if fc.get("award") else ""))
        if q.get("done"):
            parts.append("📋 " + ", ".join(q["done"]))
        if q.get("failed"):
            parts.append("quests failed: " + ", ".join(q["failed"]))
    if "opened" in res:
        opened = res.get("opened", 0)
        drops = " + ".join(f"{(x or {}).get('reward_qe', '?')}QE"
                           + (f"/{(x or {}).get('award')}" if (x or {}).get("award") else "")
                           for x in res.get("rewards", []) if "error" not in (x or {}))
        if opened:
            parts.append(f"🎁 opened {opened} chest(s): {drops} | qe_left={res.get('qe_final')}")
        else:
            parts.append(f"no chest opened (qe={res.get('qe_final')} < cost)")
    print(f"  [{done}/{total}] OK   {addr} | " + " | ".join(parts))


def open_store():
    """config.SOURCE: 1 — Accounts.txt (+ Wallet.txt), 2 — Boost.txt. Returns (store, file name)."""
    if config.SOURCE == 1:
        return AccountStore(ACCOUNTS_FILE, WALLET_FILE), ACCOUNTS_FILE
    if config.SOURCE == 2:
        if not os.path.exists(config.BOOST_FILE):
            raise SystemExit(f"[!] SOURCE = 2, but {config.BOOST_FILE} not found")
        return BoostStore(config.BOOST_FILE), config.BOOST_FILE
    raise SystemExit(f"[!] config.SOURCE must be 1 (Accounts.txt) or 2 (Boost.txt), got {config.SOURCE!r}")


def main():
    store, source = open_store()
    try:
        run(store, source)
    finally:
        store.close()   # Boost.txt: write back what is still buffered (also on Ctrl+C)


def run(store, source):
    wallets = store.wallets()
    pool = ProxyPool(config.PROXY_FILE)
    results = Results(RESULTS_FILE)

    todo = [w for w in wallets if not results.is_done(w[3])]
    with_token = sum(1 for w in todo if w[4])
    print(f"[*] {len(wallets)} accounts in {source} ({with_token} with saved session)")
    print(f"[*] {len(todo)} to process -> results in {RESULTS_FILE}")
    print(f"[*] {pool.remaining()} spare proxies | {config.NUM_THREADS} workers\n")

    ok = fail = done = 0
    ex = ThreadPoolExecutor(max_workers=config.NUM_THREADS)
    try:
        futs = {ex.submit(process, i, p, s, a, t, pool, results, store): a
                for (i, p, s, a, t) in todo}
        for fut in as_completed(futs):
            addr = futs[fut]
            done += 1
            res = fut.result()
            if res.get("skipped") or res.get("ok"):
                ok += 1
            else:
                fail += 1
            _print_result(res, addr, done, len(todo))
    except KeyboardInterrupt:
        # не ждать тысячи поставленных в очередь кошельков: только те, что уже в работе
        print("\n[*] Stopping: finishing accounts already in progress...")
        ex.shutdown(wait=True, cancel_futures=True)
        raise
    ex.shutdown(wait=True)

    print(f"\n[*] DONE — OK: {ok}  FAIL: {fail}  spare proxies left: {pool.remaining()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[*] Stopped (progress saved to {RESULTS_FILE})")
        sys.exit(0)
