#!/usr/bin/env python3
"""
Квесты уровня 3 для первых аккаунтов из Accounts.txt — отдельно от game.py (их не запускать вместе).
Работает по кругу, пока не остановить (Ctrl+C):

1. Экономика (каждый заход, как в game.py): кэш забирается при заполнении на 75-100%; апгрейды —
   сначала суперчип до SUPER_CHIP_MAX (30: на 10/20/30 приходят волны стражей) — всегда; компоненты по
   окупаемости (как в game.py), но ни один не выше COMPONENT_MAX (15) и только в стадии накопления.
   Стадии (метка в MARKS_FILE, переживает перезапуск):
     фарм престижа — баланс >= 2 млрд: только суперчип + обнуления, на компоненты QE не тратится;
     накопление    — баланс упал ниже 2 млрд: компоненты до 15, без обнулений, пока баланс не дорастёт
                     до ACCUMULATE_UNTIL_QE (5 млрд) — тогда метка снимается и снова фарм престижа.
2. Волны стражей (The Slow one / The Opportunist / The Aggressive one). Волна пройдена, когда выдержано
   нужное число её ударов: удар отражён щитом или сам провалился. Щит = валидация блока. Opportunist
   бьёт, только когда щита нет, поэтому щит заранее не ставим: ждём объявленный удар стража
   (network_attacks.warning) и только тогда валидируем блок.
3. Все три волны пройдены, стадия «фарм престижа» -> re-tape-out с чиплетом CHIPLET (compute):
   суперчип, компоненты, квантовый чип и кэш обнуляются (кэш перед этим забирается), баланс QE остаётся,
   престиж +1, и всё начинается с п.1. В стадии накопления не обнуляем.
   Каждое обнуление даёт чиплет; готовы все (3 из 3) и QE >= PACKAGE_MIN_QE (10 млрд) -> собираем пакет
   (POST /game/package/assemble/, 5 млрд QE + 100k E).
4. Охота на шине (Bus hunt): когда атакуют соседа по шине, жмём Defend (POST /game/bus-hunt/defend/),
   за это дают E. Лимит сайта — 10 защит в сутки (UTC); исчерпан -> ждём сброса.

Сессия и прокси — из Accounts.txt; новая сессия (после входа) записывается обратно в строку аккаунта.
Ошибка прокси: сначала проверяется интернет самой машины (прямой запрос). Интернета нет — ждём, прокси не
трогаем. Интернет есть, а прокси не отвечает PROXY_SWAP_AFTER раз подряд — берём следующий из Proxy.txt
(удаляется оттуда) и записываем в строку аккаунта. Не запускать вместе с game.py: оба пишут эти файлы.

Запуск:  .venv\\Scripts\\python.exe Quest.py            — работать, пока не остановить (Ctrl+C)
         .venv\\Scripts\\python.exe Quest.py --check    — один раз показать статус, ничего не делая
"""

import json
import os
import random
import secrets
import sys
import threading
import time
import uuid

from eth_account import Account

import config
from Boost import _login
from game import Game, GameError, Tick, _dec, _fmt_wait, _left, _ts
from login_wallets import (ACCOUNTS_FILE, PROXY_FAIL_EXCEPTIONS, AccountStore, ProxyPool, internet_up,
                           write_lines)
from siwe_login import SiweSession

Account.enable_unaudited_hdwallet_features()

ACCOUNTS = [1]     # позиции аккаунтов в Accounts.txt (с 1); аккаунт не на уровне 3 пропускается
ECONOMY = 1              # 1 — забирать кэш, качать суперчип/компоненты, делать re-tape-out; 0 — выкл
SUPER_CHIP_MAX = 30      # суперчип качается до этого уровня (первым делом), выше — не трогаем
COMPONENT_MAX = 15       # компоненты качаются по окупаемости, но не выше этого уровня
RETAPE = 1               # 1 — re-tape-out, когда все волны пройдены и QE хватает; 0 — выкл
RETAPE_MIN_QE = 2_000_000_000    # баланс упал ниже (2 млрд QE) -> метка «накопление»: не обнуляем, качаем
                                 # компоненты до 15 и копим
ACCUMULATE_UNTIL_QE = 5_000_000_000   # метка снимается, когда баланс дорос до этого (5 млрд QE) -> снова фарм
                                      # престижа (только суперчип + обнуления, компоненты не качаем)
MARKS_FILE = "quest_marks.json"  # метки «накопление» по аккаунтам: переживают перезапуск бота
CHIPLET = "compute"      # тип чиплета при re-tape-out: compute / memory / io
PACKAGE = 1              # 1 — собирать пакет, когда готовы все чиплеты (3 из 3) и QE хватает; 0 — выкл
PACKAGE_MIN_QE = 10_000_000_000  # не собирать, если на балансе меньше (10 млрд QE; сама сборка — 5 млрд + 100k E)
SENTINELS = 1            # 1 — защищаться от ударов стражей щитом (валидация блока), 0 — выкл
SHIELD_RETRY = (2, 4)    # с: сервер ответил RATE_LIMITED на щит -> повторить через столько, пока удар не пришёл
SHIELD_LAST_SEC = 3      # с до удара, после которых повторять уже бессмысленно
BUS_HUNT = 1             # 1 — защищать соседей по шине, 0 — выкл
POLL = (15, 25)          # с между проверками, пока есть что делать (окно защиты соседа ~40 с)
RECHECK = 600            # с: перепроверка, когда делать нечего (не уровень 3, нет слота на доске)
RETRY = 120              # с после ошибки
PROXY_RETRY = 30         # с: повтор после ошибки прокси (интернет у машины есть)
PROXY_SWAP_AFTER = 2     # столько ошибок прокси подряд (при живом интернете) -> следующий прокси из Proxy.txt
NET_WAIT = 60            # с: как часто перепроверять интернет, пока его нет (стражи бьют раз в несколько минут)

NAMES = {"slow": "The Slow one", "opportunist": "The Opportunist", "aggressive": "The Aggressive one"}
SESSION_LOST = ("NOT_AUTHENTICATED", 401)
L1_ITEMS = {"chip", "entropy"}   # Level 1 items: never ours to buy here


class SessionLost(RuntimeError):
    pass


def proxy_host(proxy):
    """host:port of a proxy line, without the login and password (for the log)."""
    rest = proxy.split("://")[-1]
    if "@" in rest:
        return rest.split("@")[-1]
    parts = rest.split(":")
    if len(parts) == 4:
        return ":".join(parts[:2]) if parts[1].isdigit() else ":".join(parts[2:])
    return rest


def qe(v):
    """QE amount, short: 11.85B / 270.4M / 15,000."""
    v = float(v)
    if v >= 1e9:
        return f"{v / 1e9:.2f}B"
    if v >= 1e6:
        return f"{v / 1e6:.1f}M"
    return f"{v:,.0f}"


def wave_line(w, prev):
    """A wave's status as the site shows it."""
    st = w.get("status")
    if st == "beaten":
        return "Beaten"
    if st == "active":
        return f"Held {w.get('held')}/{w.get('strikes_to_beat')} · landed {w.get('landed')}"
    if prev is None or prev.get("status") == "beaten":
        return f"arrives at super chip {w.get('at_super_chip_level')}"
    return f"after {NAMES.get(prev.get('sentinel'), prev.get('sentinel'))}"


class Marks:
    """MARKS_FILE: {address: {"stage": "accumulating", ...}} — accounts in the accumulation stage.
    Kept on disk so a restart knows the stage; nothing is written in --check mode."""

    def __init__(self, path, write=True):
        self.path, self.write = path, write
        self.lock = threading.Lock()
        self.data = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except ValueError:
                print(f"[!] {path} is broken: no account is marked")

    def accumulating(self, addr):
        return addr.lower() in self.data

    def set(self, addr, on, balance):
        with self.lock:
            if on:
                self.data[addr.lower()] = {"stage": "accumulating", "since": time.strftime("%Y-%m-%d %H:%M:%S"),
                                           "balance_then": qe(balance), "until": qe(ACCUMULATE_UNTIL_QE)}
            else:
                self.data.pop(addr.lower(), None)
            if self.write:
                write_lines(self.path, [json.dumps(self.data, ensure_ascii=False, indent=1)])


class QuestTick(Tick):
    """game.py's visit (claim, ROI upgrades, extraction discounts, heat guard) with Quest's caps:
    the super chip first up to SUPER_CHIP_MAX, components by ROI but never above COMPONENT_MAX."""

    def target(self, blocked):
        opts = {n: o for n, o in self.options().items() if n not in blocked and n not in L1_ITEMS}
        if "super_chip" in opts and self._level_of("super_chip") < SUPER_CHIP_MAX:
            # the super chip runs hot: lift the heat limit first if the next level would throttle production
            if (not self._heat_ok("super_chip") and "heatsink" in opts
                    and self._level_of("heatsink") < COMPONENT_MAX):
                return ("heatsink", *opts["heatsink"])
            return ("super_chip", *opts["super_chip"])
        if not getattr(self, "components_on", False):
            return None   # prestige farming: QE is kept for the next rounds, components only while accumulating
        capped = {n for n in opts if n == "super_chip" or self._level_of(n) >= COMPONENT_MAX}
        return super().target(set(blocked) | capped | L1_ITEMS)


class Quester:
    """One account: its own session and loop."""

    def __init__(self, pos, seed, addr, proxy, token, store, pool, marks, act=True):
        self.pos, self.seed, self.addr, self.proxy, self.token = pos, seed, addr, proxy, token
        self.store, self.pool, self.marks = store, pool, marks   # Accounts.txt / Proxy.txt / quest_marks.json
        self.act = act            # False (--check): read and report only, never write files
        self.proxy_fails = 0      # proxy errors in a row while the machine is online
        self.game = None
        self.next_state_at = 0.0
        self.next_econ_at = 0.0
        self.next_hunt_at = 0.0
        self.shielded_seq = None  # strike we already raised a shield against
        self.seen_recent = None   # bus-hunt results already reported
        self.was_beaten = None    # all sentinel waves beaten at the last state look (None: not seen yet)
        self.last = {}            # last printed status per topic
        self.level = None         # game level at the last state look
        # what this account does (game.py's watcher turns the economy off and starts from level 2)
        self.economy_on, self.sentinels_on, self.hunt_on, self.min_level = ECONOMY, SENTINELS, BUS_HUNT, 3

    def log(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] #{self.pos} {self.addr[:8]}…{self.addr[-4:]} | {msg}", flush=True)

    def report(self, key, text):
        """Print a status line only when it changed."""
        if self.last.get(key) != text:
            self.last[key] = text
            self.log(text)

    # --- session -------------------------------------------------------------------------

    def level_allowed(self, level):
        """May this account be played at `level`? (game.py's watcher follows config.LVL1/2/3)"""
        return True

    def new_siwe(self):
        """The login session for this account (game.py's watcher signs with the private key instead)."""
        return SiweSession(seed_phrase=self.seed, expected_address=self.addr, proxy=self.proxy, verbose=False)

    def connect(self):
        if not self.proxy and not self.swap_proxy("no proxy in Accounts.txt"):
            raise RuntimeError("no proxy for this account and no spares left in Proxy.txt")
        siwe = self.new_siwe()
        user = siwe.resume(self.token) if self.token else None
        if user is None:
            _login(siwe)
            self.log("logged in (new session saved to Accounts.txt)" if self.act else "logged in")
        token = siwe.cookie_string()
        if token != self.token:
            self.token = token
            self.save()
        self.game = Game(siwe.session)

    def save(self):
        """Proxy + session into the account's line in Accounts.txt (not in --check mode)."""
        if self.act:
            self.store.update(self.addr, self.proxy, self.token)

    def swap_proxy(self, why):
        """Next spare from Proxy.txt (removed from there) -> this account, saved to Accounts.txt."""
        if not self.act:
            return False
        new = self.pool.take()
        if not new:
            self.log(f"{why} — no spare proxies left in {config.PROXY_FILE}, keeping the current one")
            return False
        old = proxy_host(self.proxy) if self.proxy else "none"
        self.proxy, self.proxy_fails = new, 0
        self.save()
        self.log(f"🔁 {why} — proxy {old} → {proxy_host(new)} (from {config.PROXY_FILE}, "
                 f"{self.pool.remaining()} spare left)")
        return True

    def call(self, method, path, body=None):
        ok, d = self.game.call(method, path, body)
        if not ok and d in SESSION_LOST:
            raise SessionLost(str(d))
        return ok, d

    # --- economy: claim, upgrades, re-tape-out -------------------------------------------

    def economy(self, t):
        """One economy visit on the state already loaded in `t`. Sets next_econ_at."""
        se = t.st.get("sentinels") or {}
        beaten = bool(se.get("all_beaten"))
        amount, capacity, _ = t.cache()
        total = t.balance + amount   # the balance once the cache is claimed

        # stage: below 2B -> mark "accumulating" (components up to 15, no re-tape-out) until 5B
        acc = self.marks.accumulating(self.addr)
        if not acc and total < RETAPE_MIN_QE:
            acc = True
            self.marks.set(self.addr, True, total)
            self.log(f"📉 balance {qe(total)} < {qe(RETAPE_MIN_QE)} — ACCUMULATION stage: components → "
                     f"{COMPONENT_MAX}, no re-tape-out until {qe(ACCUMULATE_UNTIL_QE)}")
        elif acc and total >= ACCUMULATE_UNTIL_QE:
            acc = False
            self.marks.set(self.addr, False, total)
            self.log(f"📈 balance {qe(total)} ≥ {qe(ACCUMULATE_UNTIL_QE)} — accumulation done, back to prestige "
                     f"farming (super chip → {SUPER_CHIP_MAX} + re-tape-outs)")
        t.components_on = acc
        retape_due = RETAPE and beaten and not acc and total >= RETAPE_MIN_QE

        if not self.act:   # --check: tell what would happen
            what = (f"would re-tape-out ({CHIPLET})" if retape_due
                    else "waves not beaten yet" if not beaten
                    else f"waves beaten, accumulating up to {qe(ACCUMULATE_UNTIL_QE)} before re-tape-out")
            if self.package_ready(t):
                what += (" | would assemble package" if t.balance >= PACKAGE_MIN_QE
                         else f" | package ready, waiting for {qe(PACKAGE_MIN_QE)} QE")
            self.log(f"{self.econ_status(t)} | {what}")
            return

        # the cache: at the usual % threshold, and always right before a re-tape-out (it resets the cache)
        if capacity > 0 and (amount >= t.claim_level() or retape_due):
            t.claim()

        if retape_due and t.balance >= RETAPE_MIN_QE:
            if self.retape(t):
                t.refresh()   # fresh board: everything below starts from scratch
            else:   # not now (attack incoming, draw open, ...): keep the QE, try again soon
                t.waits.append((random.uniform(120, 300), "re-tape-out retry"))
                self.finish_econ(t, None)
                return

        # all chiplets ready (3 of 3) and enough QE -> assemble the package before upgrades spend the QE
        if self.package_ready(t) and t.balance >= PACKAGE_MIN_QE:
            if self.assemble(t):
                t.refresh()

        waiting = t.upgrades()
        if t.bought:
            t.refresh()
        self.finish_econ(t, waiting)

    def retape(self, t):
        bal = t.balance
        ok, d = self.call("POST", "/game/retape-out/",
                          {"idempotency_key": str(uuid.uuid4()), "chiplet_type": CHIPLET})
        if not ok:
            self.log(f"♻ re-tape-out not done: {d} — retry in a few minutes")
            return False
        prestige = ((t.st.get("prestige") or {}).get("level") or 0) + 1
        self.log(f"♻ RE-TAPE-OUT done ({CHIPLET}), prestige → {prestige}, balance {qe(bal)} QE — new board, "
                 f"starting over: super chip → {SUPER_CHIP_MAX}, components → {COMPONENT_MAX}, sentinel waves")
        self.shielded_seq = None
        self.last.pop("sentinels", None)
        return True

    @staticmethod
    def package_ready(t):
        pk = t.st.get("package") or {}
        return PACKAGE and pk and (pk.get("free_chiplets") or 0) >= (pk.get("required") or 3)

    def assemble(self, t):
        pk = t.st.get("package") or {}
        cost_e = _dec(pk.get("cost_e"), None)
        e_now = _dec((t.st.get("entropy") or {}).get("amount_exact_e"), None)
        if cost_e is not None and e_now is not None and e_now < cost_e:
            self.report("package", f"📦 package ready, but not enough E ({qe(e_now)} < {qe(cost_e)})")
            return False
        bal = t.balance
        ok, d = self.call("POST", "/game/package/assemble/", {"idempotency_key": str(uuid.uuid4())})
        if not ok:
            self.log(f"📦 package not assembled: {d} — retry next visit")
            return False
        self.log(f"📦 PACKAGE assembled ({pk.get('free_chiplets')} chiplets, -{qe(pk.get('cost_qe') or 0)} QE "
                 f"-{qe(pk.get('cost_e') or 0)} E), packages → {(pk.get('packages') or 0) + 1}, balance was {qe(bal)}")
        return True

    def finish_econ(self, t, waiting):
        wait, why = t.plan(waiting)
        self.next_econ_at = time.time() + wait
        parts = []
        if t.claimed:
            parts.append(f"💰 claimed {qe(t.claimed)}")
        if t.bought:
            parts.append("⬆ " + ", ".join(f"{n}+{k}" for n, k in t.bought.items()) + f" (-{qe(t.spent)})")
        parts += t.log
        parts.append(self.econ_status(t))
        parts.append(f"next in {_fmt_wait(wait)} ({why})")
        self.log(" | ".join(parts))

    def econ_status(self, t):
        stage = (f"📦 ACCUMULATING → {qe(ACCUMULATE_UNTIL_QE)}" if self.marks.accumulating(self.addr)
                 else "🔁 prestige farming")
        return f"{stage} | {self.econ_line(t)}"

    @staticmethod
    def econ_line(t):
        comps = t.st.get("components") or {}
        open_ = sum(1 for c in comps.values()
                    if c.get("unlocked") and c.get("next_cost_qe") is not None and (c.get("level") or 0) < COMPONENT_MAX)
        _, _, prod = t.cache()
        heat = t.st.get("heat") or {}
        pk = t.st.get("package") or {}
        return (f"super chip {t._level_of('super_chip')}/{SUPER_CHIP_MAX} | {open_} component(s) below "
                f"{COMPONENT_MAX} | {qe(prod)} QE/s | heat {heat.get('heat')}/{heat.get('limit')} | "
                f"chiplets {pk.get('free_chiplets', '?')}/{pk.get('required', 3)} | balance {qe(t.balance)}")

    # --- sentinels -----------------------------------------------------------------------

    def sentinels(self, st):
        """Returns True while a wave is active (needs fast polling)."""
        se = st.get("sentinels") or {}
        waves = se.get("waves") or []
        if se.get("all_beaten"):
            self.report("sentinels", "sentinels: all waves beaten ✓")
            return False
        if se.get("status") in (None, "inactive") or not waves:
            self.report("sentinels", "sentinels: no wave yet (they arrive with super chip levels)")
            return False
        parts = []
        for i, w in enumerate(waves):
            line = wave_line(w, waves[i - 1] if i else None)
            if w.get("status") == "active" and w.get("sentinel") == "opportunist" and se.get("waiting_for_shield"):
                line += " (waiting for your shield to expire)"
            parts.append(f"{NAMES.get(w.get('sentinel'), w.get('sentinel'))}: {line}")
        self.report("sentinels", "sentinels: " + " | ".join(parts))
        if not any(w.get("status") == "active" for w in waves):
            return False   # the next wave has not arrived yet (super chip level): nothing to defend now

        warn = (st.get("network_attacks") or {}).get("warning")
        if (warn and warn.get("sentinel") and not warn.get("shielded_now")
                and _left(warn.get("due_at")) > 0 and warn.get("sequence") != self.shielded_seq):
            self.raise_shield(st, warn)
        return True

    def raise_shield(self, st, warn):
        who = NAMES.get(warn.get("sentinel"), warn.get("sentinel"))
        p = _dec(warn.get("success_probability"))
        head = (f"⚠ {who} strike #{warn.get('sequence')} in {int(_left(warn.get('due_at')))}s, no shield"
                + (f" (lands with {float(p):.0%})" if p is not None else ""))
        if not self.act:
            self.log(head + " — check mode, not acting")
            return
        cost = _dec((st.get("blocks") or {}).get("cost_e"), None)
        e_now = _dec((st.get("entropy") or {}).get("amount_exact_e"), None)
        if cost is not None and e_now is not None and e_now < cost:
            self.log(f"{head} — not enough E for a block ({e_now} < {cost})")
            return
        # RATE_LIMITED -> press again in a couple of seconds, until the strike lands
        deadline = (_ts(warn.get("due_at")) or time.time()) - SHIELD_LAST_SEC
        aid, tries = None, 0
        while True:
            tries += 1
            err = None
            try:
                if aid is None:
                    aid = self.game.draw("block_validation")
            except GameError as e:
                err = str(e)
            if err is None:
                # same body as the site: idempotency key "block-<action_id>"
                ok, d = self.call("POST", "/game/blocks/validate/",
                                  {"idempotency_key": f"block-{aid}", "action_id": aid,
                                   "client_seed": secrets.token_hex(32)})
                if ok:
                    self.shielded_seq = warn.get("sequence")
                    self.log(f"{head} — 🛡 shield raised (block validated"
                             + (f", after {tries} tries)" if tries > 1 else ")"))
                    return
                err = f"validate: {d}"
            if "RATE_LIMITED" not in err:
                self.log(f"{head} — shield failed: {err}")
                return
            if time.time() + SHIELD_RETRY[1] >= deadline:
                self.log(f"{head} — shield failed: still RATE_LIMITED after {tries} tries, strike is landing")
                return
            time.sleep(random.uniform(*SHIELD_RETRY))

    # --- bus hunt ------------------------------------------------------------------------

    def bus_hunt(self):
        """Defend neighbours under attack. Returns True while defences are left today."""
        ok, h = self.call("GET", "/game/bus-hunt/")
        if not ok:
            self.report("hunt", f"bus hunt: {h}")
            self.next_hunt_at = time.time() + RECHECK
            return False
        if not h.get("ring"):
            self.report("hunt", "bus hunt: no slot on the shared board")
            self.next_hunt_at = time.time() + RECHECK
            return False

        recent = h.get("recent") or []
        if self.seen_recent is None:   # first look: don't re-report old results
            self.seen_recent = {r.get("action_id") for r in recent}
        for r in recent:
            if r.get("action_id") not in self.seen_recent:
                self.seen_recent.add(r.get("action_id"))
                share = _dec(r.get("my_share_e"), 0)
                if share and share > 0:
                    self.log(f"🎯 bus hunt: attack {r.get('outcome')}, my bounty +{share} E")

        daily = h.get("daily") or {}
        left = daily.get("remaining") or 0
        saves = (h.get("saves") or {}).get("count")
        self.report("hunt", f"bus hunt: defences left today {left}/{daily.get('limit')}, saves {saves}")
        if left <= 0:   # daily cap used: come back after the UTC reset
            self.next_hunt_at = (_ts(daily.get("resets_at")) or time.time() + RECHECK) + random.uniform(60, 300)
            return False

        for a in h.get("alarms") or []:
            if not (a.get("can_defend") and not a.get("defended_by_me") and not a.get("refusal")
                    and _left(a.get("due_at")) > 0):
                continue
            head = (f"🚨 neighbour under attack, lands in {int(_left(a.get('due_at')))}s, "
                    f"P {a.get('base_probability')}→{a.get('probability')}, {a.get('defenders')} defender(s)")
            if not self.act:
                self.log(head + " — check mode, not acting")
                continue
            ok, d = self.call("POST", "/game/bus-hunt/defend/", {"action_id": a["action_id"]})
            self.log(head + (" — ✅ defended" if ok else f" — defend failed: {d}"))
            if ok:
                left -= 1
            if left <= 0 or d == "DEFENCE_CAP_REACHED":
                break
        self.next_hunt_at = 0.0
        return True

    # --- loop ----------------------------------------------------------------------------

    def tick(self):
        """One pass. Returns seconds until the next one."""
        now = time.time()
        econ_due = self.economy_on and now >= self.next_econ_at
        if now >= self.next_state_at or econ_due:
            t = QuestTick(self.game.s)   # GET /game/state/
            self.level = t.level
            if t.level < self.min_level or not self.level_allowed(t.level):
                self.report("level", f"level {t.level}, below {self.min_level} — skipped" if t.level < self.min_level
                            else f"level {t.level} is off in config — skipped (no shield / bus hunt)")
                self.next_state_at = self.next_econ_at = self.next_hunt_at = now + RECHECK
                return RECHECK
            self.report("level", f"level {t.level}")
            if econ_due:
                self.economy(t)
            busy = self.sentinels(t.st) if self.sentinels_on else False
            self.next_state_at = now + (0 if busy else RECHECK)
            # the last wave was just beaten: don't wait for the next claim (can be hours away) —
            # come back right away for the re-tape-out / the next stage
            beaten = bool((t.st.get("sentinels") or {}).get("all_beaten"))
            if beaten and self.was_beaten is False and self.economy_on and not econ_due:
                self.next_econ_at = min(self.next_econ_at, time.time() + random.uniform(5, 30))
                self.log("all waves beaten — economy visit now (re-tape-out check)")
            self.was_beaten = beaten
        hunt = self.hunt_on and (self.level or 0) >= 3   # the bus hunt opens at level 3
        if hunt and time.time() >= self.next_hunt_at:
            self.bus_hunt()
        # poll fast while something may need us; otherwise sleep until the next planned check
        nxt = min(self.next_state_at, self.next_econ_at if self.economy_on else float("inf"),
                  self.next_hunt_at if hunt else float("inf"))
        if nxt <= time.time():
            return random.uniform(*POLL)
        return max(random.uniform(*POLL), min(RECHECK, nxt - time.time()))

    def run(self, stop):
        while not stop.is_set():
            try:
                if self.game is None:
                    self.connect()
                wait = self.tick()
                self.proxy_fails = 0
            except SessionLost as e:
                self.log(f"session lost ({e}) — logging in again")
                self.game, self.token, wait = None, "", 5
            except PROXY_FAIL_EXCEPTIONS as e:
                self.game = None
                if not internet_up():   # the machine is offline: not the proxy's fault, don't burn a spare
                    wait = NET_WAIT
                    self.log(f"no internet on this machine — waiting, proxy kept (re-check in {NET_WAIT}s)")
                else:
                    self.proxy_fails += 1
                    if self.proxy_fails >= PROXY_SWAP_AFTER and self.swap_proxy(
                            f"proxy dead ({self.proxy_fails} errors in a row: {type(e).__name__})"):
                        wait = 5
                    else:
                        wait = PROXY_RETRY if self.proxy_fails < PROXY_SWAP_AFTER else RETRY
                        self.log(f"proxy error {self.proxy_fails}/{PROXY_SWAP_AFTER} "
                                 f"({type(e).__name__}), retry in {wait}s")
            except Exception as e:
                lost = any(str(c) in str(e) for c in SESSION_LOST)   # e.g. GameError("state: NOT_AUTHENTICATED")
                self.game, wait = None, (5 if lost else RETRY)
                if lost:
                    self.token = ""
                self.log(f"error, retry in {wait}s: {e}")
            stop.wait(wait)

    def check(self):
        """--check: one read-only pass."""
        try:
            self.connect()
            self.tick()
        except Exception as e:
            self.log(f"error: {e}")


def main():
    store = AccountStore(ACCOUNTS_FILE)
    pool = ProxyPool(config.PROXY_FILE)
    accounts = [(seed, addr, proxy, token) for _, proxy, seed, addr, token in store.wallets()]
    picked = [(p, *accounts[p - 1]) for p in ACCOUNTS if 1 <= p <= len(accounts)]
    check = "--check" in sys.argv
    print(f"[*] Quest - {ACCOUNTS_FILE}: accounts {ACCOUNTS} | economy {'on' if ECONOMY else 'off'} "
          f"(super chip → {SUPER_CHIP_MAX}, components → {COMPONENT_MAX}, re-tape-out "
          f"{CHIPLET + ' from ' + qe(RETAPE_MIN_QE) + ' QE' if RETAPE else 'off'}) | "
          f"sentinels {'on' if SENTINELS else 'off'} | bus hunt {'on' if BUS_HUNT else 'off'}"
          + (" | CHECK MODE (read only)" if check else " | Ctrl+C to stop"))
    print(f"[*] {pool.remaining()} spare proxies in {config.PROXY_FILE} | proxy swapped after "
          f"{PROXY_SWAP_AFTER} errors in a row while the internet is up")
    marks = Marks(MARKS_FILE, write=not check)
    marked = [p for p, _, a, _, _ in picked if marks.accumulating(a)]
    print(f"[*] stages: prestige farming from {qe(RETAPE_MIN_QE)} QE; below it -> accumulation (components → "
          f"{COMPONENT_MAX}) until {qe(ACCUMULATE_UNTIL_QE)} | accumulating now: "
          f"{', '.join(f'#{p}' for p in marked) or 'none'} ({MARKS_FILE})")
    questers = [Quester(p, s, a, px, t, store, pool, marks, act=not check) for p, s, a, px, t in picked]
    if check:
        for q in questers:
            q.check()
        return
    stop = threading.Event()
    threads = []
    for q in questers:
        t = threading.Thread(target=q.run, args=(stop,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(random.uniform(1, 4))   # don't start all accounts in the same second
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        stop.set()
        for t in threads:
            t.join(timeout=10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
