#!/usr/bin/env python3
"""
Chip Entropico (https://interstellar.dachain.io/game/) for every account, as a scheduler.

The game is an idle one: the chip produces QE into a cache (capacity = 2 h of production), and a
claim (POST /game/cache/claim/) moves the cache into the account's qe_balance; upgrades are paid from
qe_balance. One visit ("tick") of an account:
  1. the cache is claimed GAME_CLAIM_BEFORE_FULL_MIN before it is full (anything above capacity is lost);
  2. trials (GAME_TRIALS): Bus Guardian (chip 5, coin flip, 60 s cooldown on a loss), Private Key
     mission (chip 10, unlocks the entropy module; its hacker steals 10% of the cache, so the cache is
     claimed first), Firewall (chip 18, after the guardian: an LCG seeded from the boot clock, solved
     like the site's "scan" button), Attack (chip 25, GAME_ATTACK: 3000 QE + staked E; a win ends Level 1,
     so it is tried only with the chip and the entropy module at max). All of them are one-time:
     only a lost try is repeated (guardian after 60 s, attack after 10 min, firewall at once);
  3. upgrades while qe_balance (minus GAME_QE_RESERVE) allows: the chip up to GAME_ENTROPY_AT_CHIP, then
     the entropy module to its max, then the chip to its max (level 2 items: the cheapest one).
     When the balance is short, the cache is claimed only if balance + cache pays the next upgrade;
  4. the time of the next visit is computed: when balance + cache will pay the next upgrade, or when
     that early claim is due, or when a cooldown / the E for the attack is over (+ GAME_MARGIN_SEC).
     Maxed items (chip 30, module 10) and finished trials cost no requests: such an account only
     comes back for the claim.
The next visit of every account is kept in GAME_SCHEDULE_FILE, so a restart goes on where it stopped;
GAME_THREADS accounts are handled at once, while the others wait for their time.

Wallets — config.GAME_SOURCE: 1 Accounts.txt, 2 Boost.txt, 3 Wallet.txt (only ",done" wallets).
Sessions and proxies as in Boost.py: the saved session is reused (no captcha), otherwise a SIWE login;
a dead proxy is replaced by the next one from Proxy.txt and written into the wallet's line.
The first game request asks for a human check: POST /game/session/ with a Cap.js captcha -> a game
session cookie for 12 h, saved with the account session.

Not automated: forks, blocks/shields, sentinel waves, network assault, thrones (on-chain DACC payment).
"""

import json
import math
import os
import random
import secrets
import sys
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from eth_account import Account

import cap
import config
from Boost import CAPTCHA_RETRIES, ProxyPool, WalletFile, with_session
from login_wallets import ACCOUNTS_FILE, WALLET_FILE, AccountStore, BoostStore, internet_up, write_lines

Account.enable_unaudited_hdwallet_features()

GAME_URL = f"{config.BASE_URL}/game/"
HUMAN_CHECK = "GAME_HUMAN_CHECK_REQUIRED"
MAX_PURCHASES = 500        # per tick, a guard against a loop on a broken state
MIN_WAIT = 60              # s, the shortest pause between two visits of an account
MAX_WAIT = 6 * 3600        # s, the longest one (nothing to wait for: re-check now and then)
FIREWALL_TRIES = 3

# Private Key mission: current step -> the step to send to /missions/private-key/advance/
MISSION_STEPS = {"none": "intro", "intro": "sequence", "sequence": "key", "key": "hacked", "hacked": "entropy"}

# Firewall: the site's LCG (glibc constants), seeded with booted_at in ms + 0..999 ms
LCG_A, LCG_C, LCG_MASK, LCG_OUT_MASK = 1103515245, 12345, 0xFFFFFFFF, 32767
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class GameError(RuntimeError):
    pass


def _dec(v, default=None):
    try:
        return Decimal(str(v))
    except (InvalidOperation, TypeError, ValueError):
        return default


def _ts(iso):
    """ISO time from the API -> unix seconds (None if missing/unparsable)."""
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (AttributeError, TypeError, ValueError):
        return None


def _left(iso):
    """Seconds until an ISO time from the API (0 if it is in the past or missing)."""
    t = _ts(iso)
    return max(0.0, t - time.time()) if t else 0.0


def _fmt_wait(sec):
    sec = int(sec)
    h, m = divmod(sec // 60, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{sec % 60:02d}s"


class Game:
    """Requests like the game frontend: CSRF on non-GET, human check (captcha) on demand."""

    def __init__(self, session):
        self.s = session

    def _send(self, method, path, body, extra=None):
        headers = {"Referer": GAME_URL}
        if method != "GET":
            headers["X-CSRFToken"] = self.s.cookies.get("csrftoken")
        headers.update(extra or {})
        r = self.s.request(method, f"{config.API_BASE}{path}", headers=headers, timeout=config.API_TIMEOUT,
                           json=body if method != "GET" else None)
        try:
            b = r.json()
        except ValueError:
            return r, None, r.status_code
        if r.headers.get("X-Launch-Phase-Gated") == "1":
            return r, None, "LAUNCH_PHASE_GATED"
        if r.status_code not in (200, 201) or not b.get("success"):
            return r, None, (b.get("error") or {}).get("code", r.status_code)
        return r, b.get("data") or {}, None

    def _human_check(self):
        """POST /game/session/ with a captcha; CAPTCHA_FAILED -> up to CAPTCHA_RETRIES more tries."""
        err = None
        for _ in range(CAPTCHA_RETRIES + 1):
            _, _, err = self._send("POST", "/game/session/", {}, {"X-Captcha-Token": cap.solve(self.s)})
            if err is None:
                return
            if err != "CAPTCHA_FAILED":
                break
        raise GameError(f"game session: {err}")

    def call(self, method, path, body=None):
        """Returns (ok, data | error code)."""
        r, data, err = self._send(method, path, body)
        if err == HUMAN_CHECK:
            self._human_check()
            r, data, err = self._send(method, path, body)
        elif r.status_code == 403 and method != "GET" and err not in ("NOT_AUTHENTICATED", "MODULE_DISABLED",
                                                                    "CAPTCHA_FAILED"):
            # stale CSRF token: the frontend refreshes it and repeats the request
            self.s.get(f"{config.API_BASE}/auth/csrf/", timeout=config.API_TIMEOUT)
            r, data, err = self._send(method, path, body)
        return (True, data) if err is None else (False, err)

    def action(self, path, **body):
        return self.call("POST", path, {"idempotency_key": str(uuid.uuid4()), **body})

    def draw(self, action):
        """Commitment of a verifiable draw -> its action_id (the client seed goes with the action)."""
        ok, d = self.call("POST", "/game/draws/", {"action": action})
        if not ok:
            raise GameError(f"draw {action}: {d}")
        return d["action_id"]

    def state(self):
        ok, st = self.call("GET", "/game/state/")
        if not ok:
            raise GameError(f"state: {st}")
        return st


class Tick:
    """One visit of an account: claim / trials / upgrades, then when to come back."""

    def __init__(self, session):
        self.game = Game(session)
        self.st = self.game.state()
        self.log = []
        self.waits = []          # (seconds, reason) candidates for the next visit
        self.claimed = Decimal(0)
        self.spent = Decimal(0)
        self.bought = {}
        # claim a random 10-30 min before the cache is full (L1; same figure for this whole visit)
        self.claim_margin_min = random.uniform(*config.GAME_CLAIM_MARGIN)
        # L2: claim at a random 85-95% of capacity ("within 5-15% of full"), same figure for the visit
        self.claim_pct = random.uniform(*config.GAME_CLAIM_PCT)
        self._extracted = False   # one discount extraction per visit (cooldown 120 s)

    # --- state helpers -------------------------------------------------------------------

    @property
    def level(self):
        return self.st.get("level") or 1

    def refresh(self):
        self.st = self.game.state()

    def merge(self, d):
        """Action responses carry the game state without qe_balance."""
        if isinstance(d, dict):
            self.st = {**self.st, **{k: v for k, v in d.items() if k != "qe_balance" or v is not None}}

    @property
    def balance(self):
        return _dec(self.st.get("qe_balance"), Decimal(0))

    @property
    def available(self):
        return self.balance - Decimal(config.GAME_QE_RESERVE)

    def cache(self):
        c = self.st.get("cache") or {}
        return (_dec(c.get("amount_exact_qe"), Decimal(0)), _dec(c.get("capacity_qe"), Decimal(0)),
                _dec(c.get("production_qe_per_sec"), Decimal(0)))

    def chip_level(self):
        return (self.st.get("chip") or {}).get("level") or 0

    def claim(self):
        amount, _, _ = self.cache()
        if amount < 1:
            return False
        ok, d = self.game.action("/game/cache/claim/")
        if not ok:
            if d != "CACHE_EMPTY":
                self.log.append(f"claim failed: {d}")
            return False
        self.claimed += amount.to_integral_value(rounding="ROUND_FLOOR")
        self.refresh()
        return True

    # --- trials --------------------------------------------------------------------------

    def bus_guardian(self):
        bg = self.st.get("bus_guardian") or {}
        if bg.get("status") not in ("ready", "cooldown"):
            return False
        if _left(bg.get("cooldown_until")) > 0:
            self.waits.append((_left(bg["cooldown_until"]), "guardian"))
            return False
        aid = self.game.draw("bus_guardian")
        ok, d = self.game.call("POST", "/game/trials/bus-guardian/",
                               {"action_id": aid, "client_seed": secrets.token_hex(32)})
        if not ok:
            self.log.append(f"guardian failed: {d}")
            return False
        self.merge(d)
        if "bus_guardian" not in d:
            self.refresh()
        bg = self.st.get("bus_guardian") or {}
        if bg.get("status") == "beaten":
            self.log.append("🛡 guardian passed")
            return True
        self.log.append("guardian lost")
        self.waits.append((_left(bg.get("cooldown_until")) or bg.get("cooldown_sec") or 60, "guardian"))
        return False

    def private_key(self):
        pk = self.st.get("private_key_mission") or {}
        if pk.get("status") not in ("available", "in_progress"):
            return False
        if pk.get("step") in ("none", "intro", "sequence", "key"):
            self.claim()   # the "hacked" step steals a share of the cache
        step = (self.st.get("private_key_mission") or {}).get("step")
        while step in MISSION_STEPS:
            ok, d = self.game.call("POST", "/game/missions/private-key/advance/", {"step": MISSION_STEPS[step]})
            if not ok:
                self.log.append(f"private key {step}: {d}")
                return False
            self.merge(d)
            new = (self.st.get("private_key_mission") or {}).get("step")
            if new == step:
                self.log.append(f"private key stuck at {step}")
                return False
            step = new
        if step != "entropy":
            return False
        aid = self.game.draw("private_key")
        ok, d = self.game.call("POST", "/game/missions/private-key/regenerate/",
                               {"action_id": aid, "client_seed": secrets.token_hex(32)})
        if not ok:
            self.log.append(f"private key regenerate: {d}")
            return False
        self.merge(d)
        pk = self.st.get("private_key_mission") or {}
        self.log.append(f"🔑 private key done (hacker took {pk.get('stolen_qe')}QE)")
        return True

    @staticmethod
    def solve_firewall(puzzle, predict):
        """As the site's scan: seed = booted_at in ms + 0..999, the first outputs must match."""
        booted = datetime.fromisoformat(puzzle["booted_at"].replace("Z", "+00:00"))
        base = (booted - EPOCH) // (datetime.resolution * 1000)   # ms, truncated like Date.parse
        shown = puzzle.get("outputs") or []
        for ms in range(1000):
            x, out = (base + ms) & LCG_MASK, []
            for _ in range(len(shown) + predict):
                x = (x * LCG_A + LCG_C) & LCG_MASK
                out.append((x >> 16) & LCG_OUT_MASK)
            if shown and out[:len(shown)] == shown:
                return out[len(shown):]
        return None

    def firewall(self):
        for _ in range(FIREWALL_TRIES):
            fw = self.st.get("firewall") or {}
            if fw.get("status") != "ready":
                return False
            if not fw.get("puzzle"):
                ok, d = self.game.call("POST", "/game/trials/firewall/boot/")
                if not ok:
                    self.log.append(f"firewall boot: {d}")
                    return False
                self.merge(d)
                if "firewall" not in d:
                    self.refresh()
                fw = self.st.get("firewall") or {}
                if not fw.get("puzzle"):
                    self.log.append("firewall: no puzzle after boot")
                    self.waits.append((MIN_WAIT, "firewall"))
                    return False
            prediction = self.solve_firewall(fw["puzzle"], fw.get("predict_outputs") or 3)
            if prediction is None:
                self.log.append("firewall: seed not found")
                return False
            ok, d = self.game.call("POST", "/game/trials/firewall/",
                                   {"puzzle": fw["puzzle"]["number"], "prediction": prediction})
            if not ok:
                if d == "FIREWALL_STALE_PUZZLE":
                    self.refresh()
                    continue
                self.log.append(f"firewall: {d}")
                return False
            self.merge(d)
            if (d.get("firewall_attempt") or {}).get("outcome") == "success" or \
                    (self.st.get("firewall") or {}).get("status") == "breached":
                self.log.append("🔥 firewall breached")
                return True
            self.refresh()   # wrong guess costs nothing: a new puzzle
        self.log.append("firewall: wrong guesses")
        self.waits.append((MIN_WAIT, "firewall"))
        return False

    def _attacking(self):
        """This L1 account should win the one-time Attack: it is enabled, not won yet, and the trial exists.
        The chip level does not carry into Level 2, so we attack as soon as it unlocks (chip 25) instead of
        maxing the chip first."""
        at = self.st.get("attack") or {}
        return (config.GAME_ATTACK and self.level < 2
                and not (self.st.get("victory") or {}).get("completed_at")
                and at.get("status") in ("locked", "ready", "cooldown"))

    def attack(self):
        at = self.st.get("attack") or {}
        if not config.GAME_ATTACK or at.get("status") not in ("ready", "cooldown"):
            return False
        # the entropy module carries into Level 2 (the chip does not): max it before winning, then attack
        ent = self.st.get("entropy") or {}
        if (ent.get("module_level") or 0) < (ent.get("max_level") or 0):
            return False
        if _left(at.get("cooldown_until")) > 0:
            self.waits.append((_left(at["cooldown_until"]), "attack"))   # lost: retry after the cooldown
            return False
        e_now = _dec(ent.get("amount_exact_e"), Decimal(0))
        # stake for the best odds: p = 14% + 76%*(1 - e^(-E/200)) caps at 90% near 2000 E — more is wasted,
        # since staked E is consumed on a win too (and would otherwise fuel Level 2 blocks)
        stake = min(_dec(config.GAME_ATTACK_ENTROPY, Decimal(2000)), e_now)
        if stake < 1:
            return False
        cost = _dec(at.get("cost_qe"), Decimal(0))
        if self.available < cost:
            amount, _, _ = self.cache()
            if self.available + amount.to_integral_value(rounding="ROUND_FLOOR") < cost:
                return False   # upgrades' wait covers the QE
        self.claim()   # a lost attack takes a share of the cache
        if self.available < cost:
            return False
        # the game caps the stake at the point it reaches ~90% (≈1466 E); a bigger one is INVALID_ENTROPY,
        # so step down until it is accepted
        ok, d = False, None
        for _ in range(5):
            try:
                body = {"entropy": int(stake)}
                if at.get("randomness") == "verifiable":
                    body.update(action_id=self.game.draw("central_attack"), client_seed=secrets.token_hex(32))
            except GameError as e:   # the verifiable-draw source hiccupped (e.g. many threads at once)
                d = str(e)
                break
            ok, d = self.game.action("/game/attack/", **body)
            if ok or d != "INVALID_ENTROPY" or stake <= 100:
                break
            stake = (stake * Decimal(7) / Decimal(10)).to_integral_value(rounding="ROUND_FLOOR")
        if not ok:
            self.log.append(f"attack failed: {d}")
            # transient randomness-source error: not a real block — retry in a few minutes, not next claim
            if "ENTROPY_SOURCE_UNAVAILABLE" in str(d):
                self.waits.append((random.uniform(120, 300), "attack retry"))
            return False
        self.refresh()
        at = self.st.get("attack") or {}
        last = at.get("last") or {}
        p = _dec(last.get("p"))
        self.log.append(f"⚔ attack {last.get('outcome') or at.get('status')}"
                        + (f" (p={float(p):.0%})" if p is not None else "")
                        + (f", cache lost {last['cache_lost']}" if last.get("outcome") == "lost" else ""))
        if at.get("status") == "cooldown":
            self.waits.append((_left(at.get("cooldown_until")) or 600, "attack"))
        return True

    def trials(self):
        if not config.GAME_TRIALS:
            return False
        did = False
        for trial in (self.bus_guardian, self.private_key, self.firewall, self.attack):
            try:
                did = trial() or did
            except GameError as e:
                self.log.append(str(e))
        return did

    # --- level 2: extraction, super chip -------------------------------------------------

    def extract(self, item):
        """Burn E for a discount on the next purchase of `item` (ready extraction only). The discount is
        random and expires in ~30 min, so it is done right before buying. Refreshes to see the new price."""
        if self.level < 2 or not config.GAME_EXTRACTION:
            return False
        ex = self.st.get("extraction") or {}
        if ex.get("status") != "ready":
            return False
        info = next((i for i in (ex.get("items") or []) if i.get("item") == item), None)
        if info is not None and not info.get("eligible"):
            return False   # part locked, or a discount for it is already waiting (reason "active")
        if any(a.get("item") == item for a in (ex.get("active") or [])):
            return False
        tier = config.GAME_EXTRACTION_TIER
        cost = next((_dec(t.get("cost_e")) for t in (ex.get("tiers") or []) if t.get("tier") == tier), None)
        e_now = _dec((self.st.get("entropy") or {}).get("amount_exact_e"), Decimal(0))
        if cost is None or e_now < cost:
            return False
        try:
            aid = self.game.draw("extraction")
        except GameError as e:
            self.log.append(f"extraction draw: {e}")
            return False
        ok, d = self.game.action("/game/extractions/", action_id=aid, client_seed=secrets.token_hex(32),
                                 item=item, tier=tier)
        if not ok:
            self.log.append(f"extraction: {d}")
            return False
        self.refresh()   # the discount changed next_cost_qe of the item
        return True

    def _level_of(self, name):
        if name == "super_chip":
            return (self.st.get("super_chip") or {}).get("level") or 0
        return ((self.st.get("components") or {}).get(name) or {}).get("level") or 0

    def _heat_per_level(self, name):
        """Heat a single level of `name` adds. Only the super chip, clock and validator run hot."""
        if name == "super_chip":
            return float(_dec((self.st.get("super_chip") or {}).get("heat_per_level"), Decimal(0)))
        eff = (((self.st.get("components") or {}).get(name) or {}).get("effect")) or {}
        return float(_dec(eff.get("heat_per_level"), Decimal(0)))

    def _heat_ok(self, name):
        """True if buying one level of `name` keeps heat under the limit. Above the limit production is
        halved, so a hot part is held back until the limit is raised (heatsink). Cool parts always pass."""
        add = self._heat_per_level(name)
        if add <= 0:
            return True
        h = self.st.get("heat") or {}
        limit = float(_dec(h.get("limit"), Decimal(0)))
        if limit <= 0:
            return True
        cur = float(_dec(h.get("heat"), Decimal(0)))
        return cur + add <= limit * config.GAME_HEAT_SAFETY

    PCIE_PARTS = ("super_chip", "capacitor", "power_line", "ram", "clock", "pcie_bus")
    PCIE_THRESHOLD = 5

    def _marginal_gain(self, name):
        """Extra QE/s one more level of `name` would add. 0 for upgrades that do not raise production
        (validator = cheaper blocks, entropy = E/s), so ROI never picks them.
        A part below PCIE's level-5 threshold also gets credit for the PCIE production it will unlock once
        it reaches 5 (amortized over the levels to get there), so the picker climbs cheap parts — e.g. RAM —
        to 5 when PCIE makes it worthwhile; without this the greedy ROI would never reach the threshold."""
        per = float(_dec((self.st.get("super_chip") or {}).get("prod_per_level_qe"), Decimal(50)))
        sc, pl = self._level_of("super_chip"), self._level_of("power_line")
        cap, clk, pcie = self._level_of("capacitor"), self._level_of("clock"), self._level_of("pcie_bus")
        # pcie: +3% per level for each part already at level >= 5
        parts5 = sum(1 for n in self.PCIE_PARTS if self._level_of(n) >= self.PCIE_THRESHOLD)
        sc_base = sc * per
        sc_prod = sc_base * (1 + 0.08 * pl)
        pct = 0.05 * cap + 0.05 * clk + 0.03 * pcie * parts5
        if name == "super_chip":
            gain = per * (1 + 0.08 * pl) * (1 + pct)
        elif name == "power_line":
            gain = sc_base * 0.08 * (1 + pct)
        elif name in ("capacitor", "clock"):
            gain = sc_prod * 0.05
        elif name == "pcie_bus":
            gain = sc_prod * 0.03 * parts5
        else:
            gain = 0.0
        # PCIE threshold look-ahead: bringing this part to level 5 adds +3%*pcie to every tick
        if (config.GAME_PCIE_LOOKAHEAD and pcie > 0 and name in self.PCIE_PARTS
                and self._level_of(name) < self.PCIE_THRESHOLD):
            gain += sc_prod * 0.03 * pcie / (self.PCIE_THRESHOLD - self._level_of(name))
        return gain

    def _target_roi(self, blocked):
        """Level 2: the upgrade with the best QE/s gained per QE spent. Super chip wins early (it is the
        base everything else multiplies); a component takes over once its %-bonus beats a chip level."""
        opts = {n: o for n, o in self.options().items() if n not in blocked}
        ranked, heat_blocked = [], False
        for name, (path, cost) in opts.items():
            gain = self._marginal_gain(name)
            if gain > 0 and cost > 0:
                if not self._heat_ok(name):
                    heat_blocked = True   # profitable but would overheat -> raise the limit first
                    continue
                ranked.append((gain / float(cost), name, path, cost))
        if ranked:
            _, name, path, cost = max(ranked)
            return (name, path, cost)
        # everything profitable is held back by heat: buy a heatsink to lift the limit, if it is offered
        if heat_blocked and "heatsink" in opts:
            return ("heatsink", *opts["heatsink"])
        return ("super_chip", *opts["super_chip"]) if "super_chip" in opts else None

    # --- upgrades ------------------------------------------------------------------------

    def options(self):
        """{name: (path, cost)} of every upgrade the state offers right now."""
        st, out = self.st, {}

        def add(name, path, item, level_key="level"):
            # next_cost_qe is the server's "buyable" signal (null = maxed/closed). On Level 3 the season
            # reopens components past their old max_level (level >= max_level) but keeps them buyable, so the
            # max_level guard would wrongly drop them — rely on next_cost_qe alone.
            cost = _dec(item.get("next_cost_qe"))
            if cost is not None:
                out[name] = (path, cost)

        # a won attack retires the Level 1 chip and module (LEVEL_1_CLOSED): nothing to buy until the throne
        if not (st.get("victory") or {}).get("completed_at"):
            add("chip", "/game/chip/purchase/", st.get("chip") or {})
            add("entropy", "/game/entropy-module/purchase/", st.get("entropy") or {}, "module_level")
        add("super_chip", "/game/super-chip/purchase/", st.get("super_chip") or {})
        for name, c in (st.get("components") or {}).items():
            if c.get("unlocked"):
                add(name, f"/game/components/{name}/purchase/", c)
        return out

    def target(self, blocked):
        """The next upgrade to buy. Returns (name, path, cost) or None.
        Level 2: best payback (ROI). Level 1: chip up to GAME_ENTROPY_AT_CHIP, entropy, chip, cheapest."""
        if self.level >= 2:
            return self._target_roi(blocked)
        opts = {n: o for n, o in self.options().items() if n not in blocked}
        if self._attacking():
            # the chip does not carry into Level 2: stop upgrading it once the attack is unlocked (chip 25),
            # keep only the entropy module (which does carry) — QE then just waits for the attack
            unlock = (self.st.get("attack") or {}).get("unlock_chip_level") or 25
            if self.chip_level() >= unlock:
                opts.pop("chip", None)
        if "chip" in opts and self.chip_level() < config.GAME_ENTROPY_AT_CHIP:
            return ("chip", *opts["chip"])
        for name in ("entropy", "chip"):
            if name in opts:
                return (name, *opts[name])
        if opts:
            name = min(opts, key=lambda n: opts[n][1])
            return (name, *opts[name])
        return None

    def upgrades(self):
        """Buy while QE allows; claim only when balance + cache pays the next upgrade.
        Returns the upgrade it stopped at (to wait for) or None."""
        blocked = set()
        for _ in range(MAX_PURCHASES):
            t = self.target(blocked)
            if t is None:
                return None
            name, path, cost = t
            # L2: one discount extraction on the part we're about to buy (whatever it is), right before
            # buying — lowers its price. Only when it's actually affordable this visit, so the discount is
            # not wasted (it expires ~30 min). Tier from config (high = best odds of a big discount).
            if self.level >= 2 and config.GAME_EXTRACTION and not self._extracted:
                amount, _, _ = self.cache()
                if self.available + amount.to_integral_value(rounding="ROUND_FLOOR") >= cost:
                    self._extracted = True
                    if self.extract(name):
                        continue   # re-evaluate with the discounted next_cost
            if self.available < cost:
                amount, _, _ = self.cache()
                if self.available + amount.to_integral_value(rounding="ROUND_FLOOR") < cost or not self.claim():
                    return t
                if self.available < cost:
                    return t
            ok, d = self.game.action(path)
            if not ok:
                if d == "INSUFFICIENT_QE":
                    self.refresh()
                    if self.available >= cost:   # the server still says no: leave it for this tick
                        blocked.add(name)
                    continue
                self.log.append(f"{name} upgrade failed: {d}")
                blocked.add(name)
                continue
            self.merge(d)
            self.st["qe_balance"] = str(self.balance - cost) if d.get("qe_balance") is None else d["qe_balance"]
            self.spent += cost
            self.bought[name] = self.bought.get(name, 0) + 1
        return None

    # --- the visit -----------------------------------------------------------------------

    def claim_level(self):
        """Cache amount from which it is claimed anyway. L2: a random 85-95% of capacity ("within 5-15% of
        full"). L1: claim_margin_min minutes before it is full."""
        _, capacity, prod = self.cache()
        if self.level >= 2:
            return capacity * Decimal(str(self.claim_pct))
        return max(Decimal(0), capacity - prod * Decimal(self.claim_margin_min) * 60)

    def run(self):
        # L2+ accounts just run the routine cycle: claim at the % threshold, then upgrades. Blocks/shields,
        # sentinel waves and the Network Assault are NOT automated — they are played by hand in the browser.
        amount, capacity, _ = self.cache()
        if capacity > 0 and amount >= self.claim_level():
            self.claim()
        waiting_for = None
        for _ in range(5):   # an upgrade may unlock a trial, a trial may unlock an upgrade
            did = self.trials() if self.level < 2 else False   # L1 trials only; L2 has no such trials
            before = sum(self.bought.values())
            waiting_for = self.upgrades() if config.GAME_UPGRADE else None
            if not did and sum(self.bought.values()) == before:
                break
        if self.bought:
            self.refresh()
        return self.plan(waiting_for)

    def plan(self, waiting_for):
        """Seconds until the next visit + why."""
        amount, capacity, prod = self.cache()
        waits = [(s + config.GAME_MARGIN_SEC, why) for s, why in self.waits]
        if prod > 0:
            claim_at = self.claim_level()
            why_claim = (f"claim at {self.claim_pct * 100:.0f}% full" if self.level >= 2
                         else f"claim {self.claim_margin_min:.0f}m before full")
            # the claim before the cache is full: no margin on top, better a bit early than full
            waits.append((max(0.0, float((claim_at - amount) / prod)), why_claim))
            if waiting_for:
                name, _, cost = waiting_for
                need = cost - self.available - amount
                if need <= claim_at - amount:   # reachable before the claim (min() below caps it at the claim)
                    # L2: come back for the upgrade a random 1-15 min after enough QE (sooner than the claim,
                    # so growth compounds faster); L1 keeps the fixed margin
                    margin = (random.uniform(*config.GAME_L2_UPGRADE_JITTER) * 60
                              if self.level >= 2 else config.GAME_MARGIN_SEC)
                    waits.append((max(0.0, float(need / prod)) + margin, f"{name} {cost}QE"))
        sec, why = min(waits, key=lambda w: w[0]) if waits else (MAX_WAIT, "nothing to do")
        return min(MAX_WAIT, max(MIN_WAIT, sec)), why

    def summary(self):
        _, _, prod = self.cache()
        if self.level >= 2:
            sc = self.st.get("super_chip") or {}
            ent = self.st.get("entropy") or {}
            if self.level >= 3:   # L3: super chip is maxed; heat and layers are what matters now
                h = self.st.get("heat") or {}
                lay = (self.st.get("chip_layers") or {}).get("layers")
                hot = " 🔥throttled" if h.get("throttled") else ""
                return (f"L3 ({prod.normalize()} QE/s) | heat {h.get('heat')}/{h.get('limit')}{hot} | "
                        f"layers {lay} | E {ent.get('amount_e')} | qe {self.st.get('qe_balance')}")
            return (f"L2 super {sc.get('level')}/{sc.get('max_level')} ({prod.normalize()} QE/s) | "
                    f"E {ent.get('amount_e')} | qe {self.st.get('qe_balance')}")
        vic = self.st.get("victory") or {}
        if vic.get("completed_at"):   # attack won, waiting for the throne: E/module are held in carry_over
            co = vic.get("carry_over") or {}
            return (f"L1 won → throne | carry E {co.get('entropy_e')} module {co.get('module_level')} "
                    f"cache {co.get('cache_qe')} | qe {self.st.get('qe_balance')}")
        chip, ent = self.st.get("chip") or {}, self.st.get("entropy") or {}
        return (f"chip {chip.get('level')}/{chip.get('max_level')} ({prod.normalize()} QE/s) | "
                f"E {ent.get('amount_e')} (module {ent.get('module_level')}/{ent.get('max_level')}) | "
                f"qe {self.st.get('qe_balance')}")


def skip_addresses(wallets):
    """Addresses the bot never touches (config.GAME_SKIP): 1-based file positions and/or address strings.
    Positions reveal nothing personal, so they are safe to keep in the committed config."""
    out = set()
    for it in config.GAME_SKIP:
        if isinstance(it, bool):
            continue
        if isinstance(it, int):
            if 1 <= it <= len(wallets):
                out.add(wallets[it - 1]["address"].lower())
        elif str(it).strip():
            out.add(str(it).strip().lower())
    return out


def game_job(siwe):
    t = Tick(siwe.session)
    wait_sec, why = t.run()
    parts = []
    if t.claimed:
        parts.append(f"💰 claimed {t.claimed}QE")
    if t.bought:
        parts.append("⬆ " + ", ".join(f"{n}+{k}" for n, k in t.bought.items()) + f" (-{t.spent}QE)")
    parts += t.log
    parts.append(t.summary())
    return {"wait": wait_sec, "why": why, "text": " | ".join(parts),
            "info": t.summary(), "claimed": t.claimed, "spent": t.spent}


# --- accounts and schedule -----------------------------------------------------------------

class StoreFile:
    """Accounts.txt / Boost.txt behind the WalletFile interface that Boost.with_session writes to."""

    def __init__(self, store):
        self.store = store
        self.rows = {}   # address -> wallet dict (the one handed out: next visits see the new session)

    def wallets(self):
        for _, proxy, seed, addr, token in self.store.wallets():
            key = Account.from_mnemonic(seed, account_path=config.DERIVATION_PATH).key.hex()
            self.rows[addr] = {"key": key, "address": addr, "proxy": proxy, "token": token}
        return list(self.rows.values())

    def set_field(self, addr, name, value):
        row = self.rows[addr]
        row[name] = value
        self.store.update(addr, row["proxy"], row["token"])

    def close(self):
        self.store.close()


def open_wallets():
    """config.GAME_SOURCE -> (wallet file, [wallet dicts], description)."""
    if config.GAME_SOURCE == 3:
        wf = WalletFile(WALLET_FILE)
        todo, done = wf.split()
        return wf, done, f"{WALLET_FILE}: {len(done)} done ({len(todo)} not registered skipped)"
    if config.GAME_SOURCE == 1:
        sf, name = StoreFile(AccountStore(ACCOUNTS_FILE)), ACCOUNTS_FILE
    elif config.GAME_SOURCE == 2:
        sf, name = StoreFile(BoostStore(config.BOOST_FILE)), config.BOOST_FILE
    else:
        raise SystemExit(f"[!] config.GAME_SOURCE must be 1, 2 or 3, got {config.GAME_SOURCE!r}")
    wallets = sf.wallets()
    skip = skip_addresses(wallets)
    if skip:
        kept = [w for w in wallets if w["address"].lower() not in skip]
        return sf, kept, f"{name}: {len(kept)} accounts ({len(wallets) - len(kept)} skipped — played by hand)"
    return sf, wallets, f"{name}: {len(wallets)} accounts"


class Schedule:
    """GAME_SCHEDULE_FILE: {address: {"next_at": unix time, "why": ..., "info": ...}}, rewritten atomically."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except ValueError:
                print(f"[!] {path} is broken: every account is due now")

    def due_at(self, addr):
        return (self.data.get(addr.lower()) or {}).get("next_at", 0)

    def set(self, addr, next_at, **info):
        with self.lock:
            self.data[addr.lower()] = {"next_at": next_at,
                                       "next": datetime.fromtimestamp(next_at).strftime("%Y-%m-%d %H:%M:%S"),
                                       **info}
            write_lines(self.path, [json.dumps(self.data, ensure_ascii=False, indent=1)])


def main():
    wallet_file, wallets, desc = open_wallets()
    pool = ProxyPool(config.PROXY_FILE)
    sched = Schedule(config.GAME_SCHEDULE_FILE)
    by_addr = {w["address"]: w for w in wallets}
    now = time.time()
    print(f"[*] Game - {desc} | {config.GAME_THREADS} threads | {pool.remaining()} spare proxies")
    print(f"[*] {sum(1 for a in by_addr if sched.due_at(a) <= now)} due now, schedule in "
          f"{config.GAME_SCHEDULE_FILE} | Ctrl+C to stop\n")

    stats = {"ticks": 0, "fail": 0, "claimed": Decimal(0), "spent": Decimal(0)}
    running = {}   # future -> address
    idle_note = 0
    net_trouble = False   # set when a worker reports the machine is offline (net_down)
    ex = ThreadPoolExecutor(max_workers=config.GAME_THREADS)
    try:
        while True:
            now = time.time()
            # only when a problem was signalled: confirm the connection before touching anything
            if net_trouble:
                if internet_up():
                    print(f"[{time.strftime('%H:%M:%S')}] [+] интернет вернулся — продолжаем")
                    net_trouble = False
                elif not running:
                    time.sleep(config.GAME_NET_WAIT_SEC)   # offline: re-check every GAME_NET_WAIT_SEC
                    continue
            free = config.GAME_THREADS - len(running)
            busy = set(running.values())
            due = sorted((sched.due_at(a), a) for a in by_addr if a not in busy and sched.due_at(a) <= now)
            if not net_trouble:   # offline: let the in-flight ones finish, start nothing new
                for _, addr in due[:free]:
                    running[ex.submit(with_session, game_job, by_addr[addr], pool, wallet_file)] = addr

            if not running:
                nxt = min((sched.due_at(a) for a in by_addr), default=now + 60)
                if time.time() - idle_note > 600 or nxt - now < 1:
                    print(f"[{time.strftime('%H:%M:%S')}] waiting: next account in {_fmt_wait(max(0, nxt - now))}")
                    idle_note = time.time()
                time.sleep(min(30.0, max(1.0, nxt - now)))
                continue

            done, _ = wait(list(running), timeout=5, return_when=FIRST_COMPLETED)
            for fut in done:
                addr = running.pop(fut)
                res = fut.result()
                stats["ticks"] += 1
                if res.get("ok"):
                    sec, why = res["wait"], res["why"]
                    stats["claimed"] += res["claimed"]
                    stats["spent"] += res["spent"]
                    text = f"{res['via']} | {res['text']}"
                    sched.set(addr, time.time() + sec, why=why, info=res["info"])
                elif res.get("net_down"):   # the machine is offline — not a real per-account error
                    if not net_trouble:
                        print(f"[{time.strftime('%H:%M:%S')}] [!] интернета нет — пауза, прокси не трогаем")
                    net_trouble = True
                    sec, why = 5, "net down"
                    text = res.get("error")
                    sched.set(addr, time.time() + sec, why=why)
                else:
                    stats["fail"] += 1
                    sec, why = config.GAME_RETRY_MINUTES * 60, "retry after error"
                    text = f"FAIL {res.get('error')}"
                    sched.set(addr, time.time() + sec, why=why, error=str(res.get("error"))[:300])
                print(f"[{time.strftime('%H:%M:%S')}] {addr} | {text} | next in {_fmt_wait(sec)} ({why})")
    except KeyboardInterrupt:
        print("\n[*] Stopping: finishing accounts already in progress...")
        ex.shutdown(wait=True, cancel_futures=True)
        raise
    finally:
        print(f"[*] visits: {stats['ticks']}  FAIL: {stats['fail']}  claimed: {stats['claimed']}QE  "
              f"spent on upgrades: {stats['spent']}QE  spare proxies left: {pool.remaining()}")
        if hasattr(wallet_file, "close"):
            wallet_file.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[*] Stopped (the schedule is saved: a restart goes on from it)")
        sys.exit(0)
