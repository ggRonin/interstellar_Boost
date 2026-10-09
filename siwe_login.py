#!/usr/bin/env python3
"""
Interstellar SIWE Login
Authorizes a wallet from Boost.txt on interstellar.dachain.io using
Sign-In With Ethereum (nonce -> personal_sign -> verify), exactly mirroring
the flow captured from the live site's network tab.
"""

import sys
from datetime import datetime, timedelta, timezone

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

import cap
import config

Account.enable_unaudited_hdwallet_features()


def proxy_url(proxy: str) -> str:
    """Proxy from the files -> URL for requests. Accepted:
        user:pass@host:port              -> http://user:pass@host:port
        host:port:user:pass              -> http://user:pass@host:port
        user:pass:host:port              -> http://user:pass@host:port
        host:port                        -> http://host:port
        http:// / https:// / socks5:// / socks5h:// + any of the above (socks needs PySocks)"""
    p = proxy.strip()
    scheme, sep, rest = p.partition("://")
    if not sep:
        scheme, rest = "http", p
    if "@" not in rest:
        parts = rest.split(":")
        if len(parts) == 4:
            if parts[1].isdigit():                    # host:port:user:pass
                rest = f"{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            elif parts[3].isdigit():                  # user:pass:host:port
                rest = f"{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}"
    return f"{scheme.lower()}://{rest}"


class SiweSession:
    """Handles wallet derivation, proxy setup and the SIWE auth handshake."""

    def __init__(self, seed_phrase: str, expected_address: str, proxy: str = None, verbose: bool = True):
        self.seed_phrase = seed_phrase
        self.expected_address = expected_address
        self.proxy = proxy
        self.verbose = verbose
        self.session = requests.Session()
        self.account = None
        self.address = None

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def _derive_account(self):
        self.account = Account.from_mnemonic(
            self.seed_phrase,
            account_path=config.DERIVATION_PATH,
        )
        self.address = self.account.address
        if self.expected_address and self.address.lower() != self.expected_address.lower():
            self._log(f"  ⚠ Derived address {self.address} does not match "
                       f"expected {self.expected_address} — check DERIVATION_PATH")

    def _setup_session(self):
        if not self.proxy or self.proxy.strip().lower() == "noproxy":
            raise RuntimeError(
                "No proxy set for this wallet — refusing to run without a proxy."
            )
        url = proxy_url(self.proxy)
        proxies = {
            "http": url,
            "https": url,
        }
        self.session.proxies.update(proxies)
        self.session.headers.update(config.BROWSER_HEADERS)

    def _verify_proxy(self):
        """Confirm outbound traffic is actually routed through the proxy before touching the target.
        Deliberately lets the raw requests exception propagate (ProxyError/ConnectionError/Timeout)
        so callers like mass_login.py can detect a dead proxy and swap it — never falls back to a
        direct connection itself."""
        resp = self.session.get("https://api.ipify.org?format=json", timeout=config.API_TIMEOUT)
        resp.raise_for_status()
        exit_ip = resp.json().get("ip")
        self._log(f"  Proxy exit IP: {exit_ip}")

    def _get_nonce(self) -> tuple[str, str]:
        """(nonce, адрес для сообщения). Сервер возвращает и адрес — фронтенд подписывает именно его."""
        resp = self.session.post(
            config.NONCE_ENDPOINT,
            json={"signer": self.address},
            timeout=config.API_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"Nonce request failed: {data}")
        return data["data"]["nonce"], data["data"].get("account") or self.address

    def _build_message(self, nonce: str, address: str) -> str:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        issued_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        expiration = (now + timedelta(minutes=config.SIWE_EXPIRATION_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")

        message = (
            f"{config.SIWE_DOMAIN} wants you to sign in with your Ethereum account:\n"
            f"{address}\n"
            f"\n"
            f"{config.SIWE_STATEMENT}\n"
            f"\n"
            f"URI: {config.SIWE_URI}\n"
            f"Version: {config.SIWE_VERSION}\n"
            f"Chain ID: {config.SIWE_CHAIN_ID}\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {issued_at}\n"
            f"Expiration Time: {expiration}"
        )
        return message

    def _sign_message(self, message: str) -> str:
        signable = encode_defunct(text=message)
        signed = Account.sign_message(signable, private_key=self.account.key)
        return "0x" + signed.signature.hex().removeprefix("0x")

    def _verify_siwe(self, message: str, signature: str, captcha_token: str) -> dict:
        headers = {"X-Captcha-Token": captcha_token}
        csrf = self.session.cookies.get("csrftoken")
        if csrf:  # фронтенд шлёт X-CSRFToken во всех не-GET запросах, если кука есть
            headers["X-CSRFToken"] = csrf
        resp = self.session.post(
            config.SIWE_ENDPOINT,
            json={"message": message, "signature": signature},
            headers=headers,
            timeout=config.API_TIMEOUT,
        )
        try:
            data = resp.json()
        except ValueError:
            resp.raise_for_status()
            raise
        if resp.status_code not in (200, 201) or not data.get("success"):
            raise RuntimeError(f"SIWE verify failed ({resp.status_code}): {data}")
        return data["data"]

    def login(self) -> dict:
        self._derive_account()
        self._setup_session()

        self._log(f"  Wallet:  {self.address}")
        self._log(f"  Proxy:   {self.proxy}")

        self._verify_proxy()

        nonce, address = self._get_nonce()
        self._log(f"  Nonce:   {nonce}")

        message = self._build_message(nonce, address)
        signature = self._sign_message(message)
        self._log(f"  Signature: {signature[:20]}...")

        captcha_token = cap.solve(self.session)
        self._log("  Captcha: ok")

        result = self._verify_siwe(message, signature, captcha_token)
        user = result.get("user", {})
        self._log(f"  ✓ Logged in — user_id={user.get('id')} status={user.get('status')} "
                   f"created={result.get('created')}")

        return {
            "address": self.address,
            "user": user,
            "created": result.get("created"),
            "cookies": self.session.cookies.get_dict(),
        }

    def cookie_string(self) -> str:
        """Куки сессии как 'name=value; name=value' (хранится в Accounts.txt как токен аккаунта)."""
        return "; ".join(f"{c.name}={c.value}" for c in self.session.cookies
                         if config.SIWE_DOMAIN in (c.domain or config.SIWE_DOMAIN))

    def resume(self, token: str):
        """Продолжить сохранённую сессию вместо SIWE-входа (без капчи).
        Возвращает user из /auth/me/ или None, если сессия больше не действует."""
        self._derive_account()
        self._setup_session()
        self._verify_proxy()
        for part in token.split(";"):
            name, _, value = part.strip().partition("=")
            if name:
                self.session.cookies.set(name, value, domain=config.SIWE_DOMAIN)
        resp = self.session.get(config.ME_ENDPOINT, timeout=config.API_TIMEOUT)
        if resp.status_code in (401, 403):
            return None
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success") or not data.get("data"):
            return None
        user = data["data"].get("user") or {}   # /auth/me/: {"user": {...}, "qe_balance": ..., ...}
        self._log(f"  ✓ Session reused — user_id={user.get('id')}")
        return user
