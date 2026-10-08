"""Токен капчи Cap.js для interstellar.dachain.io — только запросами, без браузера.

Флоу тот же, что у виджета на сайте:
1. POST {CAP_ENDPOINT}challenge  -> token + задачи (hashwx proof-of-work и instrumentation)
2. задачи решает cap_solver.js в Node
3. POST {CAP_ENDPOINT}redeem     -> токен для заголовка X-Captcha-Token

Запросы идут той же requests-сессией аккаунта (тот же прокси и User-Agent), что и вход.

Скрипт instrumentation присылает сервер капчи, то есть это чужой код. Поэтому Node запускается
с --permission (читать можно только cap_env.js; файлы, дочерние процессы и воркеры закрыты)
и с пустым окружением.
"""

import base64
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

import config

HERE = Path(__file__).resolve().parent
SOLVER_JS = HERE / "cap_solver.js"
ENV_JS = HERE / "cap_env.js"

_wasm_lock = threading.Lock()
# решатель грузит процессор: одновременно не больше CAP_THREADS (0 — по числу ядер)
_solver_slots = threading.BoundedSemaphore(max(1, config.CAP_THREADS or os.cpu_count() or 1))
_wasm_b64 = None


class CaptchaError(RuntimeError):
    pass


def _cap_headers(session):
    """Заголовки fetch() виджета: запрос с interstellar.dachain.io на cap.dachain.tech (другой сайт)."""
    return {
        "Origin": config.BASE_URL,
        "Referer": f"{config.BASE_URL}/",
        "Accept": "*/*",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        # requests-сессия по умолчанию шлёт application/json; у пустого POST виджета его нет
        "Content-Type": None,
    }


def _hashwx_wasm(session):
    """hashwx.wasm сайта (base64), один раз на процесс."""
    global _wasm_b64
    with _wasm_lock:
        if _wasm_b64 is None:
            r = session.get(config.CAP_HASHWX_URL, timeout=config.API_TIMEOUT,
                            headers={"Accept": "*/*", "Sec-Fetch-Dest": "empty", "Content-Type": None})
            r.raise_for_status()
            if r.content[:4] != b"\0asm":
                raise CaptchaError("hashwx.wasm: ответ не похож на WebAssembly")
            _wasm_b64 = base64.b64encode(r.content).decode()
        return _wasm_b64


def _browser_env():
    """Отпечаток для instrumentation — тот же браузер, что в BROWSER_HEADERS."""
    h = config.BROWSER_HEADERS
    brands = re.findall(r'"([^"]+)";v="(\d+)"', h.get("Sec-CH-UA", ""))
    env = {"userAgent": h["User-Agent"]}
    if brands:
        env["brands"] = [[b, v] for b, v in brands]
    return env


def _sandbox_env():
    env = {}
    if os.name == "nt" and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def _run_solver(challenges, wasm_b64):
    node = shutil.which(config.CAP_NODE) or config.CAP_NODE
    payload = json.dumps({"challenges": challenges, "hashwx": wasm_b64, "env": _browser_env()})
    try:
        with _solver_slots:
            p = subprocess.run(
                [node, "--permission", f"--allow-fs-read={ENV_JS}", str(SOLVER_JS)],
                input=payload.encode(), capture_output=True, env=_sandbox_env(),
                timeout=config.CAP_SOLVE_TIMEOUT, cwd=str(HERE),
            )
    except FileNotFoundError as e:
        raise CaptchaError(f"не найден node ({config.CAP_NODE}): нужен Node.js >= 22.13") from e
    except subprocess.TimeoutExpired as e:
        raise CaptchaError(f"cap_solver.js: таймаут {config.CAP_SOLVE_TIMEOUT}s") from e
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip()
        if "bad option" in err and "--permission" in err:
            raise CaptchaError("нужен Node.js >= 22.13: решатель запускается только с --permission")
        raise CaptchaError(f"cap_solver.js: {err[-500:] or p.returncode}")
    try:
        return json.loads(p.stdout)["solutions"]
    except (ValueError, KeyError) as e:
        raise CaptchaError(f"cap_solver.js: не-JSON ответ {p.stdout[:120]!r}") from e


def _solve_once(session):
    headers = _cap_headers(session)
    r = session.post(config.CAP_ENDPOINT + "challenge", headers=headers, timeout=config.API_TIMEOUT)
    try:
        ch = r.json()
    except ValueError:
        r.raise_for_status()
        raise CaptchaError(f"challenge: не-JSON ответ (HTTP {r.status_code})")
    if ch.get("error") or not ch.get("token") or not isinstance(ch.get("challenges"), list):
        raise CaptchaError(f"challenge: {ch.get('error') or ch}")

    solutions = _run_solver(ch["challenges"], _hashwx_wasm(session))
    bad = [s for s in solutions if s.get("blocked") or s.get("timeout")]
    if bad:
        # виджет в этом случае тоже не получает токен; повторяем с новой задачей
        raise CaptchaError(f"instrumentation не пройдена: {bad[0]}")

    r = session.post(config.CAP_ENDPOINT + "redeem", timeout=config.API_TIMEOUT,
                     headers={**headers, "Content-Type": "application/json"},
                     data=json.dumps({"token": ch["token"], "solutions": solutions}))
    try:
        res = r.json()
    except ValueError:
        r.raise_for_status()
        raise CaptchaError(f"redeem: не-JSON ответ (HTTP {r.status_code})")
    if not res.get("success") or not res.get("token"):
        raise CaptchaError(f"redeem: {res.get('error') or res}")
    return res["token"]


def solve(session):
    """Получить токен капчи для X-Captcha-Token. Сетевые ошибки requests пробрасываются как есть
    (их ловит логика смены прокси), ошибки самой капчи — CaptchaError после CAP_ATTEMPTS попыток."""
    last = None
    for _ in range(max(1, config.CAP_ATTEMPTS)):
        try:
            return _solve_once(session)
        except CaptchaError as e:
            last = e
    raise last
