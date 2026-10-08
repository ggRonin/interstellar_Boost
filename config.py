"""Configuration for the interstellar.dachain.io SIWE login bot."""

BASE_URL = "https://interstellar.dachain.io"
API_BASE = f"{BASE_URL}/api/v1"

NONCE_ENDPOINT = f"{API_BASE}/auth/siwe/nonce/"
SIWE_ENDPOINT = f"{API_BASE}/auth/siwe/"
ME_ENDPOINT = f"{API_BASE}/auth/me/"

# Same derivation path used by the Dachain Boost tooling that generated Boost.txt.
DERIVATION_PATH = "m/44'/60'/0'/0/0"

# SIWE message parameters observed from the live site (DevTools capture).
SIWE_DOMAIN = "interstellar.dachain.io"
SIWE_URI = "https://interstellar.dachain.io"
SIWE_VERSION = "1"
SIWE_CHAIN_ID = 21892
SIWE_STATEMENT = "Sign in to Interstellar. Your wallet is your identity."
SIWE_EXPIRATION_MINUTES = 10

API_TIMEOUT = 20

# Капча Cap.js (cap.dachain.tech): нужна на POST /auth/siwe/ (заголовок X-Captcha-Token).
# Решается локально в Node (cap_solver.js), без браузера и без платных сервисов.
CAP_ENDPOINT = "https://cap.dachain.tech/74e539aa4f/"
CAP_HASHWX_URL = f"{BASE_URL}/cap/hashwx.wasm"
CAP_NODE = "node"            # нужен Node.js >= 22.13 (запуск с --permission)
CAP_SOLVE_TIMEOUT = 90       # с, на одно решение
CAP_ATTEMPTS = 2             # сколько раз пробовать получить токен

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/json",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Sec-CH-UA": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Priority": "u=1, i",
}

# Откуда брать кошельки:
#   1 — Accounts.txt (seed,прокси,сессия; новые кошельки дописываются из Wallet.txt)
#   2 — Boost.txt (JSON на строку: address, proxy, seed_phrase, ...); сессия и заменённый прокси
#       записываются обратно в ту же строку (поля "token" и "proxy")
SOURCE = 1
BOOST_FLUSH_SECONDS = 5   # Boost.txt большой: переписывается не чаще, чем раз в N секунд (и в конце)

# Многопоточность
NUM_THREADS = 50   # сколько аккаунтов обрабатывать одновременно (у каждого свой прокси)
CAP_THREADS = 0    # сколько капч решать одновременно (Node грузит CPU); 0 — по числу ядер процессора

# Что делать после входа (1 — включено, 0 — выключено)
OPEN_BOX = 0   # сколько ежедневных сундуков открыть за запуск (/crates/daily/open/, 150 QE каждый);
               # 0 — не открывать. Больше дневного лимита сайта (сейчас 3) и больше, чем хватает QE, не откроется
CHECKIN = 1    # ежедневный чек-ин (/checkin/, нужна капча) — только если сегодня ещё можно
QUESTS = 1     # разовые задания-ссылки (X/Discord/Telegram/сайт) + «открыть первый сундук»

BOOST_FILE = "Boost.txt"
PROXY_FILE = "Proxy.txt"
CODES_FILE = "code.txt"   # Boost.py: неиспользованные launch-коды, по одному на строку
RESULTS_FILE = "login_results.jsonl"

MAX_PROXY_ATTEMPTS = 3  # original proxy + up to N-1 replacements before giving up on a wallet
