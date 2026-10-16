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

# TLS/HTTP2-отпечаток настоящего Chrome (curl_cffi): JA4 t13d1516h2 вместо питоновского t13d1812h1.
# Самый новый профиль Chrome в curl_cffi; у Chrome TLS от версии к версии не меняется, поэтому
# User-Agent может быть новее профиля.
IMPERSONATE = "chrome150"

# Версия Chrome в User-Agent считается от даты: известный релиз + новая major каждые 4 недели.
CHROME_RELEASE = (144, "2026-01-13")
CHROME_LAG = [0, 0, 0, 1, 1, 2]       # на сколько версий аккаунт отстаёт от свежей (случайно, но постоянно)
EDGE_SHARE = 0.15                     # доля аккаунтов на Microsoft Edge, остальные — Google Chrome
LANGS = ["en-US,en;q=0.9", "en-US,en;q=0.9", "en-US,en;q=0.9", "en-GB,en-US;q=0.9,en;q=0.8",
         "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7", "uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6",
         "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
         "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"]

# fetch() фронтенда, общее для всех аккаунтов. User-Agent, Sec-CH-UA и Accept-Language у каждого
# аккаунта свои (siwe_login.browser), Accept-Encoding ставит curl_cffi, Content-Type и Origin
# добавляются только к запросам с телом (BODY_HEADERS).
BROWSER_HEADERS = {
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-CH-UA-Mobile": "?0",
    "Accept": "application/json",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": f"{BASE_URL}/",
    "Priority": "u=1, i",
}
BODY_HEADERS = {"Content-Type": "application/json", "Origin": BASE_URL}

# Порядок заголовков, как их шлёт Chrome (HTTP/2, fetch()).
HEADER_ORDER = [
    "content-length", "sec-ch-ua-platform", "x-csrftoken", "x-captcha-token", "user-agent", "sec-ch-ua",
    "content-type", "sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site", "sec-fetch-mode",
    "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority",
]

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

# Игра Chip Entropico (/game/, game.py): планировщик — у каждого аккаунта своё время следующего захода
GAME_SOURCE = 1        # 1 — Accounts.txt, 2 — Boost.txt, 3 — Wallet.txt (только кошельки с done: остальные не пущены в игру)
GAME_THREADS = 10      # сколько аккаунтов обрабатывать одновременно (остальные ждут своего времени)
GAME_UPGRADE = 1       # 1 — покупать улучшения, пока хватает QE
GAME_ENTROPY_AT_CHIP = 20   # до этого уровня качается только чип, потом entropy-модуль до максимума, потом чип дальше
GAME_QE_RESERVE = 0    # не тратить QE ниже этого остатка на балансе
GAME_TRIALS = 1        # испытания: Bus Guardian (чип 5), Private Key (чип 10), Firewall (чип 18), Attack (чип 25)
GAME_ATTACK = 1        # Attack: 3000 QE + ставка E; шанс 14% + 76% * (1 - e^(-E/200)), потолок 90%.
                       # Атакуем, как только откроется (чип 25) — уровень чипа в L2 не переносится, качать
                       # его выше 25 ради атаки незачем; модуль добиваем до максимума (он переносится).
                       # Проигрыш — кулдаун ~10 мин, бот повторяет атаку до победы. Победа ЗАВЕРШАЕТ уровень 1
                       # (чип «на пенсии», LEVEL_1_CLOSED): в L2 переносятся половина кэша, модуль и E;
                       # L2 открывается оплатой трона (30000 E + 0.0001 DACC).
GAME_ATTACK_ENTROPY = 1466  # ставка E на атаку: игра сама режет ставку на ~1466 E (там вероятность уже
                            # упирается в потолок 90%); больше = INVALID_ENTROPY. Ставка сгорает и при победе
GAME_MARGIN_SEC = 120  # запас к расчётному времени следующего захода (когда хватит на апгрейд, кулдауны)
GAME_L2_UPGRADE_JITTER = (1, 15)   # L2: случайный запас (мин) к моменту, когда накопится QE на апгрейд,
                                   # чтобы заходить за апгрейдом раньше клейма; не позже самого клейма
GAME_CLAIM_MARGIN = (10, 30)   # за сколько минут до заполнения кэша клеймить: случайно в этом диапазоне
                               # при каждом заходе (оба уровня) — чтобы время клейма не было одинаковым

# --- Уровень 2 (после оплаты трона): суперчип вместо чипа, блоки, компоненты ---
GAME_VALIDATE_BLOCK = 1     # L2: в момент клейма валидировать блок — щит от сетевых атак + ~1600 QE в кэш
                            # (стоит ~20 E; PoW решает сервер). Между клеймами блоки не трогаем
GAME_EXTRACTION = 1         # L2: перед апом суперчипа сжечь E на скидку (может скинуть цену апа)
GAME_EXTRACTION_TIER = "base"   # тир экстракции: base (10 E, ~10%), medium (25 E), high (50 E)
                            # На L2 апгрейды выбираются по лучшей окупаемости (прирост QE/с ÷ цена),
                            # форки не трогаем (палевно). Бот сам решает, что апать.
GAME_RETRY_MINUTES = 30     # через сколько повторить аккаунт после ошибки (прокси, вход, ...)
GAME_SCHEDULE_FILE = "game_schedule.json"   # когда какой аккаунт заходить (рестарт продолжает с него)

# Защита от обрыва интернета: прямой запрос (без прокси) проверяет связь самой машины. Если интернета
# нет — все прокси «мертвы» одинаково, поэтому бот паузится, а не жжёт пул запасных прокси. Если машина
# онлайн, а сдох один прокси — проверка проходит, и бот меняет только его, как обычно.
GAME_NET_CHECK = 1          # 0 — выключить проверку
GAME_NET_CHECK_HOSTS = [    # связь есть, если ответил любой; разные провайдеры — чтобы не было ложного оффлайна
    "https://www.gstatic.com/generate_204",
    "https://cloudflare.com/cdn-cgi/trace",
    "https://api.ipify.org",
]
GAME_NET_TIMEOUT = 6        # с на одну прямую проверку
GAME_NET_WAIT_SEC = 900     # как часто перепроверять связь, пока интернета нет (на паузе) — 15 минут

BOOST_FILE = "Boost.txt"
PROXY_FILE = "Proxy.txt"
CODES_FILE = "code.txt"   # Boost.py: неиспользованные launch-коды, по одному на строку
RESULTS_FILE = "login_results.jsonl"

MAX_PROXY_ATTEMPTS = 3  # original proxy + up to N-1 replacements before giving up on a wallet
