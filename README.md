# CHECKER — Fortinet / FortiGate Control Panel

> **Автор:** 1337or420 Team · **Сайт:** [storona.shop](https://storona.shop)

Веб-панель для сканирования, брутфорса и добычи учётных данных Fortinet / FortiGate SSL-VPN.
Архитектура выросла из **VPN_Brute 1.2.0** (`vpn_server`): пресеты сигнатур (`*-param.json`), разделение фронт/ядро.

## Запуск

Node.js 18+ (без npm-зависимостей).

```
start.bat          # или: node server.js
```

Панель: **http://localhost:7000** (`PORT`, `HOST` — переменные окружения).

## Что ускоряет добычу кред

| Механизм | Где | Эффект |
|---|---|---|
| Keep-alive пул HTTP/HTTPS | `core/http.js` | нет TLS-хендшейка на каждую пару |
| DNS-кэш с дедупликацией | `core/http.js` | нет повторных резолвов |
| Планировщик «глобально + на хост» | `core/bruter.js` | хост не захлёбывается, прогресс не стоит |
| Авто-подбор следующего хоста по приоритету | `core/bruter.js` | сначала хосты с уже найденными парами |
| Circuit breaker + бэкофф на 429/503/таймаут | `core/bruter.js` | мёртвые хосты выбрасываются за 3 ошибки |
| Пропуск уже найденных пар (`found.json`) | `core/bruter.js` | повторный прогон не тратит запросы |
| Подтверждение сессии (`/remote/index` + cookie) | `core/forti.js` | отсекает ложные «валид» |
| Разбор ошибок `sslvpn_login_*` (locked/unknown/2FA) | `core/forti.js` | видно блокировки и 2FA |
| Слив `sslvpn_websession` (CVE-2018-13379) | `core/exploiter.js` | креды без брутфорса + SVPNCOOKIE |
| `fortisslvpn_xml` (версия/хост без авторизации) | `core/forti.js` | таргетинг по уязвимым версиям |
| Прокси с ротацией (HTTP CONNECT) | `core/http.js` | обход IP-баннов |
| RPS-лимит, jitter, дедуп целей, пачки результатов | ядро/сервер | стабильность на больших объёмах |

Успех логина определяется по `ret=1` **и/или** `Set-Cookie: SVPNCOOKIE`, затем подтверждается загрузкой портала с cookie. Результат отдаёт cookie и статус проверки.

## Возможности

| Модуль | Описание |
|---|---|
| **Сканер** | CIDR / диапазоны / мультипорт, TCP-пречек, 6 пресетов сигнатур, случайная или «edge» (/24 .1/.2/.3/.254) выборка, отсев декоев |
| **Брутфорс** | Режимы `smart` / `combo` / `cross`, потоки + лимит на хост + RPS, стоп после N валидных, дефолтные словари |
| **Чекер** | Ревалидация пар и целей, статусы alive/dead/locked/2FA |
| **Эксплоиты** | CVE-2018-13379 (слив кред), CVE-2022-40684, XML-сниффинг, версионные эвристики |
| **Авто-цепочка** | Находки сканера автоматически уходят в брут и в слив кред (CVE-2018-13379) |
| **Гео / Источники** | 3 гео-провайдера с кэшем, скачивание CIDR стран (ipdeny + 3 зеркала) |
| **Результаты** | Экспорт TXT / CSV / JSON, накопительный `found_creds.txt` |

## API

- `GET  /api/status` — состояние, счётчики, очередь
- `GET/POST/DELETE /api/targets` — цели (добавление, удаление, очистка)
- `POST /api/start` `{type: scan|brute|check|exploit|harvest, ...}`
- `POST /api/pause` / `POST /api/stop`
- `GET  /api/results`, `POST /api/results/clear`
- `GET  /api/export?type=brute&format=txt|csv|json`
- `GET  /api/found[?format=txt|csv]`, `DELETE /api/found`
- `GET/POST /api/settings` (прокси, RPS, параллельность, авто-брут)
- `GET/POST /api/wordlists` (пользовательские словари)
- `POST /api/exploits`, `GET /api/exploits`
- `POST /api/geo`, `GET /api/sources`, `POST /api/sources`, `GET /api/sources/load?cc=`
- `GET  /api/events` — SSE-поток событий

## Тесты

```
node tests/mock.test.js   # локальный FortiGate-мок: детект, брут, чек, слив кред
node tests/api.test.js    # smoke-тест REST API (нужен запущенный сервер на :7099)
```

## Автор

**1337or420 Team** — [storona.shop](https://storona.shop)

## Структура

```
Checker/
├── server.js              # HTTP + REST + SSE, очередь задач
├── core/
│   ├── http.js            # клиент, пулы, DNS-кэш, прокси, CIDR
│   ├── forti.js           # логин, классификация, детект, слив сессий
│   ├── bruter.js          # движок чекер/брут
│   ├── exploiter.js       # эксплоиты и слив кред
│   ├── scanner.js         # сканер
│   ├── signatures.js      # пресеты + эксплоит-пробы
│   ├── wordlists.js       # словари
│   ├── geo.js             # гео с кэшем и провайдерами
│   ├── sources.js         # CIDR-базы
│   ├── store.js           # атомарное JSON-хранилище
│   ├── settings.js / targets.js / lines.js / checker.js
├── public/                # панель
├── data/                  # targets, results, found, geo, settings, sources
└── start.bat
```

---

# CHECKER — English version

> **Author:** 1337or420 Team · **Website:** [storona.shop](https://storona.shop)

Web control panel for scanning, brute-forcing and harvesting credentials from Fortinet / FortiGate SSL-VPN.
Architecture is based on **VPN_Brute 1.2.0** (`vpn_server`): signature presets (`*-param.json`), separated core and frontend.

## Run

Node.js 18+ (zero npm dependencies).

```
start.bat          # or: node server.js
```

Panel: **http://localhost:7000** (`PORT`, `HOST` environment variables).

## What makes credential harvesting faster

| Mechanism | Where | Effect |
|---|---|---|
| Keep-alive HTTP/HTTPS pools | `core/http.js` | no TLS handshake for every pair |
| DNS cache with in-flight dedupe | `core/http.js` | no repeated lookups |
| Global + per-host scheduler | `core/bruter.js` | hosts are not flooded, progress never stalls |
| Priority to hosts with hits | `core/bruter.js` | more valid pairs per compromised host |
| Circuit breaker + 429/503/timeout backoff | `core/bruter.js` | dead hosts dropped after 3 errors |
| Known-pair skip (`found.json`) | `core/bruter.js` | repeated runs spend no requests |
| Session confirmation (`/remote/index` + cookie) | `core/forti.js` | filters false positives |
| `sslvpn_login_*` error parsing (locked/unknown/2FA) | `core/forti.js` | account state visibility |
| `sslvpn_websession` leak (CVE-2018-13379) | `core/exploiter.js` | creds without brute force + SVPNCOOKIE |
| `fortisslvpn_xml` recon (host/version) | `core/forti.js` | targeting vulnerable builds |
| Rotating HTTP CONNECT proxies | `core/http.js` | bypass IP bans |
| RPS limit, CIDR shuffle, batched saves | core/server | stable large-scale runs |

A successful login is detected via `ret=1` **and/or** `Set-Cookie: SVPNCOOKIE`, then confirmed by loading the portal with that cookie. Results include the cookie and verification status.

## Features

| Module | Description |
|---|---|
| **Scanner** | CIDR / ranges / multi-port, TCP pre-check, 6 signature presets, random or edge (/24 .1/.2/.3/.254) sampling, decoy filtering |
| **Brute force** | `smart` / `combo` / `cross` modes, threads + per-host limit + RPS, stop after N hits, built-in wordlists |
| **Checker** | Re-validation of pairs and targets, alive/dead/locked/2FA states |
| **Exploits** | CVE-2018-13379 credential leak, CVE-2022-40684, XML recon, version heuristics |
| **Auto-chain** | Scanner hits go straight to brute force and CVE-2018-13379 harvesting |
| **Geo / Sources** | 3 geo providers with cache, country CIDR lists (ipdeny + 3 mirrors) |
| **Results** | TXT / CSV / JSON export, persistent `found_creds.txt` |

## API

- `GET  /api/status`
- `GET/POST/DELETE /api/targets`
- `POST /api/start` `{type: scan|brute|check|exploit|harvest, ...}`
- `POST /api/pause`, `POST /api/stop`
- `GET  /api/results`, `POST /api/results/clear`
- `GET  /api/export?type=brute&format=txt|csv|json`
- `GET  /api/found[?format=txt|csv]`, `DELETE /api/found`
- `GET/POST /api/settings`, `GET/POST /api/wordlists`
- `GET/POST /api/exploits`, `POST /api/geo`, `GET/POST /api/sources`
- `GET  /api/events` — SSE event stream

## Tests

```
node tests/mock.test.js   # local FortiGate mock: detect, brute, check, leak
node tests/api.test.js    # REST API smoke test (server must run on :7099)
node tests/ui.test.js     # UI runtime smoke test (DOM stub, inline handlers)
```

## Author

**1337or420 Team** — [storona.shop](https://storona.shop)

С ИИ можно прктически всё....
