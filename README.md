# CHECKER — Fortinet / FortiGate Control Panel

> **Автор:** 1337or420 Team · **Сайт:** [storona.shop](https://storona.shop)

> ⚠️ **Предупреждение / Disclaimer:** Этот чекер сделан **исключительно для ознакомления** с разными видами брутфорс- и эксплоит-атак в автоматическом режиме. Проект создан при помощи ИИ. Не используйте его против чужих систем или сетей без явного письменного разрешения владельца. **Автор не несёт никакой ответственности** за любые убытки, ущерб или юридические последствия, связанные с использованием либо несанкционированным использованием этого проекта.

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
| **Сканер** | CIDR / диапазоны / мультипорт, TCP-пречек, 6 пресетов сигнатур, случайная или «edge» (/24 .1/.2/.3/.254) выборка, сохранение всех открытых портов, отсев только доказанных декоев |
| **FastScan** | Свой массовый TCP-сканер в духе masscan/rustscan: пул connect, DNS-кэш, до 32 портов, limiter и heartbeat |
| **Фингерпринт** | Для каждого открытого порта определяется сайт/панель, заголовки, стек и язык (PHP/Python/Java/Node/Go…) |
| **Брутфорс** | Режимы `smart` / `combo` / `cross`, потоки + лимит на хост + RPS, стоп после N валидных, дефолтные словари |
| **Чекер** | Ревалидация пар и целей, статусы alive/dead/locked/2FA |
| **Эксплоиты** | CVE-2018-13379 (слив кред), CVE-2022-40684, XML-сниффинг, версионные эвристики |
| **ADRecon** | Интегрированный Go/Docker модуль: VPN-конфиги → воркеры → отчёты; импорт конфигов в цели панели |
| **Авто-цепочка** | Находки сканера автоматически уходят в брут и в слив кред (CVE-2018-13379) |
| **Гео / Источники** | 3 гео-провайдера с кэшем, скачивание CIDR стран (ipdeny + 3 зеркала) |
| **Результаты** | Экспорт TXT / CSV / JSON, папки по категориям `data/results/<type>/*.txt`, кнопка открытия папки |

## API

- `GET  /api/status` — состояние, счётчики, очередь
- `GET/POST/DELETE /api/targets` — цели (добавление, удаление, очистка)
- `POST /api/start` `{type: scan|fastscan|brute|check|exploit|harvest|adrecon, ...}`
- `POST /api/pause` / `POST /api/stop`
- `GET  /api/results`, `POST /api/results/clear`
- `GET  /api/results/text?type=brute`, `GET /api/results/browse`, `POST /api/results/open-folder`
- `GET  /api/export?type=brute&format=txt|csv|json`
- `GET  /api/found[?format=txt|csv]`, `DELETE /api/found`
- `GET/POST /api/settings` (прокси, RPS, параллельность, авто-брут)
- `GET/POST /api/wordlists` (пользовательские словари)
- `GET/POST /api/adrecon` (инфо, `build`, `import` VPN-конфигов); задача `type:'adrecon'`
- `POST /api/exploits`, `GET /api/exploits`
- `POST /api/geo`, `POST /api/geo/refresh`, `GET /api/sources`, `POST /api/sources`, `GET /api/sources/load?cc=`
- `GET  /api/events` — SSE-поток событий

## Тесты

```
node tests/mock.test.js   # локальный FortiGate-мок: детект, брут, чек, слив кред
node tests/api.test.js    # smoke-тест REST API (нужен запущенный сервер на :7099)
node tests/ui.test.js     # smoke-тест UI (DOM-заглушка, обработчики кнопок)
node tests/adrecon.test.js # парсер VPN-конфигов и статус модуля ADRecon
node tests/stop.test.js    # кнопка Stop: мгновенный SSE task_state
node tests/scan.test.js    # CIDR-скан: прогресс и завершение задачи
node tests/fastscan.test.js # быстрый TCP-сканер: открытый/закрытый порт
node tests/websession.test.js # парсер sslvpn_websession (61-байтовые записи)
node tests/fingerprint.test.js # определение панели/стека/языка по открытому порту
node tests/results.test.js  # папки результатов по категориям, txt, очистка
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
│   ├── adrecon.js          # обёртка над Go/Docker модулем
│   └── fastscan.js         # свой массовый TCP-сканер
├── adrecon/                # ADRecon (Go orchestrator + scripts)
├── public/                # панель
├── data/                  # targets, results, found, geo, settings, sources
└── start.bat
```

---

# CHECKER — English version

> **Author:** 1337or420 Team · **Website:** [storona.shop](https://storona.shop)

> ⚠️ **Disclaimer:** This checker is made **for educational purposes only** — to study different kinds of brute-force and exploit attacks in automated mode. The project was created with the help of AI. Do not use it against systems or networks you do not own or have explicit written permission to test. **The author assumes no liability whatsoever** for any damages, losses or legal consequences arising from the use or unauthorized use of this project.

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
| **Scanner** | CIDR / ranges / multi-port, TCP pre-check, 6 signature presets, random or edge (/24 .1/.2/.3/.254) sampling, all open ports saved, only proven decoys filtered out |
| **FastScan** | Own mass TCP scanner in the spirit of masscan/rustscan: connect pool, DNS cache, up to 32 ports, limiter and heartbeat |
| **Fingerprint** | Every open port is identified: site/panel, headers, tech stack and language (PHP/Python/Java/Node/Go...) |
| **Brute force** | `smart` / `combo` / `cross` modes, threads + per-host limit + RPS, stop after N hits, built-in wordlists |
| **Checker** | Re-validation of pairs and targets, alive/dead/locked/2FA states |
| **Exploits** | CVE-2018-13379 credential leak, CVE-2022-40684, XML recon, version heuristics |
| **ADRecon** | Integrated Go/Docker module: VPN configs -> workers -> reports; config import into checker targets |
| **Auto-chain** | Scanner hits go straight to brute force and CVE-2018-13379 harvesting |
| **Geo / Sources** | 3 geo providers with cache, country CIDR lists (ipdeny + 3 mirrors) |
| **Results** | TXT / CSV / JSON export, persistent `found_creds.txt` |

## API

- `GET  /api/status`
- `GET/POST/DELETE /api/targets`
- `POST /api/start` `{type: scan|fastscan|brute|check|exploit|harvest|adrecon, ...}`
- `POST /api/pause`, `POST /api/stop`
- `GET  /api/results`, `POST /api/results/clear`
- `GET  /api/results/text?type=brute`, `GET /api/results/browse`, `POST /api/results/open-folder`
- `GET  /api/export?type=brute&format=txt|csv|json`
- `GET  /api/found[?format=txt|csv]`, `DELETE /api/found`
- `GET/POST /api/settings`, `GET/POST /api/wordlists`
- `GET/POST /api/adrecon` (info, `build`, `import`), task `type:'adrecon'`
- `GET/POST /api/exploits`, `POST /api/geo`, `GET/POST /api/sources`
- `GET  /api/events` — SSE event stream

## Tests

```
node tests/mock.test.js   # local FortiGate mock: detect, brute, check, leak
node tests/api.test.js    # REST API smoke test (server must run on :7099)
node tests/ui.test.js     # UI runtime smoke test (DOM stub, inline handlers)
node tests/adrecon.test.js # ADRecon config parser and module info
node tests/stop.test.js    # Stop button: immediate SSE task_state
node tests/scan.test.js    # CIDR scan: progress events and completion
node tests/fastscan.test.js # fast TCP scanner: open/closed port
node tests/websession.test.js # sslvpn_websession parser (61-byte records)
node tests/fingerprint.test.js # panel/stack/language detection on open port
node tests/results.test.js  # per-category result folders, txt, clear
```

## Author

**1337or420 Team** — [storona.shop](https://storona.shop)

С ИИ можно прктически всё....
