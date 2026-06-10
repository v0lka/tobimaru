# Tobimaru WiFi Watchdog — Roadmap-спецификация

## Обзор

Документ определяет порядок разработки проекта Tobimaru, разбитый на независимые фазы. Каждая фаза содержит список задач с зависимостями, критерии готовности (Definition of Done) и оценку трудоёмкости. Фазы 0–5 составляют обязательную часть проекта, фазы 6–12 — необязательную (расширенную).

Оценка трудоёмкости указана в условных единицах: S (1–2 дня), M (3–5 дней), L (1–2 недели), XL (2–4 недели).

---

## Граф зависимостей между фазами

```
Phase 0: Foundation
    │
    ├──► Phase 1: Capture Engine ──────► Phase 2: Detection Engine
    │         │                                │
    │         │                                ▼
    │         └─────────────────────► Phase 3: State & Storage
    │                                          │
    │                                          ▼
    │                                   Phase 4: REST API & Dashboard
    │                                          │
    ├──► Phase 5: Cross-platform (macOS) ◄─────┘
    │
    │    ═══════════════════════ Обязательная часть завершена ═══════════════════
    │
    ├──► Phase 6: EAPOL/Handshake Analysis (зависит от 1, 2)
    ├──► Phase 7: Active Countermeasures (зависит от 1, 3)
    ├──► Phase 8: Internal Network Monitoring (зависит от 0, 3, 4)
    ├──► Phase 9: Behavioral Analytics (зависит от 3, 8)
    ├──► Phase 10: OpenWrt Integration (зависит от 0, 1, 3)
    ├──► Phase 11: Advanced Detection (зависит от 1, 2)
    └──► Phase 12: Дополнительные интерфейсы и интеграции (зависит от 3, 4)
```

---

## [DONE] ~~Фаза 0: Фундамент проекта~~

Инфраструктурная фаза — создание скелета проекта, CI/CD, инструментария разработчика.

### Задачи

| ID  | Задача                                                                   | Зависит от | Трудоёмкость |
| --- | ------------------------------------------------------------------------ | ---------- | ------------ |
| 0.1 | Инициализация Go-модуля, структура каталогов (cmd/, internal/, configs/) | —          | S            |
| 0.2 | Настройка линтера (golangci-lint) и форматирования                       | 0.1        | S            |
| 0.3 | CI pipeline: lint, test, build для Linux amd64/arm64 и macOS arm64/amd64 | 0.1, 0.2   | M            |
| 0.4 | Makefile / taskfile с целями build, test, lint, run                      | 0.1        | S            |
| 0.5 | Конфигурационная подсистема: загрузка YAML, валидация, defaults          | 0.1        | M            |
| 0.6 | Structured logging (slog): инициализация, уровни, формат вывода          | 0.1        | S            |
| 0.7 | Graceful shutdown: сигналы ОС, context cancellation, cleanup hooks       | 0.1        | S            |
| 0.8 | Версионирование бинарника: ldflags injection (version, commit, date)     | 0.3        | S            |

### Definition of Done

- `go build ./...` собирает бинарник для четырёх платформ без ошибок.
- `golangci-lint run` проходит без замечаний.
- CI pipeline проходит на push/PR.
- Конфигурация загружается из YAML с валидацией обязательных полей.
- Процесс корректно завершается по SIGINT/SIGTERM.

---

## [DONE] ~~Фаза 1: Capture Engine (захват трафика из эфира)~~

Ядро системы — работа с WiFi-адаптером в режиме мониторинга, захват и начальный парсинг 802.11 фреймов.

### Задачи

| ID  | Задача                                                                                                           | Зависит от | Трудоёмкость |
| --- | ---------------------------------------------------------------------------------------------------------------- | ---------- | ------------ |
| 1.1 | Platform abstraction layer: интерфейс MonitorModeManager                                                         | 0.1        | M            |
| 1.2 | Linux-реализация MonitorModeManager (iw через exec, netlink fallback)                                            | 1.1        | M            |
| 1.3 | AF_PACKET capture handle: открытие raw socket, BPF-фильтры                                                       | 1.2        | M            |
| 1.4 | Парсинг RadioTap + Dot11 headers через gopacket/layers                                                           | 1.3        | M            |
| 1.5 | Классификация фреймов: management (beacon, probe req/resp, auth, deauth, disassoc), control (CTS/RTS, ACK), data | 1.4        | M            |
| 1.6 | Channel hopping engine: горутина, стратегия (weighted dwell time на 1/6/11), конфигурируемые параметры           | 1.2        | M            |
| 1.7 | Packet pipeline: capture goroutine → parsed frame channel → consumer(s)                                          | 1.4, 1.5   | M            |
| 1.8 | Unit-тесты на основе pcap-файлов (подготовка тестовых captures)                                                  | 1.5        | M            |
| 1.9 | Поддержка 5 GHz: расширение channel hopping, DFS-каналы                                                          | 1.6        | M            |

### Definition of Done

- Агент переводит указанный интерфейс в monitor mode и возвращает в managed при остановке.
- Захватываются и корректно парсятся beacon, probe, deauth, disassoc фреймы.
- Channel hopping работает по конфигурируемой стратегии (2.4 + 5 GHz).
- Pipeline доставляет parsed frames потребителям через Go channels без потерь при типичной нагрузке.
- Покрытие тестами >= 70% для пакетов capture/ и parser/.

---

## Фаза 2: Detection Engine (движок обнаружения атак)

Реализация правил детектирования обязательных типов атак на основе потока parsed frames из Phase 1.

### Задачи

| ID         | Задача                                                                                    | Зависит от | Трудоёмкость |
| ---------- | ----------------------------------------------------------------------------------------- | ---------- | ------------ |
| 2.1 [DONE] | ~~Абстракция Rule: интерфейс детектора, lifecycle (init, process frame, emit alert)~~     | 1.7        | M            |
| 2.2 [DONE] | ~~Detection Engine: агрегатор правил, dispatch, приоритизация, deduplication~~            | 2.1        | M            |
| 2.3        | Правило: Deauthentication flood (скользящее окно, порог за период)                        | 2.1        | M            |
| 2.4        | Правило: Disassociation flood (аналогично deauth)                                         | 2.3        | S            |
| 2.5        | Правило: Evil Twin AP (дублирование SSID, несовпадение BSSID/channel/IE fingerprint)      | 2.1        | L            |
| 2.6        | Правило: Beacon flood (резкий рост уникальных BSSID за период)                            | 2.1        | M            |
| 2.7        | Правило: Unauthorized device (MAC не в whitelist, ассоциация с защищаемой AP)             | 2.1        | M            |
| 2.8 [DONE] | ~~Модель событий безопасности: severity levels (info/warning/critical), metadata schema~~ | 2.2        | S            |
| 2.9        | Тестирование: генераторы вредоносных pcap-файлов для каждого типа атаки                   | 2.3–2.7    | L            |

### Definition of Done

- Каждый обязательный тип атаки детектируется на тестовых pcap-данных с нулевым количеством false negatives.
- False positive rate на нормальном трафике (тестовый pcap) не превышает заданного порога.
- Каждое событие содержит: timestamp, тип, severity, MAC участников, канал, RSSI, метаданные.
- Правила конфигурируемы (пороги, окна) через конфигурационный файл.
- Покрытие тестами >= 80% для пакета detector/.

---

## [DONE] ~~Фаза 3: Network State & Storage (состояние сети и хранилище)~~

Построение и поддержание карты радиоокружения, управление whitelist/blacklist, persistent storage.

### Задачи

| ID  | Задача                                                                                    | Зависит от | Трудоёмкость |
| --- | ----------------------------------------------------------------------------------------- | ---------- | ------------ |
| 3.1 | Network State Engine: in-memory map AP (BSSID→AP info) и clients (MAC→client info)        | 1.7        | M            |
| 3.2 | Обновление state из потока parsed frames (beacon → update AP; probe resp → update client) | 3.1, 1.7   | M            |
| 3.3 | TTL и eviction: удаление stale AP/clients, не наблюдавшихся N минут                       | 3.1        | S            |
| 3.4 | Whitelist/blacklist engine: CRUD операции, auto-learning mode                             | 3.1        | M            |
| 3.5 | SQLite storage layer: схема таблиц (events, aps, clients, config)                         | 0.1        | M            |
| 3.6 | Repository pattern: интерфейс хранилища, SQLite-реализация                                | 3.5        | M            |
| 3.7 | Запись событий безопасности в storage (из Detection Engine)                               | 3.6, 2.8   | S            |
| 3.8 | Запись snapshot'ов состояния (AP list, client list) с ротацией                            | 3.6, 3.2   | M            |
| 3.9 | Auto-learning mode: таймер learning phase, автоматическое формирование whitelist          | 3.4, 3.2   | M            |

### Definition of Done

- Карта окружения строится и обновляется в реальном времени из потока фреймов.
- Stale-записи удаляются по TTL.
- Whitelist/blacklist поддерживают CRUD и auto-learning.
- SQLite-хранилище корректно инициализируется, мигрирует, записывает и читает данные.
- При перезапуске агента whitelist и конфигурация сохраняются, события восстанавливаются из БД.
- Покрытие тестами >= 70% для пакетов state/ и storage/.

---

## [DONE] Фаза 4: REST API и веб-дашборд

Предоставление данных через HTTP API и встроенный веб-интерфейс для мониторинга.

### Задачи

| ID   | Задача                                                                                            | Зависит от | Трудоёмкость |
| ---- | ------------------------------------------------------------------------------------------------- | ---------- | ------------ |
| 4.1  | HTTP-сервер: маршрутизация, middleware (auth, CORS, logging, recovery)                            | 0.1, 0.6   | M            |
| 4.2  | API endpoints: GET /api/aps, GET /api/clients, GET /api/events                                    | 3.6, 3.1   | M            |
| 4.3  | API endpoints: GET/PUT /api/config, GET/POST/DELETE /api/whitelist                                | 3.4, 0.5   | M            |
| 4.4  | API endpoint: GET /api/status (uptime, текущий канал, версия, capabilities платформы)             | 1.6, 0.8   | S            |
| 4.5  | Real-time обновления: SSE или WebSocket канал для событий и обновлений состояния                  | 4.2        | M            |
| 4.6  | Аутентификация и авторизация: user/admin роли, token-based или basic auth                         | 4.1        | M            |
| 4.7  | Веб-дашборд: фронтенд (SPA или серверный рендеринг), embed в бинарник через go:embed              | 4.2, 4.5   | XL           |
| 4.8  | Дашборд: страница карты окружения (список AP, клиентов, параметры, обновление в реальном времени) | 4.7        | L            |
| 4.9  | Дашборд: страница событий безопасности (лента, фильтры по типу/severity/времени)                  | 4.7        | L            |
| 4.10 | Дашборд: страница статистики (графики событий по типам, временные ряды)                           | 4.7        | L            |
| 4.11 | Дашборд: страница настроек (конфигурация агента, whitelist/blacklist, пороги)                     | 4.7        | M            |
| 4.12 | Дашборд: страница состояния агента (статус, uptime, capabilities)                                 | 4.7        | M            |

### Definition of Done

- REST API отвечает на все documented endpoints корректными данными.
- Real-time канал доставляет события в течение 1 секунды после детектирования.
- Дашборд отображает карту окружения, ленту событий, статистику и настройки.
- Авторизация корректно разграничивает доступ user/admin.
- Бинарник содержит встроенные статические ассеты (single binary deployment).
- Дашборд корректно работает в современных браузерах (Chrome, Firefox, Safari).

---

## [DONE] ~~Фаза 5: Кроссплатформенность (macOS)~~

Обеспечение работы агента на macOS в пассивном режиме с graceful degradation.

### Задачи

| ID  | Задача                                                                          | Зависит от | Трудоёмкость |
| --- | ------------------------------------------------------------------------------- | ---------- | ------------ |
| 5.1 | macOS-реализация MonitorModeManager (CoreWLAN/airport utility, ограничения)     | 1.1        | L            |
| 5.2 | macOS capture: BPF device (/dev/bpfN) или libpcap через CGO (build tag)         | 5.1        | L            |
| 5.3 | Platform capabilities API: runtime определение доступных возможностей           | 1.1, 5.1   | M            |
| 5.4 | Graceful degradation: отключение injection, адаптация channel hopping intervals | 5.3        | M            |
| 5.5 | Отображение ограничений платформы в API и дашборде                              | 5.3, 4.4   | S            |
| 5.6 | CI: macOS build и smoke-тесты                                                   | 0.3, 5.2   | M            |
| 5.7 | Документация: инструкция по настройке macOS (права BPF, SIP, ограничения)       | 5.1        | S            |

### Definition of Done

- Бинарник собирается и запускается на macOS arm64 и amd64.
- Агент корректно определяет ограничения macOS и адаптирует поведение.
- Monitor mode активируется (с ограничениями); fреймы захватываются и парсятся.
- Injection-функции отключены без ошибок.
- API /status корректно отражает capabilities macOS.
- macOS build проходит CI.

---

## ═══ ОБЯЗАТЕЛЬНАЯ ЧАСТЬ ЗАВЕРШЕНА ═══

Ниже — необязательные фазы, каждая из которых является самодостаточным расширением. Их можно реализовывать в произвольном порядке (с учётом указанных зависимостей).

---

## Фаза 6: EAPOL / Handshake Analysis (необязательная)

Детектирование атак на процесс аутентификации WPA.

**Зависимости:** Phase 1 (capture), Phase 2 (detection engine)

### Задачи

| ID  | Задача                                                              | Зависит от | Трудоёмкость |
| --- | ------------------------------------------------------------------- | ---------- | ------------ |
| 6.1 | Парсинг EAPOL-фреймов (4-way handshake messages 1–4)                | 1.5        | M            |
| 6.2 | Правило: WPA Handshake capture attempt (поток EAPOL после deauth)   | 6.1, 2.1   | M            |
| 6.3 | Правило: PMKID harvesting (msg1 от неизвестного клиента без msg2–4) | 6.1, 2.1   | M            |
| 6.4 | Корреляция: связывание deauth-событий с последующими EAPOL-потоками | 6.2, 2.3   | M            |
| 6.5 | Тестовые pcap-файлы для EAPOL-атак                                  | 6.2, 6.3   | M            |

### Definition of Done

- EAPOL-фреймы корректно парсятся и классифицируются.
- Обнаруживаются попытки захвата handshake и PMKID.
- Корреляция deauth+EAPOL повышает severity события.
- Покрытие тестами >= 70%.

---

## Фаза 7: Активное противодействие — Frame Injection (необязательная)

Отправка deauth-фреймов для отключения атакующих устройств. Только Linux.

**Зависимости:** Phase 1 (capture handle), Phase 3 (state — знать кого деаутентифицировать)

### Задачи

| ID  | Задача                                                                                      | Зависит от    | Трудоёмкость |
| --- | ------------------------------------------------------------------------------------------- | ------------- | ------------ |
| 7.1 | Интерфейс FrameInjector с platform-aware IsSupported()                                      | 1.1           | S            |
| 7.2 | Формирование deauth-фрейма: RadioTap + Dot11 header + reason code                           | 7.1           | M            |
| 7.3 | Linux-реализация: pcap.WritePacketData или raw socket injection                             | 7.2           | M            |
| 7.4 | Response Engine: логика принятия решений (когда и кого деаутентифицировать)                 | 7.3, 3.1, 2.2 | L            |
| 7.5 | Safeguards: rate limiting, scope ограничение (только защищаемый BSSID), opt-in конфигурация | 7.4           | M            |
| 7.6 | API endpoints: POST /api/deauth (ручной trigger), GET /api/responses (история)              | 7.4, 4.1      | M            |
| 7.7 | Дашборд: секция активного противодействия (enable/disable, история, manual trigger)         | 7.6, 4.7      | M            |
| 7.8 | Правовые disclaimers в UI и при включении                                                   | 7.7           | S            |

### Definition of Done

- Deauth-фреймы корректно формируются и отправляются на Linux.
- На macOS — FrameInjector.IsSupported() == false, никакой injection не происходит.
- Response Engine принимает решения на основе результатов Detection Engine.
- Rate limiting предотвращает злоупотребление.
- Функция отключена по умолчанию и требует явного opt-in.

---

## Фаза 8: Мониторинг внутренней сети (необязательная)

Наблюдение за трафиком внутри защищаемой сети через второй (managed) интерфейс или позицию на роутере.

**Зависимости:** Phase 0 (foundation), Phase 3 (state/storage), Phase 4 (API)

### Задачи

| ID   | Задача                                                                            | Зависит от         | Трудоёмкость |
| ---- | --------------------------------------------------------------------------------- | ------------------ | ------------ |
| 8.1  | LAN capture module: AF_PACKET на managed-интерфейсе (br-lan или wlan1)            | 0.1, 1.3           | M            |
| 8.2  | ARP-мониторинг: реестр MAC↔IP, обнаружение spoofing, gratuitous ARP anomalies     | 8.1                | M            |
| 8.3  | DHCP-мониторинг: парсинг Discover/Offer/Request/Ack, rogue DHCP detection         | 8.1                | M            |
| 8.4  | Пассивный DNS-мониторинг: захват и парсинг DNS queries/responses на порту 53      | 8.1                | M            |
| 8.5  | mDNS/SSDP/NetBIOS мониторинг: каталог сервисов per-device                         | 8.1                | M            |
| 8.6  | Device inventory: объединение данных ARP/DHCP/mDNS для построения карты устройств | 8.2, 8.3, 8.5      | M            |
| 8.7  | Flow analysis: conntrack polling (на роутере) или packet-based flow records       | 8.1                | L            |
| 8.8  | TLS metadata: парсинг ClientHello (SNI, JA3/JA4 fingerprint)                      | 8.1                | L            |
| 8.9  | Правила детектирования: ARP spoofing, rogue DHCP, DNS spoofing                    | 8.2, 8.3, 8.4, 2.1 | M            |
| 8.10 | API endpoints: GET /api/devices, GET /api/flows, GET /api/dns                     | 8.6, 8.7, 8.4, 4.1 | M            |
| 8.11 | Дашборд: страница внутренней сети (устройства, потоки, DNS-профиль)               | 8.10, 4.7          | L            |

### Definition of Done

- Агент захватывает и анализирует broadcast/multicast трафик на LAN-интерфейсе.
- ARP spoofing, rogue DHCP и DNS spoofing корректно обнаруживаются.
- Device inventory отображает все устройства с hostname, MAC, IP, vendor, сервисами.
- Flow analysis (где доступен) предоставляет данные о соединениях per-device.
- Данные доступны через API и отображаются в дашборде.

---

## Фаза 9: Поведенческая аналитика (необязательная)

Построение per-device baseline и обнаружение аномалий статистическими методами.

**Зависимости:** Phase 3 (storage для хранения профилей), Phase 8 (источники данных)

### Задачи

| ID   | Задача                                                                                      | Зависит от | Трудоёмкость |
| ---- | ------------------------------------------------------------------------------------------- | ---------- | ------------ |
| 9.1  | Per-device profile model: структура данных для baseline (endpoints, volumes, ports, timing) | 3.5, 8.6   | M            |
| 9.2  | Learning phase engine: сбор метрик в период обучения, EMA, стандартное отклонение           | 9.1        | L            |
| 9.3  | Anomaly: C2 beaconing (периодичность обращений, coefficient of variation, autocorrelation)  | 9.2, 8.7   | L            |
| 9.4  | Anomaly: DGA-домены (Shannon entropy, NXDOMAIN count, consonant/vowel ratio)                | 9.2, 8.4   | M            |
| 9.5  | Anomaly: DNS tunneling (длина subdomain, TXT-query volume, bytes-per-query)                 | 9.2, 8.4   | M            |
| 9.6  | Anomaly: внутреннее сканирование портов (уникальные dst-ports per src-dst pair)             | 9.2, 8.7   | M            |
| 9.7  | Anomaly: аномальный upload volume (Z-score vs baseline)                                     | 9.2, 8.7   | M            |
| 9.8  | Anomaly: новые внешние endpoints, протоколы, порты (отклонение от whitelist)                | 9.2, 8.7   | M            |
| 9.9  | Anomaly: ночная активность, IoT-устройство стало сканером                                   | 9.2, 8.6   | M            |
| 9.10 | Threat intelligence integration: загрузка публичных blocklists (abuse.ch, Feodo), matching  | 9.1        | M            |
| 9.11 | Adaptive baseline: EMA-обновление профиля после detection phase (медленная адаптация)       | 9.2        | M            |
| 9.12 | API endpoints: GET /api/devices/:mac/profile, GET /api/anomalies                            | 9.2, 4.1   | M            |
| 9.13 | Дашборд: визуализация профилей устройств и аномалий                                         | 9.12, 4.7  | L            |

### Definition of Done

- Per-device профили строятся в learning phase и хранятся в SQLite.
- Каждая категория аномалий (C2, DGA, tunneling, lateral movement, exfil) корректно обнаруживается на тестовых данных.
- Baseline адаптируется к изменениям поведения (EMA).
- Threat intelligence feeds загружаются и используются для matching.
- Покрытие тестами >= 70% для пакета analytics/.

---

## Фаза 10: Интеграция с OpenWrt (необязательная)

Адаптация агента для запуска на роутерах с OpenWrt. Максимальная видимость при минимальном потреблении ресурсов.

**Зависимости:** Phase 0 (foundation), Phase 1 (capture), Phase 3 (storage)

### Задачи

| ID    | Задача                                                                    | Зависит от       | Трудоёмкость |
| ----- | ------------------------------------------------------------------------- | ---------------- | ------------ |
| 10.1  | Cross-compilation: цели MIPS/MIPSle/ARM/ARM64 с CGO_ENABLED=0             | 0.3              | M            |
| 10.2  | Build tags для OpenWrt-специфичных оптимизаций (//go:build openwrt)       | 10.1             | S            |
| 10.3  | Procd init script: автозапуск, respawn, logging                           | 10.1             | S            |
| 10.4  | UCI config parser: чтение /etc/config/tobimaru                            | 0.5, 10.3        | M            |
| 10.5  | Conntrack integration: polling через netlink (github.com/ti-mo/conntrack) | 8.7              | M            |
| 10.6  | Dnsmasq integration: парсинг логов DNS-запросов и/или DHCP-lease файла    | 8.4              | M            |
| 10.7  | DHCP script hook: обработка add/del/old событий от dnsmasq                | 8.3              | M            |
| 10.8  | ubus integration: получение данных от hostapd (клиенты, RSSI, события)    | 10.3             | L            |
| 10.9  | Virtual monitor interface: создание mon0 параллельно с AP (iw dev add)    | 1.2              | M            |
| 10.10 | Resource optimization: ring buffers, sync.Pool, GOGC tuning, tmpfs for DB | 3.5              | M            |
| 10.11 | Binary size optimization: strip + UPX, build tags для minimal mode        | 10.1             | M            |
| 10.12 | OpenWrt package (ipk): Makefile для OpenWrt build system                  | 10.1, 10.3, 10.4 | L            |
| 10.13 | Документация: список поддерживаемых устройств, инструкция по установке    | 10.12            | M            |

### Definition of Done

- Бинарник собирается для MIPS/ARM/ARM64 с размером <= 6 MB после strip+UPX.
- Агент запускается на OpenWrt 23.05+ с RAM >= 128 MB, потребление <= 40 MB.
- Procd управляет жизненным циклом (start/stop/restart/enable).
- UCI-конфигурация корректно читается.
- Conntrack и dnsmasq интеграции предоставляют flow и DNS данные.
- ipk-пакет устанавливается через `opkg install`.

---

## Фаза 11: Расширенное детектирование (необязательная)

Обнаружение продвинутых атак: KARMA, Known Beacons, WPA downgrade.

**Зависимости:** Phase 1 (capture), Phase 2 (detection engine)

### Задачи

| ID   | Задача                                                                          | Зависит от | Трудоёмкость |
| ---- | ------------------------------------------------------------------------------- | ---------- | ------------ |
| 11.1 | Правило: KARMA attack (AP отвечает на probe request с произвольным SSID)        | 1.5, 2.1   | M            |
| 11.2 | Правило: Known Beacons attack (множество beacon от одного BSSID с разными SSID) | 1.5, 2.1   | M            |
| 11.3 | Правило: WPA downgrade (клиент инициирует WPA2 при наличии WPA3 на AP)          | 6.1, 2.1   | M            |
| 11.4 | Правило: CTS/RTS flood                                                          | 1.5, 2.1   | M            |
| 11.5 | Правило: Authentication flood (массовые auth-запросы)                           | 1.5, 2.1   | M            |
| 11.6 | Device fingerprinting: идентификация по probe request IE, OUI, поведению        | 1.5, 3.1   | L            |
| 11.7 | Тестовые pcap-файлы для расширенных атак                                        | 11.1–11.5  | M            |

### Definition of Done

- Каждый тип атаки детектируется на тестовых данных.
- Device fingerprinting корректно идентифицирует тип устройства (с точностью по OUI + behavioral patterns).
- Новые правила интегрированы в Detection Engine и отображаются в дашборде.
- Покрытие тестами >= 70%.

---

## Фаза 12: Дополнительные интерфейсы и интеграции (необязательная)

TUI, Telegram-оповещения, OpenAPI, распределённое зондирование.

**Зависимости:** Phase 3 (state), Phase 4 (API/dashboard)

### Задачи

| ID   | Задача                                                                           | Зависит от    | Трудоёмкость |
| ---- | -------------------------------------------------------------------------------- | ------------- | ------------ |
| 12.1 | TUI (Terminal User Interface): real-time отображение состояния (bubbletea/tview) | 3.1, 2.2      | L            |
| 12.2 | Telegram Bot: оповещения о событиях через Bot API                                | 2.8, 0.5      | M            |
| 12.3 | Webhook notifications: configurable HTTP callbacks                               | 2.8, 0.5      | M            |
| 12.4 | OpenAPI (Swagger) спецификация REST API                                          | 4.1–4.5       | M            |
| 12.5 | Distributed sensing: протокол агрегации данных от нескольких агентов             | 4.1, 3.6      | XL           |
| 12.6 | Systemd / launchd unit files: production-ready деплой                            | 0.7           | S            |
| 12.7 | Интеграционные тесты: end-to-end сценарии с эмулированным трафиком               | 2.9, 3.6, 4.2 | L            |

### Definition of Done

- TUI отображает карту окружения, события и статус в реальном времени.
- Telegram Bot отправляет оповещения по настроенным фильтрам severity.
- OpenAPI spec валидна и соответствует реальному API.
- Distributed sensing позволяет агрегировать данные >= 2 агентов на одном дашборде.
- Systemd unit обеспечивает autostart, watchdog, log rotation.

---

## Суммарная матрица трудоёмкости

| Фаза                         | Задач   | Оценка            | Характер       |
| ---------------------------- | ------- | ----------------- | -------------- |
| 0: Foundation                | 8       | M (3–5 дней)      | Обязательная   |
| 1: Capture Engine            | 9       | XL (2–4 недели)   | Обязательная   |
| 2: Detection Engine          | 9       | XL (2–4 недели)   | Обязательная   |
| 3: State & Storage           | 9       | L (1–2 недели)    | Обязательная   |
| 4: REST API & Dashboard      | 12      | XL (3–4 недели)   | Обязательная   |
| 5: Cross-platform            | 7       | L (1–2 недели)    | Обязательная   |
| **Обязательная часть итого** | **54**  | **~10–14 недель** | —              |
| 6: EAPOL Analysis            | 5       | L (1–2 недели)    | Необязательная |
| 7: Active Countermeasures    | 8       | L (1–2 недели)    | Необязательная |
| 8: Internal Monitoring       | 11      | XL (2–3 недели)   | Необязательная |
| 9: Behavioral Analytics      | 13      | XL (3–4 недели)   | Необязательная |
| 10: OpenWrt Integration      | 13      | XL (2–3 недели)   | Необязательная |
| 11: Advanced Detection       | 7       | L (1–2 недели)    | Необязательная |
| 12: Additional Interfaces    | 7       | XL (2–3 недели)   | Необязательная |
| **Полный проект итого**      | **118** | **~24–32 недели** | —              |

---

## Рекомендуемый порядок реализации необязательных фаз

Если реализовывать все необязательные фазы, оптимальный порядок (по соотношению ценность/зависимости):

1. **Phase 6** (EAPOL) — минимум зависимостей, естественное продолжение Phase 2.
2. **Phase 11** (Advanced Detection) — аналогично, расширяет Phase 2.
3. **Phase 8** (Internal Monitoring) — открывает путь к Phase 9.
4. **Phase 9** (Behavioral Analytics) — максимальная детектирующая ценность.
5. **Phase 7** (Active Countermeasures) — спорная с правовой точки зрения, но уникальная feature.
6. **Phase 10** (OpenWrt) — отдельная ветка, может идти параллельно с 6–9.
7. **Phase 12** (Additional) — финальная полировка и integrations.

---

## Параллелизация

Следующие фазы могут разрабатываться параллельно (разными разработчиками или в разных ветках):

- **Phase 1 + Phase 3** (после 0): capture и storage не зависят друг от друга на начальном этапе.
- **Phase 5** может идти параллельно с Phase 4 (если macOS-специфичный код изолирован).
- **Phase 6 + Phase 11**: оба расширяют detection engine, но не пересекаются.
- **Phase 8 + Phase 10**: internal monitoring и OpenWrt интеграция разделяют capture layer, но реализации независимы.
- **Phase 7** полностью независима от Phase 8/9/10/11/12.

---

## Milestones

| Milestone       | Фазы      | Результат                                         |
| --------------- | --------- | ------------------------------------------------- |
| **Alpha**       | 0 + 1 + 2 | Агент детектирует атаки в эфире, выводит в CLI    |
| **Beta**        | + 3 + 4   | Полнофункциональный агент с web-дашбордом (Linux) |
| **Release 1.0** | + 5       | Кроссплатформенный релиз (Linux + macOS)          |
| **Release 1.1** | + 6 + 11  | Расширенное покрытие атак                         |
| **Release 1.2** | + 8       | Мониторинг внутренней сети                        |
| **Release 2.0** | + 9       | Поведенческая аналитика                           |
| **Release 2.1** | + 7 + 10  | Активное противодействие + OpenWrt                |
| **Release 3.0** | + 12      | Полный feature set                                |
