## Tobimaru WiFi Watchdog — Project Brief

### Концепция

Инструмент активной защиты домашней WiFi-сети, работающий в режиме мониторинга (monitor mode) на выделенном беспроводном интерфейсе. Система одновременно слушает эфир для обнаружения атак и подключается ко второму интерфейсу (или VLAN) защищаемой сети для анализа внутреннего трафика. При обнаружении злоумышленника — отправляет deauth-фреймы для его отключения от сети.

---

### Стек технологий

| Компонент | Рекомендация | Обоснование |
|-----------|-------------|-------------|
| **Язык** | Go 1.22+ | Concurrency-first, хорошо для потоковой обработки пакетов, кроссплатформенность |
| **Захват пакетов** | `github.com/gopacket/gopacket` + `pcap` | Де-факто стандарт в Go; поддержка Dot11, RadioTap, полный разбор 802.11 фреймов. Используется в bettercap |
| **802.11 фреймы** | `gopacket/layers` (Dot11, Dot11Mgmt, RadioTap) | Встроенная поддержка management/control/data frames |
| **Инъекция фреймов** | Raw socket / pcap injection через `pcap.WritePacketData()` | bettercap так и делает: формирует deauth-фрейм вручную и пишет через pcap handle |
| **Monitor mode** | `github.com/mdlayher/wifi` + вызовы `iw`/`iwconfig` через exec | Нет чистой Go-библиотеки для переключения режима; bettercap тоже вызывает системные утилиты |
| **Сеть (connected mode)** | `net` + `gopacket` на managed-интерфейсе | Для ARP-мониторинга, DNS-анализа, обнаружения spoofing изнутри сети |
| **Хранение состояния** | SQLite (`modernc.org/sqlite`) или BoltDB | Лёгкое embedded-хранилище для истории событий, whitelist/blacklist |
| **Конфигурация** | YAML (`gopkg.in/yaml.v3`) | Простой формат для конфига пользователя |
| **Логирование** | `log/slog` (stdlib) | Structured logging, встроен в Go 1.21+ |
| **UI/Оповещения** | REST API + WebSocket (опционально) | Для будущего веб-дашборда или мобильного приложения |
| **Целевая платформа** | Linux (Raspberry Pi, x86) | Monitor mode надёжно работает только на Linux; macOS — ограниченно |

---

### Архитектура (двухинтерфейсная)

```
┌─────────────────────────────────────────────────────┐
│                  Tobimaru Daemon                    │
├──────────────────┬──────────────────────────────────┤
│  wlan0 (monitor) │  wlan1 (managed, connected)      │
│  ─────────────── │  ──────────────────────────────  │
│  • Channel hop   │  • ARP table monitoring          │
│  • Sniff all     │  • DNS request analysis          │
│  • Frame inject  │  • Internal traffic baseline     │
│  • RadioTap meta │  • Device fingerprinting         │
└────────┬─────────┴────────────────┬─────────────────┘
         │                          │
         ▼                          ▼
┌─────────────────┐      ┌─────────────────────────┐
│  Detection      │      │  Network State Engine   │
│  Engine         │      │  (known devices, flows) │
└────────┬────────┘      └────────────┬────────────┘
         │                            │
         ▼                            ▼
┌──────────────────────────────────────────────────┐
│              Response Engine                     │
│  • Deauth attacker                               │
│  • Alert user                                    │
│  • Log event                                     │
│  • Auto-blacklist                                │
└──────────────────────────────────────────────────┘
```

---

### Атаки, которые можно детектировать и/или митигировать

#### 1. Management Frame Attacks (через monitor mode)

| Атака | Детектирование | Противодействие |
|-------|---------------|-----------------|
| **Deauthentication flood** | Счётчик deauth-фреймов за период; порог аномалии | Логирование, оповещение (PMF делает защиту на уровне AP) |
| **Disassociation flood** | Аналогично deauth | Оповещение |
| **Beacon flood** | Резкий рост числа уникальных BSSID | Оповещение, фильтрация по RSSI |
| **Evil Twin AP** | Дублирование SSID с другим BSSID или каналом; расхождение IE (Information Elements) | Deauth клиентов evil twin; оповещение |
| **KARMA / Known Beacons** | AP отвечает на probe-request с произвольным SSID | Deauth; blacklist BSSID |
| **Probe request tracking** | Мониторинг probe от защищаемых устройств | Оповещение о подозрительных probe responses |

#### 2. Authentication/Crypto Attacks

| Атака | Детектирование | Противодействие |
|-------|---------------|-----------------|
| **WPA handshake capture** | Аномальный поток EAPOL-фреймов; deauth перед хендшейком | Оповещение; blacklist MAC |
| **PMKID capture** | Аномальный первый EAPOL-фрейм от неизвестного клиента | Оповещение |
| **KRACK (Key Reinstallation)** | Повторная передача msg3 в 4-way handshake | Оповещение (фикс — на стороне firmware) |
| **Downgrade attack (WPA3→WPA2)** | Клиент начинает WPA2-ассоциацию когда AP поддерживает WPA3 | Deauth клиента на downgrade-попытке |

#### 3. Data-plane / In-network Attacks (через managed-интерфейс)

| Атака | Детектирование | Противодействие |
|-------|---------------|-----------------|
| **ARP spoofing** | Изменение ARP-таблицы; gratuitous ARP от неизвестных | Оповещение; опционально ARP-ответ с правильным MAC |
| **DNS spoofing** | DNS-ответы от не-шлюза; несовпадение с upstream | Оповещение |
| **Rogue DHCP** | DHCP-offer от неожиданного сервера | Оповещение; blacklist |
| **MAC flooding** | Аномальное количество новых MAC-адресов | Оповещение |
| **Unauthorized device** | Новое устройство в сети вне whitelist | Deauth; оповещение |

#### 4. Denial of Service

| Атака | Детектирование | Противодействие |
|-------|---------------|-----------------|
| **CTS/RTS flood** | Аномальный объём CTS/RTS фреймов | Оповещение |
| **Authentication flood** | Массовые auth-запросы к AP | Оповещение |
| **Channel interference** | Резкое падение SNR на рабочем канале | Оповещение (физическое — нельзя софтверно исправить) |

---

### Рекомендуемый список фич по приоритету

**MVP (Phase 1):**

1. Monitor-mode capture с channel hopping по 2.4 GHz (каналы 1–13)
2. Парсинг всех 802.11 management frames (beacon, probe req/resp, auth, deauth, disassoc)
3. Построение карты окружения: список AP (BSSID, SSID, channel, encryption, RSSI) и клиентов
4. Детектирование deauth/disassoc flood (сигнатурный метод)
5. Детектирование evil twin (дублирование SSID, расхождение fingerprint)
6. Активное противодействие: отправка deauth-фреймов атакующим устройствам
7. CLI-интерфейс с real-time выводом событий
8. Конфигурация через YAML (защищаемый SSID, whitelist MAC, пороги)

**Phase 2:**

9. Подключение к защищаемой сети (managed interface): ARP/DNS мониторинг
10. Обнаружение ARP spoofing и rogue DHCP
11. Device fingerprinting (по probe request IE, OUI, поведению)
12. Whitelist/blacklist с автообучением (первые N минут — learning mode)
13. Поддержка 5 GHz (каналы 36–165, DFS channels)
14. REST API для интеграции с внешними системами
15. Persistent storage (SQLite) для аудита и истории

**Phase 3:**

16. Обнаружение PMKID/EAPOL-атак
17. Обнаружение KARMA/Known Beacons атак
18. Обнаружение WPA downgrade
19. Поведенческая аналитика (baseline нормального трафика → аномалии)
20. Web-dashboard (React/HTMX)
21. Push-оповещения (Telegram, webhook)
22. Интеграция с systemd (запуск как сервис)

---

### Структура проекта (рекомендация)

```
tobimaru/
├── cmd/
│   └── tobimaru/          # main entry point
├── internal/
│   ├── capture/           # pcap handle, monitor mode setup, channel hopping
│   ├── parser/            # 802.11 frame parsing, event extraction
│   ├── detector/          # detection engine (rules + anomaly)
│   │   ├── deauth.go
│   │   ├── eviltwin.go
│   │   ├── arp.go
│   │   └── ...
│   ├── responder/         # active response (deauth injection, alerts)
│   ├── state/             # network state: AP map, client map, whitelist
│   ├── config/            # YAML config loader
│   └── api/               # REST/WebSocket API
├── configs/
│   └── tobimaru.yaml      # sample config
├── scripts/
│   └── setup-monitor.sh   # helper script for interface setup
├── go.mod
├── go.sum
└── README.md
```

---

### Ключевые технические решения

**Monitor mode:** Чистых Go-библиотек для переключения интерфейса в monitor mode нет. Придётся вызывать `iw dev wlan0 set type monitor` / `ip link set wlan0 up` через `os/exec`, как это делает bettercap. Альтернатива — использовать netlink напрямую через `github.com/mdlayher/netlink` + `github.com/mdlayher/wifi`.

**Channel hopping:** Отдельная горутина, переключающая канал каждые 200–500ms через `iw dev wlan0 set channel N`. Для повышения quality — задерживаться на каналах 1, 6, 11 (наиболее используемые в 2.4 GHz).

**Frame injection:** `pcap.WritePacketData(rawBytes)` на monitor-mode интерфейсе. Фрейм должен содержать RadioTap header + Dot11 header + deauth reason code. Bettercap формирует их вручную побайтово.

**Concurrency:** Горутина на capture-loop, горутина на channel-hop, горутина на detection-engine (получает parsed events через канал), горутина на responder. Общение через Go channels.

---

### Существующие проекты для вдохновения

| Проект | Язык | Что полезного |
|--------|------|---------------|
| **bettercap** | Go | Эталонная реализация WiFi capture/inject на Go; gopacket, monitor mode, deauth |
| **Kismet** | C++ | Зрелый WIDS, детектирование широкого спектра атак |
| **OpenWIPS-ng** | C | Open-source WIPS, атака-детектирование-ответ pipeline |
| **wifipumpkin3** | Python | Evil twin / rogue AP toolkit — полезно понять атакующую сторону |
| **airgeddon** | Bash | Обёртка над aircrack-ng suite — список атак для покрытия |

---

### Правовые замечания

Отправка deauth-фреймов в эфир может нарушать законодательство некоторых юрисдикций (ст. 272 УК РФ, FCC Part 15 в США). Проект должен:

- Чётко ограничивать scope действия защищаемой сетью (по BSSID)
- Документировать, что активное противодействие — ответственность пользователя
- Предоставить «passive-only» режим по умолчанию
- Активное противодействие включать только по явному opt-in в конфигурации

---

### Рекомендуемые научные работы

1. **"A Wireless Intrusion Detection System for 802.11 WPA3 Networks"** (Dalal et al., 2021) — описывает 9 атак на WPA3, предлагает signature-based IDS с открытым кодом. [arxiv.org/abs/2110.04259](https://arxiv.org/abs/2110.04259)

2. **"Stealth and Evasion in Rogue AP Attacks"** (2024) — анализ современных rogue AP и методов обхода детектирования. [arxiv.org/abs/2512.10470](https://arxiv.org/abs/2512.10470)

3. **"A Comprehensive Taxonomy of Wi-Fi Attacks"** (Vink, 2020) — полная классификация WiFi-атак для формирования покрытия. [cs.ru.nl](https://www.cs.ru.nl/masters-theses/2020/M_Vink___A_comprehensive_taxonomy_of_wifi_attacks.pdf)

4. **"On the Robustness of Wi-Fi Deauthentication Countermeasures"** — анализ эффективности различных контрмер против deauth. [researchgate.net](https://www.researchgate.net/publication/360628126)
