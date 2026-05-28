## Tobimaru WiFi Wathdog — Интеграция с OpenWrt

### Почему OpenWrt — идеальная платформа

OpenWrt — единственная позиция в домашней сети, которая даёт **полную видимость всего трафика** без дополнительных ухищрений. Роутер — это точка, через которую проходит каждый пакет каждого устройства (и внутрисетевой, и интернет-трафик). Это делает его оптимальным местом для размещения агента Tobimaru.

Преимущества позиции на роутере:

- Весь DNS-трафик (dnsmasq обрабатывает его локально).
- Все сетевые потоки (conntrack видит каждое соединение).
- ARP-таблица всех устройств (роутер является L3-шлюзом).
- DHCP-lease всех клиентов (роутер выдаёт адреса).
- Возможность создания виртуального monitor-интерфейса параллельно с работающим AP.
- Доступ к hostapd (данные об ассоциированных клиентах, уровень сигнала, скорость).

---

### Ресурсные ограничения

OpenWrt работает на устройствах с сильно ограниченными ресурсами. Это главное архитектурное ограничение.

| Класс устройства | RAM | Flash | CPU | Пример |
|---|---|---|---|---|
| Бюджетный | 64–128 MB | 8–16 MB | MIPS 580 MHz | TP-Link Archer C7 |
| Средний | 256 MB | 32–128 MB | ARM Cortex-A7 dual-core | Xiaomi Mi Router 4A Gigabit |
| Рекомендуемый (2025+) | 512 MB+ | 128 MB+ | ARM Cortex-A53 quad-core | Banana Pi BPI-R3, GL.iNet GL-MT6000 |
| x86/RPi | 1–8 GB | SD/SSD | x86_64 / ARM Cortex-A72 | PC Engines APU2, Raspberry Pi 4 |

**Рекомендация:** минимальные требования для Tobimaru — 128 MB RAM и 32 MB flash. Комфортная работа — 256 MB RAM и выше. На устройствах с 64 MB RAM запуск нецелесообразен.

---

### Подход 1: Статический Go-бинарник (основной)

Go компилируется в один статически слинкованный бинарник. Это идеально для OpenWrt — не нужны зависимости, shared libraries, runtime.

**Кросс-компиляция:**

```bash
# Для MIPS (старые роутеры: TP-Link, Netgear, Atheros SoC)
GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o tobimaru-mips ./cmd/tobimaru

# Для MIPS little-endian (MediaTek MT76xx)
GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o tobimaru-mipsle ./cmd/tobimaru

# Для ARM (новые роутеры: Qualcomm IPQ, MediaTek MT7981/MT7986)
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o tobimaru-arm ./cmd/tobimaru

# Для ARM64 (RPi 4, Banana Pi R3, GL.iNet MT6000)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o tobimaru-arm64 ./cmd/tobimaru
```

**Ключевые моменты:**

- `CGO_ENABLED=0` — критически важно. Отказ от CGO означает чистый Go-бинарник без привязки к musl/glibc. Но это исключает использование libpcap через CGO.
- `-ldflags="-s -w"` — strip debug info и DWARF, экономит 30–40% размера.
- `GOMIPS=softfloat` — обязательно для большинства MIPS-роутеров (нет FPU).
- Дополнительное сжатие через `upx --best` уменьшает бинарник ещё в 2–3 раза.

**Проблема libpcap:** gopacket/pcap требует CGO для привязки к libpcap. Варианты решения:

| Подход | Описание | Плюсы | Минусы |
|---|---|---|---|
| CGO + static musl libpcap | Собрать libpcap.a под musl, скомпилировать с CGO_ENABLED=1 и musl cross-compiler | Полная функциональность pcap | Сложная сборка; нужен musl toolchain |
| `gopacket/afpacket` (Linux only) | AF_PACKET socket — чистый Go, без CGO | Нет зависимости от libpcap; работает на всех Linux | Нет monitor mode через af_packet; только L2 capture на managed |
| Вызов `iw` + raw socket | Monitor mode через exec(`iw`), захват через raw AF_PACKET | Чистый Go; monitor mode работает | Менее удобно чем pcap handle |
| Hybrid: af_packet для LAN, exec tcpdump для monitor | Разделить capture: внутренний трафик через af_packet, эфир через pipe от tcpdump | Не нужен CGO; модульность | Зависимость от tcpdump на устройстве |

**Рекомендация:** для OpenWrt-деплоя использовать `afpacket` (для захвата на br-lan) + вызов `iw` для создания monitor-интерфейса и AF_PACKET на нём. Это позволяет оставить CGO_ENABLED=0 и получить чистый статический бинарник.

---

### Подход 2: OpenWrt-пакет (ipk)

Для удобной установки через opkg агент можно оформить как пакет.

**Структура пакета:**

```
package/tobimaru/
├── Makefile              # OpenWrt package Makefile
└── files/
    ├── tobimaru.init     # Procd init script (/etc/init.d/tobimaru)
    ├── tobimaru.config   # UCI config (/etc/config/tobimaru)
    └── tobimaru.hotplug  # Hotplug script (optional)
```

**Procd init script** (`/etc/init.d/tobimaru`):

```sh
#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/tobimaru --config /etc/config/tobimaru
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

**UCI-конфигурация** (`/etc/config/tobimaru`):

```
config tobimaru 'main'
    option enabled '1'
    option monitor_iface 'wlan0'
    option lan_iface 'br-lan'
    option protected_ssid 'HomeNetwork'
    option channel_hop_interval '300'
    option learning_mode '0'
    option api_port '8080'
    option api_bind '0.0.0.0'

config whitelist
    list mac 'AA:BB:CC:DD:EE:01'
    list mac 'AA:BB:CC:DD:EE:02'

config alerts
    option webhook_url 'https://hooks.example.com/tobimaru'
    option min_severity 'warning'
```

**Package Makefile** (упрощённый):

```makefile
include $(TOPDIR)/rules.mk

PKG_NAME:=tobimaru
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/tobimaru
  SECTION:=net
  CATEGORY:=Network
  TITLE:=WiFi network security monitor
  DEPENDS:=+iw +libpcap
  PKGARCH:=all
endef

define Package/tobimaru/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tobimaru $(1)/usr/bin/tobimaru
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/tobimaru.init $(1)/etc/init.d/tobimaru
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/tobimaru.config $(1)/etc/config/tobimaru
endef

$(eval $(call BuildPackage,tobimaru))
```

---

### Захват трафика на OpenWrt

#### Внутренний трафик (LAN)

На OpenWrt все LAN-порты и WiFi-клиенты объединены в мост `br-lan`. Захват на `br-lan` даёт видимость **всего внутрисетевого трафика**, включая:

- Трафик между клиентами (если не включён AP isolation).
- Трафик клиент → WAN (до NAT/маскарада на уровне netfilter).
- ARP, DHCP, mDNS, SSDP — весь broadcast/multicast.

```go
// Захват на br-lan через AF_PACKET
handle, err := afpacket.NewTPacket(afpacket.OptInterface("br-lan"))
```

**Conntrack как источник flow-данных.** На OpenWrt netfilter отслеживает все соединения. Вместо парсинга каждого пакета можно периодически опрашивать conntrack:

```go
// Через netlink: github.com/ti-mo/conntrack
conn, _ := conntrack.Dial(nil)
flows, _ := conn.Dump()
for _, flow := range flows {
    // src IP, dst IP, src port, dst port, bytes, packets, protocol, state
}
```

Это даёт метаданные о каждом активном соединении без необходимости захвата и парсинга пакетов — крайне экономно по ресурсам.

#### DNS-мониторинг

Два подхода:

**A. Парсинг логов dnsmasq.** Dnsmasq (DNS/DHCP-сервер OpenWrt) можно настроить на логирование всех запросов:

```
# /etc/config/dhcp
config dnsmasq
    option logqueries '1'
    option logfacility '/tmp/dnsmasq.log'
```

Агент читает лог (tail -f или inotify) и парсит строки вида:
```
query[A] suspicious-domain.xyz from 192.168.1.105
```

Плюсы: zero overhead на захват; dnsmasq уже работает. Минусы: формат лога — plain text, нет структурированных данных.

**B. Перехват DNS-пакетов на br-lan (порт 53).** Захват только UDP/TCP порт 53 через BPF-фильтр:

```go
filter := "udp port 53 or tcp port 53"
// gopacket BPF на AF_PACKET handle
```

Плюсы: полный парсинг DNS-пакета (включая ответы, TTL, NXDOMAIN). Минусы: чуть больше CPU.

**Рекомендация:** вариант B (перехват пакетов) — более надёжный и информативный. Overhead минимален при использовании BPF-фильтра.

#### Monitor mode (эфир)

На роутере с mac80211-драйвером (ath9k, ath10k, mt76) можно создать виртуальный monitor-интерфейс **параллельно с работающей AP:**

```bash
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
iw dev mon0 set channel 6
```

**Критически важно:** это работает одновременно с hostapd (AP продолжает обслуживать клиентов). Интерфейс `mon0` захватывает все 802.11 фреймы на том же канале, что и AP. Channel hopping здесь ограничен — переключение `mon0` на другой канал не влияет на AP, но пропускаются фреймы на рабочем канале AP.

**Стратегия:** основное наблюдение — на рабочем канале AP (без hopping). Периодические excursions на соседние каналы для обнаружения evil twin. Это оптимальный баланс для роутера.

---

### Интеграция с подсистемами OpenWrt

#### ubus (micro bus)

ubus — IPC-механизм OpenWrt. Через него можно получить:

```bash
# Список WiFi-клиентов от hostapd
ubus call hostapd.wlan0 get_clients

# Статус сетевого интерфейса
ubus call network.interface.lan status

# Информация о WiFi
ubus call network.wireless status
```

**Интеграция из Go:** ubus общается через Unix-socket JSON-RPC. Можно вызывать `ubus call` через exec или реализовать клиент по Unix-socket напрямую.

```go
// Простой вариант через exec
out, _ := exec.Command("ubus", "call", "hostapd.wlan0", "get_clients").Output()
var clients HostapdClients
json.Unmarshal(out, &clients)
```

**Что даёт ubus:**
- Список ассоциированных клиентов с RSSI, RX/TX rate, время ассоциации.
- Статус WiFi-радио (канал, ширина, мощность).
- Информация о DHCP-lease.
- Возможность подписки на события (client connect/disconnect).

#### UCI (Unified Configuration Interface)

Конфигурация Tobimaru хранится в `/etc/config/tobimaru` в формате UCI. Это позволяет:

- Управлять конфигурацией через LuCI (веб-интерфейс OpenWrt).
- Использовать `uci` CLI для скриптов и автоматизации.
- Единообразие с другими сервисами OpenWrt.

Для чтения UCI из Go — парсинг простой: формат key-value с секциями.

#### hostapd

Помимо ubus, hostapd предоставляет control socket (`/var/run/hostapd/wlan0`) с протоколом запрос-ответ. Через него можно:

- Получить список станций: `STA-FIRST`, `STA-NEXT`.
- Получить детали станции: `STA <mac>` (TX/RX bytes, signal, capabilities).
- Deauth клиента: `DEAUTHENTICATE <mac>` (для активного противодействия).
- Подписаться на события: `ATTACH` (connect/disconnect/auth events).

Это самый низкоуровневый и информативный интерфейс к AP.

---

### Оптимизация под ограниченные ресурсы

#### Размер бинарника

| Оптимизация | Эффект |
|---|---|
| `-ldflags="-s -w"` | -30–40% (strip symbols + DWARF) |
| `upx --best --lzma` | -60–70% дополнительно (runtime decompression) |
| Минимизация зависимостей | Каждый import тянет код; audit imports |
| Отказ от embed для web-assets | Отдельная директория `/www/tobimaru/` вместо embedded |
| Build tags для feature-gating | `//go:build !minimal` — отключить тяжёлые фичи |

Ориентир: чистый Go-бинарник с gopacket + HTTP-сервер + базовая логика — ~8–15 MB. После strip + upx — ~3–6 MB. Это помещается на устройства с 32 MB flash.

#### Потребление RAM

| Техника | Эффект |
|---|---|
| Ring buffer для событий (не бесконечный лог) | Фиксированное потребление памяти |
| Conntrack polling вместо full packet capture | Значительно меньше аллокаций |
| Пороги на размер state (max AP, max clients) | Предсказуемый memory footprint |
| `sync.Pool` для packet buffers | Снижение GC pressure |
| `GOGC=50` (aggressive GC) | Меньший heap за счёт чуть большего CPU |
| SQLite с WAL mode + periodic vacuum | Контролируемый размер БД на flash |

Ориентир: при 50 устройствах в сети, 10 AP в окружении — рабочее потребление должно быть 15–40 MB RAM.

#### Снижение нагрузки на flash (износ)

Flash-память роутеров (NOR/NAND) имеет ограниченное количество циклов записи.

- **БД событий — в tmpfs** (`/tmp/tobimaru.db`). При перезагрузке теряется, но для real-time мониторинга это приемлемо.
- **Persistent storage — для конфигурации и whitelist** (в `/etc/config/`, overlay, редкая запись).
- **Ротация логов** — syslog-ng / logread, не писать в файл на flash.
- **Опционально:** периодический flush критических событий на persistent storage (раз в час).

---

### Варианты деплоя

#### Вариант A: Прямая установка на OpenWrt

```
opkg install tobimaru_0.1.0_arm_cortex-a7.ipk
# или: scp tobimaru root@router:/usr/bin/ && chmod +x /usr/bin/tobimaru
uci set tobimaru.main.enabled='1'
uci set tobimaru.main.protected_ssid='MyHome'
uci commit tobimaru
/etc/init.d/tobimaru start
/etc/init.d/tobimaru enable
```

Плюсы: минимальный overhead, прямой доступ к интерфейсам.
Минусы: ограничения по ресурсам; обновление — ручной процесс.

#### Вариант B: Docker/LXC-контейнер на мощном роутере

На x86-роутерах и устройствах с 512 MB+ RAM можно использовать Docker (пакет `dockerd` доступен в OpenWrt):

```yaml
# docker-compose.yml
services:
  tobimaru:
    image: tobimaru:latest
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - /etc/config/tobimaru:/etc/tobimaru
```

Плюсы: изоляция, простое обновление.
Минусы: overhead Docker; только для мощных устройств.

#### Вариант C: Companion на Raspberry Pi, подключённый к OpenWrt

Если роутер слишком слаб, агент запускается на RPi, подключённом по Ethernet к LAN-порту роутера. OpenWrt настраивается на mirror трафика:

```bash
# На OpenWrt: зеркалирование через iptables TEE
iptables -t mangle -A PREROUTING -j TEE --gateway 192.168.1.250
iptables -t mangle -A POSTROUTING -j TEE --gateway 192.168.1.250
```

Или через tc mirred:
```bash
tc qdisc add dev br-lan ingress
tc filter add dev br-lan parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev eth0.99
```

Плюсы: неограниченные ресурсы на RPi; роутер не нагружен.
Минусы: нужен отдельный хост; настройка mirroring; задержки.

---

### Взаимодействие с dnsmasq

Dnsmasq — DNS/DHCP-сервер на OpenWrt. Интеграция с ним даёт:

**DHCP-leases** (`/tmp/dhcp.leases`):
```
1715600000 aa:bb:cc:dd:ee:01 192.168.1.101 iPhone-Vasya *
1715600000 aa:bb:cc:dd:ee:02 192.168.1.102 Samsung-TV *
```
Парсинг этого файла даёт mapping MAC → IP → hostname для всех устройств.

**DNS query log** (при `logqueries '1'`):
```
dnsmasq[1234]: query[A] evil-domain.xyz from 192.168.1.101
dnsmasq[1234]: reply evil-domain.xyz is NXDOMAIN
```

**DHCP script hook** (`dhcp-script` option в dnsmasq):
```
# /etc/config/dhcp
config dnsmasq
    option dhcpscript '/usr/lib/tobimaru/dhcp-hook.sh'
```
Скрипт вызывается при каждом DHCP-событии (add/del/old) с аргументами: action, MAC, IP, hostname. Это push-based уведомление о появлении/уходе устройств.

---

### Взаимодействие с LuCI (опционально)

LuCI — веб-интерфейс OpenWrt. Для глубокой интеграции можно создать LuCI-приложение:

```
/usr/lib/lua/luci/controller/tobimaru.lua   -- маршруты
/usr/lib/lua/luci/model/cbi/tobimaru.lua    -- формы конфигурации (UCI)
/usr/lib/lua/luci/view/tobimaru/            -- шаблоны
```

Однако это Lua-разработка с специфичным API. **Рекомендуемый альтернативный подход:** Tobimaru предоставляет собственный веб-дашборд на отдельном порту (`:8080`), а в LuCI добавляется только ссылка или iframe. Это проще в поддержке и не привязывает к LuCI API.

---

### Архитектурная схема на OpenWrt

```
┌─────────────────────────────── OpenWrt Router ────────────────────────────────┐
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │                        Tobimaru Agent                               │  │
│  ├─────────────────┬──────────────────┬──────────────────┬────────────────┤  │
│  │ Monitor Module  │  LAN Module      │  DNS Module      │  HTTP/API      │  │
│  │ (mon0 iface)    │  (br-lan)        │  (port 53 sniff  │  (dashboard)   │  │
│  │                 │                  │   or dnsmasq log) │                │  │
│  └────┬────────────┴────────┬─────────┴────────┬─────────┴───────┬────────┘  │
│       │                     │                  │                  │            │
│       ▼                     ▼                  ▼                  ▼            │
│  ┌─────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ mac80211│  │  Linux bridge    │  │   dnsmasq        │  │  :8080       │  │
│  │ wlan0   │  │  br-lan          │  │   (DNS/DHCP)     │  │  Web UI      │  │
│  │ + mon0  │  │  (all clients)   │  │                  │  │              │  │
│  └─────────┘  └──────────────────┘  └──────────────────┘  └──────────────┘  │
│       │                     │                  │                               │
│  ┌─────────┐  ┌──────────────────┐  ┌──────────────────┐                     │
│  │hostapd  │  │  conntrack       │  │  dhcp.leases     │                     │
│  │(AP mgmt)│  │  (flow table)    │  │  (device map)    │                     │
│  └─────────┘  └──────────────────┘  └──────────────────┘                     │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

### Минимальные требования к OpenWrt-устройству

| Параметр | Минимум | Рекомендуемо |
|---|---|---|
| RAM | 128 MB | 256 MB+ |
| Flash | 32 MB | 128 MB+ |
| WiFi-чипсет | mac80211-совместимый (ath9k, ath10k, mt76) | ath10k, mt76 (5 GHz + monitor) |
| CPU | MIPS 580 MHz / ARM Cortex-A7 | ARM Cortex-A53 quad-core |
| Ядро Linux | 5.4+ | 5.15+ (лучшая поддержка mac80211) |
| OpenWrt | 21.02+ | 23.05+ |

---

### Рекомендуемые устройства

| Устройство | CPU | RAM | Flash | WiFi | Цена (ориентир) |
|---|---|---|---|---|---|
| GL.iNet GL-MT6000 (Flint 2) | MT7986A quad-core 2 GHz | 1 GB | 8 GB eMMC | Wi-Fi 6, mt76 | ~$90 |
| Banana Pi BPI-R3 | MT7986A quad-core 2 GHz | 2 GB | 8 GB eMMC + SD | Wi-Fi 6, mt76 | ~$80 |
| Dynalink DL-WRX36 | IPQ8072A quad-core 2.2 GHz | 1 GB | 512 MB NAND | Wi-Fi 6, ath11k | ~$60 |
| Raspberry Pi 4 + USB WiFi | BCM2711 quad-core 1.8 GHz | 4/8 GB | SD card | Через USB-адаптер | ~$60 + adapter |
| x86 mini-PC (любой) | Intel N100 / AMD | 8 GB | SSD | Через USB/PCIe WiFi | ~$100+ |

---

### Итого: уровни интеграции

| Уровень | Что даёт | Сложность реализации |
|---|---|---|
| **L0: Просто бинарник на роутере** | Захват на br-lan, базовый мониторинг | Низкая — scp + запуск |
| **L1: + procd init + UCI config** | Автозапуск, конфигурация через UCI | Средняя — написать init script и UCI parser |
| **L2: + dnsmasq интеграция** | DNS-мониторинг, DHCP-события | Средняя — парсинг логов или hook-скрипт |
| **L3: + ubus/hostapd** | Данные о клиентах, RSSI, события connect/disconnect | Средняя — ubus call парсинг JSON |
| **L4: + monitor mode (mon0)** | Обнаружение атак в эфире | Высокая — виртуальный интерфейс + packet capture |
| **L5: + conntrack flow analysis** | Полный flow analysis без full capture | Средняя — netlink или polling conntrack |
| **L6: + LuCI integration** | GUI управления в стандартном интерфейсе роутера | Высокая — Lua/JS разработка |
| **L7: + ipk пакет** | Установка через opkg; чистая интеграция | Средняя — OpenWrt build system Makefile |

**Рекомендуемый MVP для OpenWrt:** L0 + L1 + L2 + L5 — даёт серьёзную видимость (все flows + все DNS + все DHCP) при минимальном overhead и без необходимости monitor mode.
