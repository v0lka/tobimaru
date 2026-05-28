## Tobimaru WiFi Watchdog — Проблемы macOS и пути решения

### Общая картина

macOS — принципиально более ограниченная платформа для инструментов WiFi-безопасности по сравнению с Linux. Apple последовательно закрывает низкоуровневый доступ к беспроводному стеку, и с каждой версией системы ситуация ухудшается. Ниже — карта конкретных проблем и реалистичных путей их решения.

---

### Проблема 1: Monitor Mode — ограниченный и хрупкий

**Суть проблемы.** macOS формально поддерживает monitor mode на встроенном WiFi-адаптере (Broadcom на Intel Mac, собственный чип на Apple Silicon), но с рядом принципиальных ограничений.

Встроенный адаптер переключается в monitor mode двумя способами: через утилиту `airport` (скрыта в `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport`) или через приложение Wireless Diagnostics (Window → Sniffer). Оба способа требуют сначала отключиться от текущей сети (`airport -z`), после чего адаптер начинает слушать один конкретный канал.

Ограничения:

- **Нет channel hopping.** Адаптер захватывает только один канал за раз. Переключение канала возможно (`airport --channel=N`), но каждое переключение — это вызов системной утилиты с ненулевой задержкой и возможными пропусками пакетов.
- **Отключение от сети обязательно.** Нельзя одновременно быть подключённым к WiFi-сети и слушать эфир на том же адаптере. Это делает невозможной двухрежимную работу (monitor + managed) на одном интерфейсе.
- **Нестабильность.** На macOS Sonoma и Sequoia пользователи сообщают о ненадёжной работе monitor mode — адаптер иногда не переключается обратно или перестаёт захватывать пакеты после нескольких минут.
- **Утилита `airport` не документирована.** Apple может удалить или изменить её в любой версии macOS без предупреждения. На некоторых версиях macOS Sequoia она уже работает нестабильно.

**Пути решения:**

| Подход | Плюсы | Минусы |
|--------|-------|--------|
| Использовать `airport -z` + BPF capture через libpcap | Работает без доп. оборудования; gopacket поддерживает BPF на macOS | Один канал; нет одновременного подключения; нестабильно |
| CoreWLAN framework через cgo | Официальный Apple API; переключение канала, сканирование | API ограничен; monitor mode через него ненадёжен; нет документации по raw capture |
| Внешний USB-адаптер с Linux-драйвером | Полноценный monitor mode с channel hopping | Требует кастомного драйвера (kext/dext); Apple блокирует kext начиная с Big Sur |
| Linux-VM с проброшенным USB-адаптером | Полноценная поддержка как на нативном Linux | Неудобно; требует VM и проброс USB; высокий overhead |

---

### Проблема 2: Frame Injection — фактически невозможна

**Суть проблемы.** macOS **не поддерживает инъекцию 802.11 фреймов** через встроенный WiFi-адаптер. Это подтверждено разработчиками scapy (issue #2870 на GitHub), bettercap и другими проектами. Вызов `pcap.WritePacketData()` на macOS в monitor mode просто не работает — фрейм не уходит в эфир.

Причина в том, что macOS WiFi-драйвер (IO80211Family / CoreWLAN) не предоставляет path для записи raw 802.11 фреймов. BPF-устройство (`/dev/bpf*`) на macOS работает только на чтение для wireless-интерфейсов.

**Это означает, что ключевая фича проекта — deauth-ответ атакующему — на macOS нереализуема через встроенный адаптер.**

**Пути решения:**

| Подход | Реалистичность | Комментарий |
|--------|---------------|-------------|
| Внешний USB-адаптер (Alfa AWUS036ACH, RTL8812AU) на Linux | Высокая | Но на macOS нужен драйвер; kext заблокированы Apple; dext (DriverKit) не поддерживает raw injection |
| Запуск через Linux VM (Parallels/UTM) с проброшенным USB | Средняя | Работает, но громоздко для продукта |
| ESP32/ESP8266 как внешний «injection dongle» по USB/UART | Средняя | ESP8266 поддерживает deauth injection; можно сделать микроконтроллер-мост |
| Passive-only режим на macOS | Высокая | Отказаться от injection на macOS; детектировать, но не отвечать |

---

### Проблема 3: Доступ к BPF-устройствам и права

**Суть проблемы.** Для захвата пакетов через libpcap на macOS нужен доступ к `/dev/bpf*`. По умолчанию эти устройства принадлежат `root:wheel` с правами `rw-------`. Программа должна запускаться от root или пользователю нужно изменить права на BPF-устройства.

Проблема усугубляется тем, что macOS пересоздаёт `/dev/bpf*` при каждой перезагрузке, сбрасывая права.

**Пути решения:**

- **LaunchDaemon.** Запускать Tobimaru как системный демон от root через `launchd` (файл `.plist` в `/Library/LaunchDaemons/`). Это аналог systemd-сервиса.
- **ChmodBPF.** Установить скрипт аналогичный Wireshark ChmodBPF — LaunchDaemon, который при загрузке системы выставляет `chmod 660 /dev/bpf*` и `chgrp access_bpf /dev/bpf*`. Пользователь добавляется в группу `access_bpf`.
- **Entitlements (для распространения через App Store / нотаризации).** Apple требует com.apple.developer.networking.packet-capture entitlement для BPF. Получить его можно только через Apple Developer Program.

---

### Проблема 4: System Integrity Protection (SIP) и DriverKit

**Суть проблемы.** Начиная с macOS Big Sur (11.0), Apple перешла от kernel extensions (kext) к DriverKit extensions (dext) для сторонних драйверов. Это значит, что установить собственный WiFi-драйвер (для внешнего USB-адаптера с поддержкой injection) через kext невозможно без отключения SIP. А DriverKit не предоставляет API для raw 802.11 frame injection.

На macOS Sonoma/Sequoia:

- kext-драйверы сторонних WiFi-адаптеров (chris1111/Wireless-USB-OC-Big-Sur-Adapter) работают **только с отключённым SIP**, что неприемлемо для production-продукта безопасности.
- Apple Silicon Mac дополнительно усложняет это, требуя перезагрузку в Recovery Mode для изменения политик безопасности.

**Пути решения:**

| Подход | Комментарий |
|--------|-------------|
| Не требовать отключения SIP; использовать passive-only режим | Единственный «чистый» вариант для macOS |
| Документировать процедуру с отключённым SIP для продвинутых пользователей | Не для массового продукта |
| Использовать Apple Network Extension framework | Работает на уровне L3+, не видит 802.11 management frames |

---

### Проблема 5: Два интерфейса на macOS

**Суть проблемы.** Архитектура проекта предполагает два WiFi-интерфейса: один в monitor mode, другой подключён к защищаемой сети. На большинстве Mac только один встроенный WiFi-адаптер.

**Пути решения:**

- **Внешний USB WiFi-адаптер** как второй интерфейс. Но снова упираемся в проблему с драйверами (см. выше).
- **Работа в одном режиме с переключением.** Периодически переключаться между monitor и managed mode. Это создаёт «слепые пятна» в мониторинге и разрывает сетевое подключение.
- **Использовать Ethernet для managed-соединения.** Подключить Mac к роутеру по кабелю (через USB-C→Ethernet адаптер) для in-network мониторинга, а встроенный WiFi — в monitor mode.

---

### Проблема 6: Apple Silicon — специфика

На Apple Silicon (M1/M2/M3/M4):

- Встроенный WiFi-чип — проприетарный Apple, без публичной документации.
- Monitor mode работает (поддерживается захват на 2.4 GHz, 5 GHz, 6 GHz с шириной канала до 160 MHz), но нестабильно.
- USB-адаптеры требуют Rosetta 2 для x86-драйверов kext, что добавляет слой нестабильности.
- Нет поддержки PCMCIA/CardBus, которые исторически использовались для injection на старых Mac.

---

### Итоговая матрица возможностей: macOS vs Linux

| Возможность | Linux | macOS |
|-------------|-------|-------|
| Monitor mode (встроенный адаптер) | Полная | Ограниченная (один канал, нестабильно) |
| Monitor mode (USB-адаптер) | Полная | Требует kext + отключение SIP |
| Channel hopping | Нативная (`iw`) | Через `airport`, с задержками |
| Frame injection | Полная (`pcap.WritePacketData`) | Не поддерживается |
| Два интерфейса | Легко (wlan0 + wlan1) | Сложно (один встроенный) |
| BPF/pcap доступ | Стандартный (root) | Требует настройки BPF permissions |
| Стабильность monitor mode | Высокая | Низкая (зависит от версии macOS) |
| Запуск как сервис | systemd | launchd (но ограничения на root-доступ) |

---

### Рекомендуемая стратегия для macOS

**Реалистичный подход — «macOS Lite» режим:**

1. **Passive-only мониторинг.** Детектирование атак без активного ответа. Адаптер в monitor mode, один канал за раз, ротация по таймеру.
2. **In-network мониторинг через Ethernet.** Если Mac подключён к роутеру по кабелю, полноценный ARP/DNS/DHCP мониторинг без ограничений.
3. **Оповещения вместо противодействия.** Push-уведомления / Telegram / webhook при обнаружении угрозы.
4. **Документировать, что полный функционал — только на Linux.** macOS — как удобная платформа для разработки и passive-мониторинга.

**Для продвинутых пользователей (opt-in):**

5. Поддержка внешнего USB-адаптера с injection (документировать необходимость отключения SIP).
6. Поддержка ESP32-«донгла» как injection-моста (Serial/USB, команды по UART).

---

### Влияние на архитектуру проекта

Чтобы поддерживать обе платформы, в проекте нужен **platform abstraction layer:**

```
internal/
├── platform/
│   ├── iface.go          // интерфейс: MonitorModeManager, FrameInjector
│   ├── linux.go          // build tag: //go:build linux
│   │   ├── iw-based monitor mode
│   │   ├── pcap injection
│   │   └── netlink channel control
│   ├── darwin.go          // build tag: //go:build darwin
│   │   ├── airport-based monitor mode
│   │   ├── CoreWLAN via cgo (scan, channel)
│   │   └── injection: not supported / ESP32 bridge
│   └── darwin_cgo.go     // CoreWLAN bindings
```

Ключевые интерфейсы:

```go
type MonitorModeManager interface {
    Enable(iface string) error
    Disable(iface string) error
    SetChannel(iface string, channel int) error
    IsSupported() bool
}

type FrameInjector interface {
    InjectDeauth(bssid, client net.HardwareAddr) error
    IsSupported() bool  // false on macOS by default
}
```

Использование `IsSupported()` позволяет gracefully degraded experience: на macOS detection engine работает, но response engine знает, что injection невозможна, и переключается на alert-only режим.
