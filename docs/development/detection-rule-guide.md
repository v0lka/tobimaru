# Руководство по реализации правила детектирования

## Обзор

Этот документ описывает полный процесс добавления нового правила детектирования в Tobimaru Detection Engine. Правило — это реализация интерфейса `Rule`, которая получает поток распарсенных 802.11-фреймов и генерирует события безопасности (`SecurityEvent`) при обнаружении атаки.

---

## 1. Архитектура Detection Engine

### Поток данных

```
Capture Pipeline → []*parser.ParsedFrame → Engine.dispatch()
                                              │
                                              ├─ Rule1.Process(frame) → []*SecurityEvent
                                              ├─ Rule2.Process(frame) → []*SecurityEvent
                                              └─ RuleN.Process(frame) → []*SecurityEvent
                                                          │
                                                          ▼
                                              Engine.emit() → дедупликация → alerts channel
```

### Ключевые принципы

- **Правила — чистые функции**: `Process()` получает фрейм, возвращает события. Правила не управляют каналами, не блокируют, не паникуют.
- **Дедупликация** — ответственность Engine (по ключу `eventType:srcMAC:bssid`).
- **Panic recovery** — Engine перехватывает панику каждого правила и продолжает работу.
- **Состояние внутри правила** — правило может и должно хранить внутреннее состояние (скользящие окна, счётчики), но обязано быть потокобезопасным (Engine вызывает `Process` последовательно для одного фрейма, но подряд без задержек).

---

## 2. Интерфейс Rule

Файл: `internal/detector/rule.go`

```go
type Rule interface {
    // Name — уникальный идентификатор правила (e.g. "deauth_flood").
    // Используется в логах и как EventType по умолчанию.
    Name() string

    // Init — вызывается один раз при регистрации. Правило извлекает из конфига
    // свои пороговые значения. Возвращает ошибку, если конфигурация невалидна.
    Init(cfg config.DetectionConfig) error

    // Process — основная логика. Получает распарсенный фрейм, возвращает 0..N событий.
    // Нельзя сохранять указатель на frame после возврата.
    // Нельзя блокировать или паниковать.
    Process(frame *parser.ParsedFrame) []*SecurityEvent
}
```

---

## 3. Структура ParsedFrame (входные данные правила)

Файл: `internal/parser/parser.go`

```go
type ParsedFrame struct {
    FrameType      FrameType        // тип фрейма (Beacon, Deauth, ProbeRequest, и т.д.)
    Timestamp      time.Time        // временная метка захвата
    SrcMAC         net.HardwareAddr // MAC-адрес отправителя (Address2)
    DstMAC         net.HardwareAddr // MAC-адрес получателя (Address1)
    BSSID          net.HardwareAddr // BSSID точки доступа (Address3)
    SSID           string           // имя сети (из beacon/probe)
    Channel        int              // номер канала
    ChannelFreq    int              // частота канала в MHz
    RSSI           int              // уровень сигнала в dBm
    SequenceNum    uint16           // sequence number 802.11
    FragmentNum    uint16           // fragment number
    ReasonCode     uint16           // reason code (deauth/disassoc)
    AuthAlgorithm  uint16           // алгоритм аутентификации
    AuthSeq        uint16           // номер последовательности auth
    AuthStatus     uint16           // статус auth
    Status         uint16           // статус ассоциации
    InfoElements   map[uint8][]byte // информационные элементы (IE ID → data)
    Capability     uint16           // capability information
    BeaconInterval uint16           // интервал beacon
    ToDS           bool             // флаг To DS
    FromDS         bool             // флаг From DS
    WEP            bool             // флаг Privacy/WEP
    Retry          bool             // флаг повторной передачи
}
```

### Типы фреймов (FrameType)

```go
FrameTypeBeacon        // management: beacon
FrameTypeProbeRequest  // management: probe request
FrameTypeProbeResponse // management: probe response
FrameTypeAuth          // management: authentication
FrameTypeDeauth        // management: deauthentication
FrameTypeDisassoc      // management: disassociation
FrameTypeAssocReq      // management: association request
FrameTypeAssocResp     // management: association response
FrameTypeCTS           // control: CTS
FrameTypeRTS           // control: RTS
FrameTypeACK           // control: ACK
FrameTypeData          // data frame
FrameTypeQoSData       // QoS data frame
```

Вспомогательные методы:
- `ft.IsManagement()` — true для management-фреймов
- `ft.IsControl()` — true для control-фреймов
- `ft.IsData()` — true для data-фреймов

---

## 4. Модель событий безопасности (SecurityEvent)

Файл: `internal/detector/event.go`

```go
type SecurityEvent struct {
    Timestamp   time.Time          // момент детектирования
    EventType   string             // идентификатор атаки ("deauth_flood", "evil_twin")
    Severity    Severity           // Info / Warning / Critical
    SrcMAC      net.HardwareAddr   // MAC атакующего
    DstMAC      net.HardwareAddr   // MAC жертвы
    BSSID       net.HardwareAddr   // BSSID целевой/поддельной AP
    SSID        string             // связанный SSID
    Channel     int                // канал наблюдения
    RSSI        int                // сила сигнала
    FrameCount  int                // количество фреймов в окне обнаружения
    Duration    time.Duration      // продолжительность атаки
    Metadata    map[string]any     // произвольные метаданные правила
    Description string             // человекочитаемое описание
}
```

### Severity levels

| Уровень | Значение | Когда использовать |
|---------|----------|--------------------|
| `SeverityInfo` | 0 | Информационные события без непосредственной угрозы |
| `SeverityWarning` | 1 | Потенциальная угроза, требует внимания |
| `SeverityCritical` | 2 | Активная атака, требует немедленных действий |

### Конструктор NewEvent

```go
ev := detector.NewEvent(time.Now(), "deauth_flood", detector.SeverityCritical)
ev.SrcMAC = frame.SrcMAC
ev.DstMAC = frame.DstMAC
ev.BSSID = frame.BSSID
ev.Channel = frame.Channel
ev.RSSI = frame.RSSI
ev.FrameCount = count
ev.Duration = windowDuration
ev.Description = "Deauthentication flood detected: 50 frames in 10s"
ev.Metadata["reason_code"] = frame.ReasonCode
```

---

## 5. Конфигурация правила

### Расширение DetectionConfig

Файл: `internal/config/config.go`

Каждое правило получает конфигурацию через `DetectionConfig`. Для правилоспецифичных настроек необходимо расширить структуру:

```go
type DetectionConfig struct {
    Enabled         bool          `yaml:"enabled"`
    DedupWindow     time.Duration `yaml:"dedup_window"`
    AlertBufferSize int           `yaml:"alert_buffer_size"`

    // Пример: конфигурация для правила deauth_flood
    DeauthFlood DeauthFloodConfig `yaml:"deauth_flood"`
}

type DeauthFloodConfig struct {
    Enabled   bool          `yaml:"enabled"`
    Threshold int           `yaml:"threshold"` // порог фреймов
    Window    time.Duration `yaml:"window"`    // скользящее окно
}
```

### YAML-конфигурация

```yaml
detection:
  enabled: true
  dedup_window: 30s
  alert_buffer_size: 256
  deauth_flood:
    enabled: true
    threshold: 10
    window: 10s
```

### Defaults

Добавить значения по умолчанию в `internal/config/defaults.go`:

```go
const (
    DefaultDeauthFloodThreshold = 10
    DefaultDeauthFloodWindow    = 10 * time.Second
)
```

---

## 6. Пошаговое создание правила

### Шаг 1: Создать файл правила

Создайте файл в `internal/detector/`:

```
internal/detector/rule_deauth_flood.go
```

### Шаг 2: Определить структуру

```go
package detector

import (
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/vkochetkov/tobimaru/internal/config"
    "github.com/vkochetkov/tobimaru/internal/parser"
)

// DeauthFloodRule detects deauthentication flood attacks by tracking
// the number of deauth frames from a source MAC within a sliding window.
type DeauthFloodRule struct {
    threshold int
    window    time.Duration
    // Внутреннее состояние: трекер по source MAC
    mu      sync.Mutex
    tracker map[string]*deauthTracker
}

type deauthTracker struct {
    timestamps []time.Time
}
```

### Шаг 3: Реализовать интерфейс Rule

```go
func (r *DeauthFloodRule) Name() string {
    return "deauth_flood"
}

func (r *DeauthFloodRule) Init(cfg config.DetectionConfig) error {
    r.threshold = cfg.DeauthFlood.Threshold
    r.window = cfg.DeauthFlood.Window

    // Применить defaults, если не задано
    if r.threshold <= 0 {
        r.threshold = config.DefaultDeauthFloodThreshold
    }
    if r.window <= 0 {
        r.window = config.DefaultDeauthFloodWindow
    }

    r.tracker = make(map[string]*deauthTracker)
    return nil
}

func (r *DeauthFloodRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
    // Быстрая проверка типа фрейма — пропустить нерелевантные
    if frame.FrameType != parser.FrameTypeDeauth {
        return nil
    }

    now := frame.Timestamp
    key := frame.SrcMAC.String()

    r.mu.Lock()
    defer r.mu.Unlock()

    tr, exists := r.tracker[key]
    if !exists {
        tr = &deauthTracker{}
        r.tracker[key] = tr
    }

    // Добавить текущий timestamp
    tr.timestamps = append(tr.timestamps, now)

    // Удалить устаревшие записи (за пределами окна)
    cutoff := now.Add(-r.window)
    i := 0
    for i < len(tr.timestamps) && tr.timestamps[i].Before(cutoff) {
        i++
    }
    tr.timestamps = tr.timestamps[i:]

    // Проверить порог
    if len(tr.timestamps) >= r.threshold {
        ev := NewEvent(now, r.Name(), SeverityCritical)
        ev.SrcMAC = frame.SrcMAC
        ev.DstMAC = frame.DstMAC
        ev.BSSID = frame.BSSID
        ev.Channel = frame.Channel
        ev.RSSI = frame.RSSI
        ev.FrameCount = len(tr.timestamps)
        ev.Duration = now.Sub(tr.timestamps[0])
        ev.Description = fmt.Sprintf(
            "Deauthentication flood: %d frames in %v from %s",
            len(tr.timestamps), ev.Duration.Round(time.Second), frame.SrcMAC,
        )
        ev.Metadata["reason_code"] = frame.ReasonCode
        ev.Metadata["threshold"] = r.threshold

        // Сбросить трекер после генерации события (избежать повторных событий)
        tr.timestamps = tr.timestamps[:0]

        return []*SecurityEvent{ev}
    }

    return nil
}
```

### Шаг 4: Зарегистрировать правило в main.go

Файл: `cmd/tobimaru/main.go`

```go
// Register rules
if cfg.Detection.Enabled {
    if err := engine.Register(&detector.DeauthFloodRule{}); err != nil {
        slog.Error("failed to register deauth_flood rule", "error", err)
    }
}
```

### Шаг 5: Написать тесты

Создать файл `internal/detector/rule_deauth_flood_test.go`:

```go
package detector

import (
    "net"
    "testing"
    "time"

    "github.com/vkochetkov/tobimaru/internal/config"
    "github.com/vkochetkov/tobimaru/internal/parser"
)

func TestDeauthFloodRule_BelowThreshold(t *testing.T) {
    rule := &DeauthFloodRule{}
    err := rule.Init(config.DetectionConfig{
        DeauthFlood: config.DeauthFloodConfig{
            Threshold: 5,
            Window:    10 * time.Second,
        },
    })
    if err != nil {
        t.Fatalf("Init failed: %v", err)
    }

    src, _ := net.ParseMAC("00:11:22:33:44:55")
    for i := range 4 {
        frame := &parser.ParsedFrame{
            FrameType: parser.FrameTypeDeauth,
            Timestamp: time.Now().Add(time.Duration(i) * time.Second),
            SrcMAC:    src,
            BSSID:     src,
            Channel:   6,
        }
        events := rule.Process(frame)
        if len(events) != 0 {
            t.Errorf("expected no events at frame %d, got %d", i, len(events))
        }
    }
}

func TestDeauthFloodRule_ThresholdReached(t *testing.T) {
    rule := &DeauthFloodRule{}
    err := rule.Init(config.DetectionConfig{
        DeauthFlood: config.DeauthFloodConfig{
            Threshold: 5,
            Window:    10 * time.Second,
        },
    })
    if err != nil {
        t.Fatalf("Init failed: %v", err)
    }

    src, _ := net.ParseMAC("00:11:22:33:44:55")
    bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

    var events []*SecurityEvent
    for i := range 5 {
        frame := &parser.ParsedFrame{
            FrameType: parser.FrameTypeDeauth,
            Timestamp: time.Now().Add(time.Duration(i) * time.Second),
            SrcMAC:    src,
            BSSID:     bssid,
            Channel:   6,
            RSSI:      -50,
        }
        events = rule.Process(frame)
    }

    if len(events) != 1 {
        t.Fatalf("expected 1 event, got %d", len(events))
    }
    if events[0].EventType != "deauth_flood" {
        t.Errorf("EventType = %q, want deauth_flood", events[0].EventType)
    }
    if events[0].Severity != SeverityCritical {
        t.Errorf("Severity = %v, want Critical", events[0].Severity)
    }
}

func TestDeauthFloodRule_IgnoresNonDeauth(t *testing.T) {
    rule := &DeauthFloodRule{}
    _ = rule.Init(config.DetectionConfig{
        DeauthFlood: config.DeauthFloodConfig{Threshold: 1, Window: 10 * time.Second},
    })

    frame := &parser.ParsedFrame{
        FrameType: parser.FrameTypeBeacon,
        Timestamp: time.Now(),
    }
    events := rule.Process(frame)
    if len(events) != 0 {
        t.Error("expected no events for non-deauth frame")
    }
}
```

### Шаг 6: Добавить pcap-тесты (интеграционные)

Используйте `internal/testutil/pcapgen.go` для генерации тестовых данных:

```go
import "github.com/vkochetkov/tobimaru/internal/testutil"

func TestDeauthFloodRule_PcapIntegration(t *testing.T) {
    pcapData := testutil.BuildDeauthFloodPcap(
        testutil.SrcMAC(net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}),
        testutil.BSSID(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}),
        testutil.FloodCount(20),
        testutil.Channel(6),
        testutil.Reason(7), // Class 3 frame from nonassociated STA
    )
    // ... парсинг pcap и прогон через rule.Process()
}
```

---

## 7. Чеклист для нового правила

- [ ] Создать файл `internal/detector/rule_<name>.go`
- [ ] Реализовать интерфейс `Rule` (Name, Init, Process)
- [ ] Добавить конфигурационную структуру в `config.DetectionConfig`
- [ ] Добавить defaults в `internal/config/defaults.go`
- [ ] Добавить секцию YAML в `configs/tobimaru.yaml`
- [ ] Зарегистрировать правило в `cmd/tobimaru/main.go`
- [ ] Создать unit-тесты: `internal/detector/rule_<name>_test.go`
  - [ ] Тест: ниже порога — нет событий
  - [ ] Тест: достижение порога — событие генерируется
  - [ ] Тест: нерелевантные фреймы игнорируются
  - [ ] Тест: окно скольжения — устаревшие фреймы не считаются
  - [ ] Тест: множество источников — события для каждого отдельно
- [ ] Создать pcap-интеграционные тесты
- [ ] Запустить `make lint` и `make test`
- [ ] Обновить `specs/domains/detection.md` при необходимости

---

## 8. Паттерны реализации

### Скользящее окно (sliding window)

Наиболее частый паттерн для flood-правил. Храним список timestamps в отсортированном порядке, удаляем устаревшие при каждом вызове Process:

```go
// Удаление устаревших записей
cutoff := now.Add(-r.window)
i := 0
for i < len(timestamps) && timestamps[i].Before(cutoff) {
    i++
}
timestamps = timestamps[i:]
```

### Трекинг по MAC-адресу

Для правил, отслеживающих поведение конкретных устройств:

```go
type tracker struct {
    mu   sync.Mutex
    data map[string]*perMACState
}
```

Ключ — `SrcMAC.String()` или `BSSID.String()` в зависимости от семантики правила.

### Трекинг по SSID/BSSID (Evil Twin)

Для правил, сравнивающих характеристики AP с одним SSID:

```go
type apRecord struct {
    bssid     net.HardwareAddr
    channel   int
    firstSeen time.Time
    lastSeen  time.Time
    ies       map[uint8][]byte // fingerprint
}

// Ключ map — SSID → []apRecord
```

### Сброс трекера после генерации события

Для предотвращения потока дублирующихся событий (в дополнение к дедупликации Engine):

```go
if detected {
    // Сбросить счётчик/окно
    tr.timestamps = tr.timestamps[:0]
    return []*SecurityEvent{ev}
}
```

### Периодическая очистка stale-данных

Для предотвращения утечки памяти при множестве MAC-адресов:

```go
func (r *MyRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
    // Раз в N вызовов — очистка stale entries
    r.callCount++
    if r.callCount%10000 == 0 {
        r.cleanupStale(frame.Timestamp)
    }
    // ...
}
```

---

## 9. Доступные утилиты для тестирования

### testutil.pcapgen

Пакет `internal/testutil` предоставляет функции генерации pcap с конфигурируемыми параметрами:

| Функция | Описание |
|---------|----------|
| `BuildBeaconPcap(opts...)` | pcap с одним beacon-фреймом |
| `BuildDeauthPcap(opts...)` | pcap с одним deauth-фреймом |
| `BuildDisassocPcap(opts...)` | pcap с одним disassoc-фреймом |
| `BuildDeauthFloodPcap(opts...)` | pcap с N deauth-фреймов (flood) |
| `BuildDisassocFloodPcap(opts...)` | pcap с N disassoc-фреймов (flood) |
| `BuildProbeReqPcap(opts...)` | pcap с одним probe request |
| `BuildProbeRespPcap(opts...)` | pcap с одним probe response |
| `BuildMultiFramePcap(opts...)` | pcap с несколькими типами фреймов |

### Опции (Options)

```go
testutil.SrcMAC(mac)       // задать MAC отправителя
testutil.DstMAC(mac)       // задать MAC получателя
testutil.BSSID(mac)        // задать BSSID
testutil.SSID("MyNetwork") // задать SSID
testutil.Channel(6)        // задать канал
testutil.RSSI(-45)         // задать уровень сигнала
testutil.Reason(7)         // задать reason code
testutil.SeqNum(42)        // задать sequence number
testutil.FloodCount(100)   // задать количество фреймов в flood
```

### Парсинг pcap для тестов

```go
import (
    "bytes"
    "github.com/gopacket/gopacket"
    "github.com/gopacket/gopacket/pcapgo"
    "github.com/gopacket/gopacket/layers"
    "github.com/vkochetkov/tobimaru/internal/parser"
)

func parseTestPcap(t *testing.T, data []byte) []*parser.ParsedFrame {
    t.Helper()
    reader, err := pcapgo.NewReader(bytes.NewReader(data))
    if err != nil {
        t.Fatalf("failed to open pcap: %v", err)
    }

    var frames []*parser.ParsedFrame
    packetSource := gopacket.NewPacketSource(
        &pcapReaderWrapper{reader},
        layers.LayerTypeRadioTap,
    )
    for packet := range packetSource.Packets() {
        frame, err := parser.Parse(packet)
        if err != nil {
            continue
        }
        frames = append(frames, frame)
    }
    return frames
}
```

---

## 10. Регистрация и запуск

### Порядок в main.go

```go
// 1. Создать Engine
engine := detector.NewEngine(cfg.Detection)

// 2. Зарегистрировать правила (ДО вызова Run!)
engine.Register(&detector.DeauthFloodRule{})
engine.Register(&detector.DisassocFloodRule{})
engine.Register(&detector.EvilTwinRule{})
engine.Register(&detector.BeaconFloodRule{})
engine.Register(&detector.UnauthorizedDeviceRule{})

// 3. Запустить Engine
engine.Run(ctx, pipeline.Frames())

// 4. Потреблять алерты
go consumeAlerts(ctx, engine.Alerts())
```

### Поведение Engine

- Каждый фрейм последовательно передаётся всем зарегистрированным правилам
- Паника одного правила не влияет на остальные
- Дедупликация по ключу `eventType:srcMAC:bssid` (окно 30s по умолчанию)
- При переполнении канала алертов — событие отбрасывается (логируется warning)

---

## 11. Соглашения по именованию

| Элемент | Формат | Пример |
|---------|--------|--------|
| Файл правила | `rule_<snake_case>.go` | `rule_deauth_flood.go` |
| Структура правила | `<PascalCase>Rule` | `DeauthFloodRule` |
| Name() | `snake_case` | `"deauth_flood"` |
| EventType | совпадает с Name() | `"deauth_flood"` |
| Конфиг-структура | `<PascalCase>Config` | `DeauthFloodConfig` |
| YAML-ключ | `snake_case` | `deauth_flood:` |
| Тест-файл | `rule_<snake_case>_test.go` | `rule_deauth_flood_test.go` |

---

## 12. Рекомендации

1. **Быстрая ранняя фильтрация**: первая строка в `Process()` — проверка `frame.FrameType`. Пропускайте нерелевантные фреймы как можно раньше.

2. **Не выделяйте память без необходимости**: возвращайте `nil` вместо пустого слайса, когда событий нет.

3. **Описательные Description**: включайте количество фреймов, временное окно, MAC-адреса.

4. **Metadata**: добавляйте любые данные, полезные для расследования (reason codes, каналы, fingerprints).

5. **Тестируемость**: выделяйте внутреннюю логику (windowing, tracking) в отдельные методы для изолированного тестирования.

6. **Ограничивайте потребление памяти**: периодически очищайте stale-данные из внутренних map'ов.
