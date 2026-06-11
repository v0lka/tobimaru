# Руководство разработчика

Данное руководство охватывает архитектуру, рабочий процесс разработки и
процесс внесения вклада в проект Tobimaru.

## Архитектура

Tobimaru следует строгой слоистой архитектуре, где `cmd/tobimaru` является
единственным оркестратором, а вся бизнес-логика находится в пакетах
`internal/`.

### Граф зависимостей пакетов

```
cmd/tobimaru (оркестратор — импортирует все internal-пакеты)
    │
    ├── internal/config        (самодостаточный: загрузка YAML, валидация, defaults)
    ├── internal/logging       (→ config: фабрика slog)
    ├── internal/shutdown      (самодостаточный: сигналы, LIFO-хуки очистки)
    ├── internal/version       (самодостаточный: метаданные сборки через ldflags)
    ├── internal/platform      (самодостаточный: runtime-определение возможностей платформы)
    ├── internal/parser        (самодостаточный: разбор 802.11-фреймов)
    ├── internal/capture       (→ config, parser, platform: pcap, monitor mode, channel hopping)
    ├── internal/detector      (→ config, parser: интерфейс правил, движок, dedup, события)
    ├── internal/state         (→ config, parser: карты AP/clients, whitelist/blacklist, learning)
    ├── internal/storage       (→ config, detector, state: SQLite — события, snapshots, sessions, lists)
    ├── internal/api           (→ config, state, storage, detector, capture, version, logging)
    │       └── internal/api/web (самодостаточный: встроенная React SPA через go:embed)
    └── internal/testutil      (самодостаточный: хелперы генерации pcap)
```

### Правила импортов

- `cmd/tobimaru` — ЕДИНСТВЕННЫЙ потребитель пакетов `internal/`.
- Ни один пакет `internal/` не импортирует `cmd/`.
- Циклические зависимости запрещены.
- Самодостаточные пакеты без импортов проекта: `config`, `shutdown`,
  `version`, `platform`, `parser`, `api/web`, `testutil`.

Полный DAG зависимостей и правила импортов — в `specs/architecture/layers.md`.

### Структура каталогов

```
cmd/tobimaru/          Точка входа, связывание, оркестрация
internal/
  config/              Загрузка YAML, валидация, значения по умолчанию
  logging/             Фабрика логгера slog
  shutdown/            Обработка сигналов, LIFO-хуки очистки
  version/             Метаданные сборки (внедряются при компиляции)
  platform/            Определение возможностей платформы (Linux/macOS/прочие)
  parser/              Разбор и классификация фреймов 802.11
  capture/             Monitor mode, pcap-хэндл, channel hopping, пайплайн
  detector/            Движок обнаружения, правила, события безопасности
  state/               Трекинг AP/clients, whitelist/blacklist, auto-learning
  storage/             SQLite-репозиторий (события, снапшоты, сессии, списки)
  api/                 chi-роутер, REST-обработчики, SSE-хаб, auth
    web/               Встроенная React 19 SPA (go:embed dist/)
  testutil/            Тестовые хелперы (генерация pcap)
configs/               Примеры файлов конфигурации
web/                   Исходники React 19 + Vite + TypeScript SPA
specs/                 Системные спецификации
  architecture/        Иерархия пакетов и правила
  domains/             Спецификации концептуальных доменов
  contracts/           Спецификации интерфейсов между границами
  decisions/           Записи архитектурных решений (ADR)
docs/                  Документация
  development/         Дорожная карта и внутренние заметки разработки
```

## Настройка окружения разработки

### Необходимые компоненты

- Go 1.26+
- GNU Make
- golangci-lint v2 (для линтинга; Makefile вызывает `golangci-lint-v2`)
- Node.js 22+ и npm (только при изменении веб-дашборда)

### Начало работы

```bash
git clone https://github.com/vkochetkov/tobimaru.git
cd tobimaru
make tidy
make build
make test
make lint
```

Заранее собранный бандл дашборда зафиксирован в `internal/api/web/dist/`,
поэтому бэкенд всегда собирается без Node. Запускайте `make web-deps && make web`
только при изменении исходников SPA. `make web-deps` необходимо выполнить
перед `make web` для установки TypeScript и других Node-зависимостей.

## Цели Make

| Цель | Описание |
|------|----------|
| `make all` | Восстановить все зависимости (Go + npm), собрать web, затем собрать бинарник |
| `make build` | Сборка для текущей платформы → `bin/tobimaru` (встраивает `web/dist`) |
| `make build-all` | Кросс-компиляция для `linux/amd64`, `linux/arm64`, `darwin/arm64` |
| `make test` | Запуск тестов с детектором гонок и покрытием |
| `make test-cover` | Запуск тестов и открытие отчёта о покрытии |
| `make lint` | Запуск `golangci-lint run ./...` |
| `make run` | `go run` с ldflags |
| `make clean` | Удаление `bin/` и `coverage.out` (сохраняет закоммиченный `web/dist`) |
| `make fmt` | `go fmt ./...` |
| `make tidy` | `go mod tidy` |
| `make web-deps` | `npm ci` в каталоге `web/` |
| `make web` | Сборка SPA в `internal/api/web/dist/` |
| `make web-clean` | Удаление встроенного бандла SPA |
| `make lint-web` | Запуск ESLint по исходникам SPA |
| `make help` | Список всех целей |

## Система сборки

Метаданные версии внедряются при компиляции через ldflags:

```bash
# Переменные, устанавливаемые автоматически Makefile:
VERSION  # git-тег или "dev"
COMMIT   # git rev-parse --short HEAD
DATE     # временная метка UTC ISO 8601

# Внедряются в пакет internal/version:
-X github.com/vkochetkov/tobimaru/internal/version.Version=$(VERSION)
-X github.com/vkochetkov/tobimaru/internal/version.Commit=$(COMMIT)
-X github.com/vkochetkov/tobimaru/internal/version.Date=$(DATE)
```

Бинарные файлы стрипаются (`-s -w`) для уменьшения размера.

## Тестирование

Запуск всех тестов с детектором гонок:

```bash
make test
```

Ключевые практики тестирования:

- Тесты используют стандартный пакет `testing`.
- Детектор гонок включён по умолчанию (флаг `-race`).
- На macOS Makefile задаёт `CGO_LDFLAGS=-Wl,-no_warn_duplicate_libraries`,
  чтобы погасить предупреждение о дублирующихся библиотеках на Apple Silicon.
- `internal/testutil/` предоставляет хелперы для генерации синтетических
  pcap-данных.
- CI запускает тесты на Ubuntu и macOS.

### Написание тестов

- Размещайте тестовые файлы рядом с тестируемым кодом (`foo_test.go` рядом
  с `foo.go`).
- Используйте табличные тесты (table-driven tests), где применимо.
- Тестируйте как успешные, так и ошибочные пути.
- Для тестов capture/parser/detector используйте `testutil.BuildBeaconPcap()`,
  `testutil.BuildDeauthPcap()`, `testutil.BuildDeauthFloodPcap()`,
  `testutil.BuildDisassocFloodPcap()`, `testutil.BuildProbeReqPcap()`,
  `testutil.BuildProbeRespPcap()` и аналоги для создания синтетических
  фреймов.

## Линтинг

Проект использует golangci-lint v2 со строгой конфигурацией (`.golangci.yml`):

```bash
make lint
```

CI проверяет линтинг на всех PR. Исправьте все замечания линтера перед
отправкой изменений.

## CI-пайплайн

GitHub Actions (`.github/workflows/ci.yml`) запускается при push/PR в `main`:

1. **Lint** — `golangci-lint v2` на `ubuntu-latest` (Go 1.26).
2. **Web** — Vite-сборка + ESLint на Node 22; артефакт
   `internal/api/web/dist`.
3. **Test** — `go test -race -cover` на `ubuntu-latest`.
4. **Build** — матричная кросс-компиляция для `linux/amd64`,
   `linux/arm64` (`ubuntu-24.04-arm`) и `darwin/arm64` (`macos-latest`).
5. **Test (macOS)** — тесты и smoke-тест `--version` на `macos-latest`.

Все задания должны пройти перед мержем.

## Потоки данных

### Последовательность запуска

1. Разбор флагов CLI (`-config`, `-version`, `-hash-password`).
   Флаг `-hash-password` — это отдельная утилита: она генерирует bcrypt-хэш,
   выводит его в stdout и немедленно завершается — демон не запускается.
   Так оператор получает значения `admin_password_hash`/`user_password_hash`
   для YAML-конфига.
2. Загрузка и валидация YAML-конфигурации.
3. Инициализация структурированного логгера.
4. Открытие SQLite-хранилища (если `storage.enabled`).
5. Создание движка состояния, загрузка persisted whitelist/blacklist.
6. Создание движка детектирования и регистрация настроенных правил.
7. Создание capture-пайплайна и его запуск с signal-контекстом (включает
   monitor mode, открывает pcap, стартует channel hopper).
8. Регистрация хуков завершения (`capture_stop`, `storage_close`,
   `api_stop`, `consumer_stop`).
9. Создание SSE-хаба, если `api.enabled`.
10. Запуск consumer-горутин в зависимости от включённых функций:
    - `fan-out`, если активны и detection, и state.
    - Движок детектирования + alert consumer (логирует, сохраняет, шлёт по SSE).
    - State-frame consumer + state-eviction горутина.
    - Snapshot writer, если активны state и storage.
    - Auto-learning, если включён.
11. Запуск API-сервера, цикла `Hub.Run` и периодического публикатора статуса.
12. Блокировка до получения SIGINT/SIGTERM.
13. Выполнение хуков очистки в LIFO-порядке с дедлайном 30 секунд.

### Пайплайн обработки фреймов

```
WiFi-адаптер (monitor mode)
    ↓
pcap-хэндл (RFMon + BPF-фильтр: mgt/ctl/data)
    ↓
Горутина цикла захвата
    ├── Чтение сырого пакета
    ├── parser.Parse() → ParsedFrame
    └── Отправка в канал фреймов (буфер = monitor.capture.frame_buffer_size)
         ↓
fanOut (когда detection и state включены одновременно)
    ├──► канал детектирования ──► Detection Engine
    │                                ├── Диспатч фрейма всем зарегистрированным правилам
    │                                ├── Rule.Process(frame) → []*SecurityEvent
    │                                ├── Дедупликация (ключ: eventType:srcMAC:bssid)
    │                                └── Отправка в канал alerts (cap = detection.alert_buffer_size)
    │                                         ↓
    │                                   Alert Consumer
    │                                         ├── Логирование по severity
    │                                         ├── Сохранение в SQLite (если storage.enabled)
    │                                         └── Бродкаст через SSE (если api.enabled)
    └──► канал состояния ──► State Engine
                                  ├── Обновление карт AP / clients
                                  └── Eviction-горутина чистит stale-записи
```

Если включён только один из движков (detection или state), соответствующий
consumer читает напрямую из capture-пайплайна, минуя `fanOut`.

## Ключевые интерфейсы

### Правила обнаружения

Новые правила обнаружения реализуют интерфейс `Rule`
(`internal/detector/rule.go`):

```go
type Rule interface {
    Name() string
    Init(cfg config.DetectionConfig) error
    Process(frame *parser.ParsedFrame) []*SecurityEvent
}
```

Контракты:

- `Name()` должен возвращать уникальный идентификатор.
- `Init()` вызывается один раз при настройке движка.
- `Process()` должен быть чистой функцией — без удержания ссылок на фрейм,
  без блокировок, без паник. Движок перехватывает паники и продолжает работу.
- Регистрируйте правила до вызова `engine.Run()`.

Пакет detector содержит пять конкретных правил: `DeauthFloodRule`,
`DisassocFloodRule`, `BeaconFloodRule`, `EvilTwinRule`,
`UnauthorizedDeviceRule`. Flood-правила используют общий внутренний хелпер
`floodRule` (`internal/detector/rule_flood.go`); используйте его при
добавлении новых flood-правил вместо дублирования логики скользящего окна.
Подробное руководство — в
[`docs/development/detection-rule-guide.md`](development/detection-rule-guide.md).

### События безопасности

События несут результаты обнаружения (`internal/detector/event.go`):

```go
type SecurityEvent struct {
    Timestamp   time.Time
    EventType   string
    Severity    Severity            // SeverityInfo, SeverityWarning, SeverityCritical
    SrcMAC      net.HardwareAddr
    DstMAC      net.HardwareAddr
    BSSID       net.HardwareAddr
    SSID        string
    Channel     int
    RSSI        int
    FrameCount  int
    Duration    time.Duration
    Metadata    map[string]any
    Description string
}
```

Используйте `detector.NewEvent(timestamp, eventType, severity)` для
получения значения с предварительно инициализированным `Metadata`.

### Возможности платформы

Платформо-специфичное поведение абстрагировано через build-теги:

- `internal/platform/capabilities_linux.go` (build tag: `linux`)
- `internal/platform/capabilities_darwin.go` (build tag: `darwin`)
- `internal/platform/capabilities_others.go` (build tag: `!linux && !darwin`)
- `internal/capture/monitor_linux.go` / `monitor_darwin.go` /
  `monitor_unsupported.go` (macOS-реализация включает CoreWLAN-мост в
  `monitor_darwin.m`).

При добавлении платформо-специфичного кода следуйте этому паттерну с
соответствующими build-ограничениями.

## Веб-дашборд

Дашборд — React 19 SPA в `web/`:

- **Страницы:** `Status.tsx`, `Map.tsx`, `Events.tsx`, `Stats.tsx`,
  `Settings.tsx`, `Login.tsx`.
- **Состояние:** `auth.tsx` (`AuthContext`), `api.ts` (REST-клиент),
  `sse.ts` (SSE-хук).
- **Стили:** Tailwind CSS через `tailwind.config.ts`.
- **Графики:** `recharts`.
- **Отображение конфига:** `js-yaml` для форматирования YAML на странице
  настроек.

Результат сборки попадает в `internal/api/web/dist/` и встраивается во
время компиляции через `internal/api/web/embed.go`. SPA отдаётся для всех
не-`/api/`-маршрутов через chi-обработчик `NotFound`.

Для dev-режима с hot reload запустите демон с `api.enabled: true` и
`npm run dev` внутри `web/`. Vite проксирует `/api` на `127.0.0.1:8080`.

## Система спецификаций

Перед внесением структурных изменений обращайтесь к системе спецификаций:

1. Начните с [`specs/INDEX.md`](../specs/INDEX.md) — сопоставляет задачи
   с релевантными спецификациями.
2. Прочитайте [`specs/WORKFLOW.md`](../specs/WORKFLOW.md) — объясняет, как
   использовать и обновлять спецификации.
3. Проверьте [`specs/META.md`](../specs/META.md) — определяет форматы
   спецификаций.

### Типы спецификаций

| Тип | Расположение | Назначение |
|-----|--------------|------------|
| Доменные спецификации | `specs/domains/` | Определения концептуальных доменов |
| Контрактные спецификации | `specs/contracts/` | Интерфейсы между границами |
| Архитектурные спецификации | `specs/architecture/` | Системные правила (граф импортов) |
| ADR | `specs/decisions/` | Записи архитектурных решений |

При добавлении новых пакетов или изменении интерфейсов обновляйте
соответствующие спецификации.

## Записи архитектурных решений

Значимые проектные решения документируются как ADR в `specs/decisions/`:

- **ADR-001:** YAML-конфигурация с `KnownFields(true)` (строгий парсинг).
- **ADR-002:** Внедрение версии через ldflags.
- **ADR-003:** Структурированное логирование slog.
- **ADR-004:** Pure-Go SQLite (`modernc.org/sqlite`, без CGO).
- **ADR-005:** chi-роутер + встроенная React SPA + SSE для real-time.

Используйте `specs/decisions/_template.md` при добавлении новых ADR.

## Дизайн конфигурации

Система конфигурации (`internal/config/`) следует этим принципам:

- YAML со строгим парсингом — неизвестные ключи вызывают ошибку загрузки.
- Значения по умолчанию применяются к полям с нулевым значением после
  декодирования (`defaults.go`).
- Валидация собирает все ошибки (не fail-fast) через `errors.Join`.
- Только `monitor.interface` действительно обязателен; всё остальное имеет
  значения по умолчанию.
- Sentinel-ошибки для конкретных ситуаций валидации.

`Config` покрывает секции `Log`, `Monitor`, `Detection`, `State`,
`Whitelist`, `Storage` и `API`. Полный справочник полей — в
[USERGUIDE_ru.md](USERGUIDE_ru.md#конфигурация).

## Добавление новых пакетов

При создании нового пакета `internal/`:

1. Проверьте `specs/architecture/layers.md` на предмет допустимых
   зависимостей.
2. Убедитесь в отсутствии циклических импортов.
3. Только `cmd/tobimaru` должен импортировать новый пакет.
4. Добавьте соответствующие тесты.
5. Обновите спецификации, если пакет вводит новые доменные концепции или
   контракты.

## Дорожная карта разработки

Проект следует поэтапному плану разработки:

| Фаза | Статус | Описание |
|------|--------|----------|
| 0 | Завершена | Фундамент (config, logging, shutdown, version, CI) |
| 1 | Завершена | Capture Engine (monitor mode, pcap, channel hopping, парсинг) |
| 2 | Завершена | Detection Engine (интерфейс правил, движок, пять правил, pcap-интеграционные тесты) |
| 3 | Завершена | Состояние сети и хранилище (трекинг AP/clients, whitelist/blacklist, SQLite) |
| 4 | Завершена | REST API и дашборд (chi, SSE, React 19 SPA, auth) |
| 5 | Завершена | Кроссплатформенность (macOS — CoreWLAN-мост без airport + BPF) |
| 6+ | Запланировано | EAPOL, активные контрмеры, мониторинг внутренней сети, поведенческая аналитика, OpenWrt, расширенное детектирование, дополнительные интеграции |

Подробные разбиения по задачам — в
[`docs/development/wifi-watchdog-roadmap.md`](development/wifi-watchdog-roadmap.md).

## Внешние зависимости

| Модуль | Назначение |
|--------|------------|
| `gopkg.in/yaml.v3` | Парсинг YAML-конфигурации (строгий, `KnownFields`) |
| `github.com/gopacket/gopacket` | Захват pcap и декодирование 802.11-фреймов |
| `github.com/go-chi/chi/v5` | HTTP-роутер для REST API |
| `golang.org/x/crypto` | bcrypt для хэширования паролей |
| `modernc.org/sqlite` | Pure-Go SQLite-драйвер (без CGO) |

Зависимости минимальны по дизайну. Новые зависимости должны быть
обоснованы и обсуждены в ADR.
