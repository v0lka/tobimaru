# Обзор атак: задачи 2.3–2.7

Документ описывает каждую атаку из задач 2.3–2.7 роадмапа, механизмы их обнаружения и привязку к структурам `ParsedFrame` / `SecurityEvent`.

---

## 2.3 Deauthentication Flood

### Описание атаки

Атакующий массово рассылает фреймы типа Deauthentication, имитируя AP или клиента. Цель — принудительное отключение клиентов от точки доступа. Основа для более сложных атак (Evil Twin, WPA handshake capture).

### Признаки в эфире

- Большое количество `Deauthentication` фреймов за короткий период
- Фреймы исходят от одного `SrcMAC` (может быть broadcast или unicast в `DstMAC`)
- `DstMAC` часто `ff:ff:ff:ff:ff:ff` (broadcast) для отключения всех клиентов
- Разнообразие reason codes (часто `7` — Class 3 frame received from nonassociated STA)
- Нетипично высокая скорость (десятки–сотни фреймов в секунду)

### Поля ParsedFrame для проверки

| Поле | Назначение |
|------|-----------|
| `FrameType` | **Должен быть** `FrameTypeDeauth` |
| `SrcMAC` | Ключ трекинга — идентификация источника атаки |
| `DstMAC` | Если broadcast — более серьёзная атака |
| `BSSID` | Целевая AP |
| `Timestamp` | Для скользящего окна |
| `ReasonCode` | Метаданные события (код причины: 1–45) |
| `Channel` | Канал наблюдения |
| `RSSI` | Сила сигнала атакующего |

### Алгоритм детектирования

```
Тип: Sliding Window Counter
Ключ: SrcMAC (или SrcMAC+BSSID для более точного трекинга)

Для каждого входящего deauth-фрейма:
  1. Фильтр: frame.FrameType == FrameTypeDeauth
  2. Получить/создать трекер по ключу SrcMAC
  3. Добавить frame.Timestamp в скользящее окно
  4. Удалить записи старше window (e.g. 10s)
  5. Если count(timestamps) >= threshold → генерировать событие
  6. После генерации — сбросить окно (или пометить "уже сработало")
```

### Параметры конфигурации

| Параметр | Тип | Default | Описание |
|----------|-----|---------|----------|
| `threshold` | int | 10 | Минимум deauth-фреймов для срабатывания |
| `window` | duration | 10s | Размер скользящего окна |

### SecurityEvent

| Поле | Значение |
|------|----------|
| `EventType` | `"deauth_flood"` |
| `Severity` | `SeverityCritical` |
| `SrcMAC` | MAC источника flood |
| `DstMAC` | MAC жертвы (или broadcast) |
| `BSSID` | BSSID целевой AP |
| `FrameCount` | Количество фреймов в окне |
| `Duration` | Длительность окна |
| `Metadata["reason_code"]` | Последний reason code |
| `Metadata["threshold"]` | Установленный порог |

---

## 2.4 Disassociation Flood

### Описание атаки

Аналогична Deauth Flood, но использует фреймы `Disassociation`. Эффект тот же — принудительное отключение клиентов. Некоторые атакующие инструменты (mdk3/mdk4, aireplay-ng) чередуют deauth и disassoc.

### Признаки в эфире

- Массовые `Disassociation` фреймы от одного источника
- Характеристики идентичны deauth flood
- Reason code часто `8` (Disassociated because sending STA is leaving BSS)

### Поля ParsedFrame для проверки

| Поле | Назначение |
|------|-----------|
| `FrameType` | **Должен быть** `FrameTypeDisassoc` |
| `SrcMAC` | Ключ трекинга |
| `DstMAC` | Жертва (unicast) или broadcast |
| `BSSID` | Целевая AP |
| `Timestamp` | Для скользящего окна |
| `ReasonCode` | Метаданные (обычно 1, 4, 5, 8) |
| `Channel` | Канал |
| `RSSI` | Сила сигнала |

### Алгоритм детектирования

Полностью аналогичен deauth flood, отличается только фильтр по FrameType:

```
Тип: Sliding Window Counter
Ключ: SrcMAC

  1. Фильтр: frame.FrameType == FrameTypeDisassoc
  2. Далее идентично deauth_flood
```

**Рекомендация**: реализовать как параметризованный общий тип `FloodRule` с настраиваемым фильтром по FrameType, либо как отдельную копию с минимальными отличиями.

### Параметры конфигурации

| Параметр | Тип | Default | Описание |
|----------|-----|---------|----------|
| `threshold` | int | 10 | Минимум disassoc-фреймов для срабатывания |
| `window` | duration | 10s | Размер скользящего окна |

### SecurityEvent

| Поле | Значение |
|------|----------|
| `EventType` | `"disassoc_flood"` |
| `Severity` | `SeverityCritical` |
| `SrcMAC` | MAC источника flood |
| `DstMAC` | MAC жертвы |
| `BSSID` | BSSID целевой AP |
| `FrameCount` | Количество фреймов в окне |
| `Duration` | Длительность окна |
| `Metadata["reason_code"]` | Последний reason code |

---

## 2.5 Evil Twin AP

### Описание атаки

Атакующий создаёт точку доступа с тем же SSID, что и легитимная AP. Клиенты могут подключиться к поддельной AP, позволяя перехват трафика (MitM). Атакующий часто сочетает Evil Twin с deauth flood для переключения клиентов.

### Признаки в эфире

- Два (или более) beacon/probe response с **одинаковым SSID**, но:
  - **Разный BSSID** (основной признак)
  - **Разный канал** (сильный индикатор)
  - **Разные Information Elements** (IE fingerprint) — RSN/WPA IE, Vendor-specific IE
- Возможно: более сильный сигнал (RSSI) у поддельной AP
- Подозрительное время появления — новый BSSID для известного SSID

### Поля ParsedFrame для проверки

| Поле | Назначение |
|------|-----------|
| `FrameType` | **Beacon** или **ProbeResponse** |
| `SSID` | Ключ трекинга — группировка AP по SSID |
| `BSSID` | Идентификатор AP — должен быть уникальным для легитимной AP |
| `Channel` | Сравнение каналов AP с одним SSID |
| `InfoElements` | Fingerprinting: сравнение IE-набора |
| `Capability` | Capability info (WPA/WPA2/WPA3 bits) |
| `BeaconInterval` | Необычный интервал — дополнительный индикатор |
| `RSSI` | Оценка расстояния, подозрение при сильном сигнале нового AP |
| `Timestamp` | Время первого и последнего наблюдения |

### Алгоритм детектирования

```
Тип: State Table + Comparison
Ключ: SSID

Состояние:
  known_aps: map[SSID] → []APRecord
  APRecord: { BSSID, Channel, IEs, Capability, FirstSeen, LastSeen, RSSI }

Для каждого beacon/probe_response:
  1. Фильтр: frame.FrameType == FrameTypeBeacon || FrameTypeProbeResponse
  2. Извлечь SSID; пропустить, если SSID пустой
  3. Найти/создать запись по SSID
  4. Проверить: есть ли уже AP с таким BSSID?
     - Да → обновить LastSeen, RSSI
     - Нет → добавить новый APRecord
  5. Если для данного SSID существует >1 BSSID:
     a. Сравнить каналы — если разные, повысить уверенность
     b. Сравнить IE fingerprint (RSN IE, Vendor IEs) — если различаются, повысить уверенность
     c. Проверить Capability bits — различие в WPA/WPA2/WPA3 индикатор
  6. При достаточной уверенности → генерировать событие

Scoring (пример):
  - Разный BSSID для того же SSID: +50 (базовый)
  - Разный канал: +30
  - Различие в RSN IE: +40
  - Различие в Vendor IE: +20
  - Capability mismatch: +20
  - Порог срабатывания: 80
```

### Сравнение IE fingerprint

Ключевые Information Elements для сравнения:

| IE ID | Название | Важность |
|-------|----------|----------|
| 48 | RSN (WPA2) | Критичный — определяет параметры шифрования |
| 221 | Vendor Specific (WPA IE и другие) | Высокая — vendor fingerprint |
| 45 | HT Capabilities | Средняя — радио-характеристики |
| 191 | VHT Capabilities | Средняя |
| 127 | Extended Capabilities | Средняя |
| 1 | Supported Rates | Низкая |

```go
// Пример: проверка RSN IE
func compareRSN(ie1, ie2 map[uint8][]byte) bool {
    rsn1, ok1 := ie1[48]
    rsn2, ok2 := ie2[48]
    if ok1 != ok2 {
        return false // одна AP имеет RSN, другая нет
    }
    return bytes.Equal(rsn1, rsn2)
}
```

### Параметры конфигурации

| Параметр | Тип | Default | Описание |
|----------|-----|---------|----------|
| `enabled` | bool | true | Включение правила |
| `score_threshold` | int | 80 | Минимальный score для срабатывания |
| `stale_timeout` | duration | 5m | Таймаут удаления неактивных AP |
| `learning_period` | duration | 60s | Период обучения при запуске (не алертить) |
| `min_beacons` | int | 3 | Минимум beacon'ов от AP перед сравнением |

### SecurityEvent

| Поле | Значение |
|------|----------|
| `EventType` | `"evil_twin"` |
| `Severity` | `SeverityCritical` |
| `SrcMAC` | BSSID поддельной AP (новой) |
| `BSSID` | BSSID легитимной AP (первой наблюдённой) |
| `SSID` | Общий SSID |
| `Channel` | Канал поддельной AP |
| `RSSI` | RSSI поддельной AP |
| `Metadata["legitimate_bssid"]` | BSSID легитимной AP |
| `Metadata["legitimate_channel"]` | Канал легитимной AP |
| `Metadata["score"]` | Вычисленный score |
| `Metadata["ie_mismatch"]` | Список несовпавших IE |
| `Metadata["new_bssid"]` | BSSID подозрительной AP |
| `Metadata["new_channel"]` | Канал подозрительной AP |
| `Metadata["new_rssi"]` | RSSI подозрительной AP |
| `Metadata["min_beacons"]` | Порог минимального количества beacon'ов |

### Сложности реализации

1. **Множественные AP с одним SSID** — легитимная конфигурация (enterprise roaming). Решение: проверять IE fingerprint, а не только BSSID.
2. **Определение "легитимной" AP** — первая увиденная, или из whitelist (Phase 3).
3. **Очистка stale AP** — AP, не наблюдаемые в течение timeout, удаляются из state.
4. **Начальный learning period** — первые N минут после старта не генерировать алерты (опционально).

---

## 2.6 Beacon Flood

### Описание атаки

Атакующий генерирует массовое количество beacon-фреймов с разными (обычно случайными) BSSID и SSID. Цель — перегрузка WiFi-клиентов огромным количеством "видимых" сетей, истощение ресурсов и возможное нарушение нормальной работы (инструменты: mdk3 beacon flood mode).

### Признаки в эфире

- Резкий рост числа уникальных BSSID за короткий период
- Множество beacon'ов с разными SSID от MAC-адресов, не наблюдавшихся ранее
- Часто beacon'ы со случайными/нечитаемыми SSID
- Все фреймы приходят на одном канале
- RSSI может быть одинаковым (один физический передатчик)
- BeaconInterval и Capability могут быть одинаковыми для всех "фейковых" AP

### Поля ParsedFrame для проверки

| Поле | Назначение |
|------|-----------|
| `FrameType` | **Должен быть** `FrameTypeBeacon` |
| `BSSID` | Ключ уникальности — подсчёт новых BSSID |
| `SSID` | Дополнительный индикатор — множество новых SSID |
| `Channel` | Канал наблюдения |
| `Timestamp` | Для скользящего окна |
| `RSSI` | Одинаковый RSSI — индикатор одного передатчика |
| `BeaconInterval` | Одинаковый interval — fingerprint генератора |
| `Capability` | Одинаковый capability — fingerprint генератора |

### Алгоритм детектирования

```
Тип: Unique Counter (Sliding Window)
Ключ: Channel (или глобальный)

Состояние:
  window_bssids: map[Channel] → set of BSSIDs seen in current window
  known_bssids: set of previously established BSSIDs (before current window)

Для каждого beacon:
  1. Фильтр: frame.FrameType == FrameTypeBeacon
  2. Проверить: BSSID уже в known_bssids?
     - Да → обновить last_seen, пропустить
     - Нет → добавить в window_bssids (новый BSSID)
  3. Если count(window_bssids за последние N секунд) >= threshold:
     → Генерировать событие "beacon_flood"
  4. Периодически (раз в window) переносить window_bssids в known_bssids

Улучшение — дополнительная эвристика:
  - Группировка "новых" BSSID с одинаковым RSSI/Capability/BeaconInterval
  - Если >80% новых BSSID имеют идентичный RSSI — почти наверняка flood
```

### Параметры конфигурации

| Параметр | Тип | Default | Описание |
|----------|-----|---------|----------|
| `threshold` | int | 50 | Минимум новых уникальных BSSID для срабатывания |
| `window` | duration | 10s | Окно подсчёта |
| `learning_period` | duration | 60s | Период обучения при запуске (не алертить) |

### SecurityEvent

| Поле | Значение |
|------|----------|
| `EventType` | `"beacon_flood"` |
| `Severity` | `SeverityWarning` |
| `Channel` | Канал, где обнаружен flood |
| `FrameCount` | Общее количество beacon'ов в окне |
| `Description` | "N new unique BSSIDs in Xs" |
| `Metadata["new_bssid_count"]` | Количество новых BSSID |
| `Metadata["sample_ssids"]` | Несколько примеров SSID (для UI) |
| `Metadata["common_rssi"]` | Если RSSI одинаковый — указать |

### Примечания

- `SrcMAC` в событии заполняется MAC-адресом отправителя из триггерного фрейма.
- Severity — `Warning`, а не `Critical`, т.к. атака является DoS, но не приводит к утечке данных.

---

## 2.7 Unauthorized Device

### Описание атаки

Устройство, не находящееся в whitelist, пытается ассоциироваться с защищаемой точкой доступа. Может указывать на:
- Попытку несанкционированного доступа к сети
- Rogue device в периметре
- Успешную атаку Evil Twin (клиент переключился)

### Признаки в эфире

- Association Request/Response от MAC, отсутствующего в whitelist
- Probe Request, направленный на конкретный защищаемый SSID от неизвестного MAC
- Authentication frame от неизвестного устройства к защищаемой AP

### Поля ParsedFrame для проверки

| Поле | Назначение |
|------|-----------|
| `FrameType` | `FrameTypeAssocReq`, `FrameTypeReassocReq`, `FrameTypeAuth`, `FrameTypeProbeRequest` |
| `SrcMAC` | MAC устройства — проверка по whitelist |
| `DstMAC` | MAC точки доступа (должна быть защищаемой) |
| `BSSID` | BSSID защищаемой AP |
| `SSID` | SSID защищаемой сети (из probe/assoc request) |
| `Timestamp` | Время попытки |
| `Channel` | Канал |
| `RSSI` | Оценка расстояния устройства |

### Алгоритм детектирования

```
Тип: Whitelist Lookup
Ключи конфигурации:
  - protected_bssids: []MAC — список BSSID защищаемых AP
  - protected_ssids: []string — список SSID защищаемых сетей (для probe request)
  - whitelist: []MAC — разрешённые клиентские устройства

Для каждого входящего фрейма:
  1. Фильтр по типу:
     - FrameTypeAssocReq / FrameTypeReassocReq — клиент пытается подключиться
     - FrameTypeAuth — клиент начинает аутентификацию
     - FrameTypeProbeRequest с конкретным SSID (если alert_on_probe: true)
  2. Проверить: BSSID ∈ protected_bssids? (для assoc/auth)
     - Для ProbeRequest: SSID ∈ protected_ssids?
     - Нет → нерелевантная AP/сеть, пропустить
  3. Проверить: SrcMAC ∈ whitelist?
     - Да → легитимный клиент, пропустить
     - Нет → неизвестное устройство → генерировать событие
  4. Защита от спама: cooldown по SrcMAC (не генерировать повторно для одного устройства)
```

### Параметры конфигурации

| Параметр | Тип | Default | Описание |
|----------|-----|---------|----------|
| `enabled` | bool | false | Включение (по умолчанию отключено, т.к. требует whitelist) |
| `protected_bssids` | []string | [] | Список BSSID защищаемых AP |
| `protected_ssids` | []string | [] | Список SSID защищаемых сетей (для probe request) |
| `whitelist` | []string | [] | Список разрешённых MAC клиентов |
| `alert_on_probe` | bool | false | Алертить на probe request (шумный) |
| `cooldown` | duration | 5m | Не алертить повторно для одного MAC в течение этого времени |

### SecurityEvent

| Поле | Значение |
|------|----------|
| `EventType` | `"unauthorized_device"` |
| `Severity` | `SeverityWarning` |
| `SrcMAC` | MAC неизвестного устройства |
| `DstMAC` | BSSID целевой AP |
| `BSSID` | BSSID защищаемой AP (из frame.BSSID; fallback на DstMAC) |
| `SSID` | SSID защищаемой сети (если доступен) |
| `Channel` | Канал |
| `RSSI` | Сила сигнала устройства |
| `Metadata["frame_type"]` | Тип фрейма, вызвавшего срабатывание ("assoc_req", "auth", etc.) |
| `Metadata["protected_target"]` | Целевой BSSID или SSID защищаемой AP |
| `Metadata["cooldown"]` | Установленный cooldown |

### Особенности реализации

1. **Whitelist необходим** — правило бесполезно без заполненного whitelist. На Phase 2 whitelist задаётся в конфиге. На Phase 3 — из state/storage.
2. **MAC Randomization** — современные устройства рандомизируют MAC при probe request'ах. Рекомендация: по умолчанию не алертить на probe request (`alert_on_probe: false`), т.к. это вызовет шквал false positives.
3. **Protected BSSIDs / SSIDs** — если не заданы, правило не может работать; `Init()` должен вернуть ошибку или правило должно быть отключено. При `alert_on_probe: true` необходимо задать хотя бы один `protected_ssid`.
4. **Cooldown** — внутренний механизм (в дополнение к Engine dedup) для подавления повторных алертов для одного MAC.

---

## Сводная таблица

| Правило | FrameType фильтр | Ключ трекинга | Алгоритм | Severity |
|---------|-------------------|---------------|----------|----------|
| Deauth Flood | `FrameTypeDeauth` | SrcMAC | Sliding Window Counter | Critical |
| Disassoc Flood | `FrameTypeDisassoc` | SrcMAC | Sliding Window Counter | Critical |
| Evil Twin | `FrameTypeBeacon`, `FrameTypeProbeResponse` | SSID | State Table + Score | Critical |
| Beacon Flood | `FrameTypeBeacon` | Channel | Unique BSSID Counter | Warning |
| Unauthorized Device | `FrameTypeAssocReq`, `FrameTypeAuth`, `FrameTypeProbeRequest` | SrcMAC | Whitelist Lookup + Cooldown | Warning |

---

## Общие рекомендации по реализации

### Порядок реализации

1. **Deauth Flood (2.3)** → самый простой, паттерн sliding window
2. **Disassoc Flood (2.4)** → почти копия deauth, можно параметризовать
3. **Beacon Flood (2.6)** → unique counter, средняя сложность
4. **Evil Twin (2.5)** → наиболее сложная логика (state table, fingerprinting)
5. **Unauthorized Device (2.7)** → зависит от whitelist, простая логика lookup

### Общий паттерн: параметризованный FloodRule

Для задач 2.3 и 2.4 можно создать обобщённую реализацию:

```go
type FloodRule struct {
    name       string
    frameType  parser.FrameType
    threshold  int
    window     time.Duration
    tracker    map[string]*floodTracker
    mu         sync.Mutex
}
```

Это позволит избежать дублирования кода и упростить добавление аналогичных flood-правил в будущем (CTS/RTS flood в Phase 11).

### Тестовые pcap-файлы

Для каждого правила подготовить:
1. **Positive test** — pcap с данными атаки, правило ДОЛЖНО сработать
2. **Negative test** — pcap с нормальным трафиком, правило НЕ ДОЛЖНО сработать
3. **Edge case** — pcap на границе порога (threshold - 1 / threshold)

Использовать `internal/testutil/pcapgen.go`:
- `BuildDeauthFloodPcap()` → для deauth flood
- `BuildDisassocFloodPcap()` → для disassoc flood
- `BuildBeaconPcap()` с множественными вызовами → для beacon flood / evil twin
- `BuildAssocReqPcap()` → для unauthorized device
