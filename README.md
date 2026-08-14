# Access Monitor

Android-приложение для мониторинга **системных запросов** выбранного приложения через **root-доступ**.

Поддерживаемые версии Android: **13–17** (API 33–35).

## Что отслеживается

Приложение фиксирует обращения целевого приложения к:

| Категория | Примеры |
|-----------|---------|
| GPS / Геолокация | LocationManager, GNSS, Fused Location |
| Камера | Camera API, open(/dev/camera) |
| Микрофон | AudioRecord, MediaRecorder |
| Телефон / SIM | IMEI, IMSI, номер SIM, TelephonyManager |
| Идентификаторы (**159 типов**) | Build, IMEI, Android ID, GAID, Widevine, MAC, HTTP URL… |
| Контакты / SMS | ContactsProvider, SmsManager |
| Сеть / API | HTTP-запросы (метаданные), connect(), сокеты |
| Разрешения | AppOps, checkPermission, requestPermissions |
| Хранилище | Файлы, MediaStore, ContentResolver |
| Датчики / Bluetooth | SensorManager, BluetoothAdapter |

## Источники данных (root)

1. **AppOps** (`dumpsys appops`) — фактическое использование разрешений
2. **Logcat** (`logcat --uid=` + системные теги + буферы events/radio/crash/kernel)
3. **strace** — системные вызовы: open, connect, ioctl, read/write
4. **/proc** — дескрипторы, TCP/UDP, `/proc/maps` (нативные SDK)
5. **dumpsys / cmd** — LMS, GNSS, камера, RIL, Health Connect, Nearby, `cmd location`…
6. **Binder / iptables UID LOG / ss** — IPC и сеть без VPN/MITM
7. **inotify / sqlite** — запись в `/data/data/<pkg>` (кэш GPS, prefs, БД)
8. **Frida** (вручную) — Java API: Location, OkHttp, WebView, SQLite, SharedPreferences

## Требования

- Android 13+ (API 33)
- **Root-доступ (su)** на устройстве
- `strace` в системе (обычно `/system/bin/strace`)

## Сборка

```bash
./gradlew assembleDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`

## Использование

1. Установите APK и предоставьте root-доступ приложению
2. Выберите целевое приложение из списка
3. Нажмите на приложение — начнётся мониторинг
4. Запустите целевое приложение (кнопка ▶ в панели мониторинга)
5. Выполняйте действия в целевом приложении — все запросы отображаются в реальном времени
6. Нажмите на событие для просмотра полных данных (запрос, ответ, raw-лог)

## Ограничения

- Без root мониторинг невозможен
- Некоторые API могут не попадать в logcat на release-сборках (обфускация/ProGuard)
- strace может быть недоступен на некоторых прошивках
- Приложение **не перехватывает содержимое HTTPS-трафика** — фиксируются только метаданные сетевых подключений и API-вызовы из логов

## Архитектура

```
MainActivity          → выбор приложения
MonitorActivity       → список событий + фильтры + проба ответа
AccessMonitorService  → foreground-сервис
  ├── AppOpsMonitor
  ├── LogcatMonitor / SystemLogcatMonitor / ExtraLogcatMonitor
  ├── StraceMonitor / ProcMonitor
  ├── LocationDumpMonitor / ComprehensiveDumpMonitor
  ├── ExtraChannelMonitor   → binder, maps, ss, iptables, sqlite, intents
  ├── KernelAuditMonitor    → SELinux AVC, kernel/binder
  ├── CmdApiMonitor         → cmd location/wifi/phone/…
  ├── InotifyDataMonitor    → /data/data/<pkg>
  └── FridaMonitor          → ручной frida-inject + Java hooks
```

### Frida-хуки (release-сборки)

На release-сборках logcat часто молчит — Frida перехватывает Java API напрямую.

**Не** используется `wrap.*` / `LD_PRELOAD` (на Android 13+ вешает приложения). Инъекция только вручную: **Frida к запущенному** или **Запустить + Frida** (`frida-inject -p PID`).

Хуки: Location/GNSS/Fused, Telephony, Camera, Audio, OkHttp, HttpURLConnection, WebView, SQLite, SharedPreferences, файлы с lat/lon, Geofence, ActivityRecognition, WorkManager, ContentResolver, Build/getprop/Settings.

События: `/data/local/tmp/access_monitor/events.jsonl` → источник **Frida**.

Данные хранятся локально в Room Database.

## Каталог идентификаторов (159 типов)

Полный список в `app/src/main/java/.../identifiers/IdentifierCatalog.kt`, основан на AOSP (`Build.java`, `TelephonyManager`, `SettingsProvider`, `MediaDrm`).

| Группа | Кол-во | Что входит |
|--------|--------|------------|
| **BUILD** | 27 | MODEL, MANUFACTURER, DEVICE, BRAND, HARDWARE, BOARD, FINGERPRINT, SERIAL, SOC, SKU, ABI, эмулятор… |
| **OS_VERSION** | 9 | SDK, RELEASE, security patch, incremental, codename, **версия ядра** (`/proc/version`) |
| **SYSTEM_PROPERTY** | 17 | `getprop`: ro.serialno, ro.product.*, ro.build.*, gsm.*, persist.radio.imei… |
| **SETTINGS** | 7 | Android ID (SSAID), bluetooth_address/name, device_name, settings providers |
| **TELEPHONY** | 19 | IMEI, MEID, IMSI, ICCID, номер телефона, MCC/MNC, carrier ID, TAC, IMEISV… |
| **SUBSCRIPTION** | 9 | Subscription ID, ICCID, phone number, SIM slot, MCC/MNC, eSIM port |
| **WIFI** | 9 | MAC, BSSID, SSID, scan results, IP, sysfs MAC |
| **BLUETOOTH** | 6 | Local/remote MAC и name, sysfs, audio device MAC |
| **ADVERTISING** | 7 | GAID, GSF ID, Firebase FID, App Set ID, OAID, limit ad tracking |
| **DRM** | 6 | Widevine deviceUniqueId, PlayReady, security level L1/L3 |
| **INSTALL** | 5 | Install referrer, installer package, signing cert, install times |
| **ACCOUNT** | 5 | AccountManager, email, auth token, Google Sign-In |
| **CONTENT_PROVIDER** | 6 | telephony/siminfo, GSF, settings, ICC, SQLite, SharedPreferences |
| **PROC_SYS** | 9 | /proc/cpuinfo, meminfo, version, boot_id, auxv, __properties__, CPU topology, файлы приложения |
| **NETWORK** | 6 | IP, MAC, hostname, IPv6, HTTP URL, WebView |
| **ENTERPRISE** | 2 | Enrollment Specific ID, Organization ID |
| **OEM** | 5 | Samsung, Huawei, Vivo, OAID-специфичные ключи |
| **ATTESTATION** | 5 | Key attestation, StrongBox, Play Integrity, SafetyNet, verified boot |

Каждый идентификатор содержит: API, system property, file path, regex для logcat/strace, требуемое разрешение.

В UI: фильтр **ID** → подфильтры по группам (Build, Telephony, Settings, getprop…).
