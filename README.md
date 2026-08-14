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
| Идентификаторы (**222 типа**) | Build, IMEI, Android ID, GAID, Widevine, MAC, HTTP/2, Integrity verdict, root hide… |
| Root / Integrity | su, Magisk/Shamiko, Play Integrity verdict, VPN/CA/pin, hooks, isolated, .text |
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
9. **Perfetto / atrace** — короткие трейсы AM/WM/camera/audio/binder
10. **tcpdump / pcap** — заголовки пакетов (snaplen 96) и DNS QNAME, без расшифровки HTTPS
11. **statsd atoms** — системные счётчики location/camera/appops
12. **eBPF / qtaguid** — карты netd, xt_qtaguid, cgroup UID
13. **GMS internals / WorkManager** — Fused/NLP/Geofence и фоновые job'ы
14. **GNSS HAL / vendor** — lshal, `/dev/gnss*`, `/data/vendor/gps`
15. **am trace-ipc** — Binder IPC к LMS/camera/telephony
16. **unix / DnsResolver / ip6tables / nft** — локальные сокеты и IPv6 UID
17. **FGS / privacy / overlay** — типы foreground service и индикаторы камеры/GPS
18. **FCM / Sync / wakelock** — пуши и синк, которые будят локацию
19. **security / keystore / ANR** — буфер security, attestation, tombstones
20. **OEM + indoor** — IZat/HMS/SEM, Wi‑Fi RTT, UWB
21. **MITM HTTPS** (вручную) — plaintext запросов/ответов выбранного приложения

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
- **HTTPS MITM** только вручную (кнопка «MITM HTTPS»): локальный CA + iptables REDIRECT, ALPN `h2`/`http/1.1`, разбор HTTP/2 HEADERS и Frida `SSL_read`/`SSL_write` + снятие pinning. Не расшифровывает чужой Wi‑Fi — только выбранное приложение на этом устройстве.
- Токен Play Integrity на клиенте зашифрован: verdict (`MEETS_DEVICE_INTEGRITY` и т.д.) появляется, если сервер вернул JSON или виден SafetyNet JWS. Сырой SVC в `.text` (не через libc) не перехватывается.

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
  ├── PerfettoMonitor       → perfetto / atrace
  ├── TcpdumpMonitor        → pcap + DNS
  ├── StatsdMonitor         → atoms
  ├── EbpfMonitor           → bpf maps / qtaguid
  ├── GmsInternalsMonitor   → Fused / NLP / Geofence
  ├── WorkManagerMonitor    → jobs / WorkSpec
  ├── HalGnssMonitor        → GNSS HAL / vendor
  ├── BinderIpcMonitor      → am trace-ipc
  ├── UnixNetdMonitor       → unix / DNS / ip6 / nft
  ├── PrivacyFgsMonitor     → FGS / privacy / overlay
  ├── SyncPushMonitor       → FCM / sync / wake
  ├── SecurityKeystoreMonitor
  ├── OemIndoorMonitor      → IZat / RTT / UWB
  ├── RootDetectionMonitor  → maps / ports / RootBeer / LSPosed
  ├── EnvironmentAnalysisMonitor → Shamiko/DenyList, isolated, libc .text
  ├── NetworkEnvMonitor     → VPN / proxy / user CA / pin fail
  ├── DecisionTracker       → после root-check → login/403
  └── FridaMonitor          → ручной frida-inject + Java hooks
```

### Frida-хуки (release-сборки)

На release-сборках logcat часто молчит — Frida перехватывает Java API напрямую.

**Не** используется `wrap.*` / `LD_PRELOAD` (на Android 13+ вешает приложения). Инъекция только вручную: **Frida к запущенному** или **Запустить + Frida** (`frida-inject -p PID`).

Хуки: Location/GNSS/Fused, Telephony, Camera, Audio, OkHttp, HttpURLConnection, WebView, SQLite, SharedPreferences, файлы с lat/lon, Geofence, ActivityRecognition, WorkManager, ContentResolver, Build/getprop/Settings, Play Integrity / SafetyNet (в т.ч. token/JWS), NetworkCapabilities/VPN/proxy, pinning, Process.isIsolated, libc `syscall()`, RootBeer/Talsec/JailMonkey.

События: `/data/local/tmp/access_monitor/events.jsonl` → источник **Frida**.

Данные хранятся локально в Room Database.

## Каталог идентификаторов (222 типа)

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
| **NETWORK** | 15 | IP, MAC, HTTP/HTTPS/HTTP2, WebView, DNS, SNI, VPN, proxy, user CA, pin fail |
| **LOCATION** | 14 | GPS, fused, NLP, GNSS, geofence, cell, Wi‑Fi scan, RTT, UWB, HAL, SUPL |
| **ENTERPRISE** | 2 | Enrollment Specific ID, Organization ID |
| **OEM** | 6 | Samsung, Huawei, Vivo, OAID-специфичные ключи |
| **ATTESTATION** | 6 | Key attestation, StrongBox, Play Integrity, SafetyNet, **verdict**, verified boot |
| **ROOT** | 28 | su, Magisk, Shamiko/DenyList, isolated, .text диск≠RAM, libc syscall, Talsec, Frida/LSPosed |

Каждый идентификатор содержит: API, system property, file path, regex для logcat/strace, требуемое разрешение.

В UI: фильтр **ID** → подфильтры по группам (Build, Telephony, Settings, getprop…).
