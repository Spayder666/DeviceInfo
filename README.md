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
| Идентификаторы | Android ID, MAC, Advertising ID, Serial |
| Контакты / SMS | ContactsProvider, SmsManager |
| Сеть / API | HTTP-запросы (метаданные), connect(), сокеты |
| Разрешения | AppOps, checkPermission, requestPermissions |
| Хранилище | Файлы, MediaStore, ContentResolver |
| Датчики / Bluetooth | SensorManager, BluetoothAdapter |

## Источники данных (root)

1. **AppOps** (`dumpsys appops`) — фиксация фактического использования разрешений
2. **Logcat** (`logcat --pid=`) — системные логи API-вызовов
3. **strace** — системные вызовы: open, connect, ioctl, read/write
4. **/proc** — открытые файловые дескрипторы и TCP-соединения

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
MonitorActivity       → список событий + фильтры
AccessMonitorService  → foreground-сервис, оркестрация мониторов
  ├── AppOpsMonitor   → dumpsys appops
  ├── LogcatMonitor   → logcat --pid
  ├── StraceMonitor   → strace -p PID
  └── ProcMonitor     → /proc/PID/fd, /proc/PID/net
```

Данные хранятся локально в Room Database.
