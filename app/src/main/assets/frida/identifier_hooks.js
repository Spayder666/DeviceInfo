'use strict';

var EVENT_FILE = '/data/local/tmp/access_monitor/events.jsonl';
var TARGET_PKG = '__TARGET_PACKAGE__';

var nativeIo = null;

function initNativeIo() {
  if (nativeIo) return nativeIo;
  try {
    nativeIo = {
      fopen: new NativeFunction(Module.findExportByName('libc.so', 'fopen'), 'pointer', ['pointer', 'pointer']),
      fwrite: new NativeFunction(Module.findExportByName('libc.so', 'fwrite'), 'int', ['pointer', 'int', 'int', 'pointer']),
      fclose: new NativeFunction(Module.findExportByName('libc.so', 'fclose'), 'int', ['pointer'])
    };
  } catch (e) {
    nativeIo = null;
  }
  return nativeIo;
}

function jsonEscape(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function writeLine(line) {
  var io = initNativeIo();
  if (!io) return;
  try {
    var path = Memory.allocUtf8String(EVENT_FILE);
    var mode = Memory.allocUtf8String('a');
    var fp = io.fopen(path, mode);
    if (fp.isNull()) return;
    var payload = line + '\n';
    var buf = Memory.allocUtf8String(payload);
    io.fwrite(buf, 1, payload.length, fp);
    io.fclose(fp);
  } catch (e) {}
}

function writeEvent(identifierId, action, request, response, permission) {
  var ts = Date.now();
  var line = '{"identifierId":"' + jsonEscape(identifierId || '') +
    '","action":"' + jsonEscape(action || '') +
    '","request":"' + jsonEscape(request || '') +
    '","response":"' + jsonEscape(response || '') +
    '","permission":"' + jsonEscape(permission || '') +
    '","timestamp":' + ts +
    ',"source":"frida"}';
  writeLine(line);
}

function safeStr(v) {
  if (v === null || v === undefined) return '';
  try { return String(v); } catch (e) { return '<error>'; }
}

function hookTelephonyManager() {
  var TM = Java.use('android.telephony.TelephonyManager');
  var hooks = [
    ['getImei', 'tel.imei', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getMeid', 'tel.meid', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getDeviceId', 'tel.device_id', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getSubscriberId', 'tel.subscriber_id', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getSimSerialNumber', 'tel.sim_serial', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getLine1Number', 'tel.line1_number', 'READ_PHONE_NUMBERS'],
    ['getPrimaryImei', 'tel.imei', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getNai', 'tel.nai', 'READ_PHONE_STATE'],
    ['getGroupIdLevel1', 'tel.group_id', 'READ_PHONE_STATE'],
    ['getTypeAllocationCode', 'tel.tac', null],
    ['getDeviceSoftwareVersion', 'tel.software_version', 'READ_PHONE_STATE'],
    ['getNetworkOperator', 'tel.network_operator', null],
    ['getNetworkOperatorName', 'tel.network_operator_name', null],
    ['getNetworkCountryIso', 'tel.network_country', null],
    ['getSimOperator', 'tel.sim_operator', null],
    ['getSimOperatorName', 'tel.sim_operator_name', null],
    ['getSimCountryIso', 'tel.sim_country', null],
    ['getSimCarrierId', 'tel.carrier_id', null],
    ['getVoiceMailNumber', 'tel.voicemail', 'READ_PHONE_STATE']
  ];

  hooks.forEach(function (h) {
    var method = h[0], id = h[1], perm = h[2];
    try {
      TM[method].overloads.forEach(function (overload) {
        overload.implementation = function () {
          var args = [];
          for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
          var result = overload.apply(this, arguments);
          writeEvent(id, 'TelephonyManager.' + method, JSON.stringify(args), safeStr(result), perm);
          return result;
        };
      });
    } catch (e) {}
  });
}

function hookSubscriptionManager() {
  try {
    var SM = Java.use('android.telephony.SubscriptionManager');
    ['getPhoneNumber', 'getActiveSubscriptionInfoList', 'getSubscriptionId'].forEach(function (m) {
      try {
        SM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('sub.phone_number', 'SubscriptionManager.' + m, '', safeStr(result), 'READ_PHONE_NUMBERS');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var SI = Java.use('android.telephony.SubscriptionInfo');
    ['getIccId', 'getSubscriptionId', 'getSimSlotIndex', 'getMccString', 'getMncString', 'getCardId'].forEach(function (m) {
      try {
        SI[m].implementation = function () {
          var result = this[m]();
          writeEvent('sub.iccid', 'SubscriptionInfo.' + m, '', safeStr(result), null);
          return result;
        };
      } catch (e) {}
    });
  } catch (e) {}
}

function hookSettings() {
  var classes = [
    ['android.provider.Settings$Secure', 'settings.android_id'],
    ['android.provider.Settings$Global', 'settings.device_name'],
    ['android.provider.Settings$System', 'settings.system']
  ];
  classes.forEach(function (c) {
    try {
      var Cls = Java.use(c[0]);
      Cls.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, key) {
        var result = this.getString(cr, key);
        var id = key === 'android_id' ? 'settings.android_id' : c[1];
        writeEvent(id, c[0] + '.getString', safeStr(key), safeStr(result), null);
        return result;
      };
    } catch (e) {}
  });
}

function hookSystemProperties() {
  try {
    var SP = Java.use('android.os.SystemProperties');
    ['get', 'getInt', 'getLong', 'getBoolean'].forEach(function (m) {
      try {
        SP[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var key = arguments[0] ? safeStr(arguments[0]) : '';
            var result = overload.apply(this, arguments);
            if (isInterestingProperty(key)) {
              writeEvent(mapPropertyToId(key), 'SystemProperties.' + m, key, safeStr(result), null);
            }
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function isInterestingProperty(key) {
  if (!key) return false;
  return key.indexOf('ro.serial') === 0 ||
    key.indexOf('ro.boot.serial') === 0 ||
    key.indexOf('persist.radio') === 0 ||
    key.indexOf('gsm.') === 0 ||
    key === 'ro.product.model' ||
    key === 'ro.product.manufacturer' ||
    key === 'ro.build.fingerprint' ||
    key === 'ro.bootimage.build.fingerprint' ||
    key === 'ro.build.version.security_patch';
}

function mapPropertyToId(key) {
  var map = {
    'ro.product.model': 'build.model',
    'ro.product.manufacturer': 'build.manufacturer',
    'ro.product.device': 'build.device',
    'ro.product.brand': 'build.brand',
    'ro.product.name': 'build.product',
    'ro.hardware': 'build.hardware',
    'ro.build.fingerprint': 'build.fingerprint',
    'ro.bootimage.build.fingerprint': 'prop.bootimage.fingerprint',
    'ro.serialno': 'build.serial',
    'ro.boot.serialno': 'prop.boot.serialno',
    'ro.build.version.release': 'version.release',
    'ro.build.version.sdk': 'version.sdk',
    'ro.build.version.security_patch': 'version.security_patch',
    'gsm.version.baseband': 'prop.gsm.version.baseband',
    'persist.radio.imei': 'prop.persist.radio.imei'
  };
  return map[key] || 'getprop.shell';
}

function hookBuild() {
  try {
    var Build = Java.use('android.os.Build');
    Build.getSerial.implementation = function () {
      var result = this.getSerial();
      writeEvent('build.serial', 'Build.getSerial()', '', safeStr(result), 'READ_PRIVILEGED_PHONE_STATE');
      return result;
    };
  } catch (e) {}
}

function hookWifiAndBluetooth() {
  try {
    var WifiInfo = Java.use('android.net.wifi.WifiInfo');
    ['getMacAddress', 'getBSSID', 'getSSID', 'getNetworkId', 'getIpAddress'].forEach(function (m) {
      try {
        WifiInfo[m].implementation = function () {
          var result = this[m]();
          writeEvent('wifi.mac', 'WifiInfo.' + m, '', safeStr(result), 'ACCESS_FINE_LOCATION');
          return result;
        };
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var WM = Java.use('android.net.wifi.WifiManager');
    WM.getScanResults.implementation = function () {
      var result = this.getScanResults();
      writeEvent('wifi.scan_results', 'WifiManager.getScanResults', '', 'count=' + (result ? result.size() : 0), 'ACCESS_FINE_LOCATION');
      return result;
    };
  } catch (e) {}

  try {
    var BA = Java.use('android.bluetooth.BluetoothAdapter');
    ['getAddress', 'getName'].forEach(function (m) {
      try {
        BA[m].implementation = function () {
          var result = this[m]();
          writeEvent('bt.local_mac', 'BluetoothAdapter.' + m, '', safeStr(result), 'BLUETOOTH_CONNECT');
          return result;
        };
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var BD = Java.use('android.bluetooth.BluetoothDevice');
    ['getAddress', 'getName'].forEach(function (m) {
      try {
        BD[m].implementation = function () {
          var result = this[m]();
          writeEvent('bt.remote_mac', 'BluetoothDevice.' + m, '', safeStr(result), 'BLUETOOTH_CONNECT');
          return result;
        };
      } catch (e) {}
    });
  } catch (e) {}
}

function hookMediaDrm() {
  try {
    var MD = Java.use('android.media.MediaDrm');
    MD.getPropertyByteArray.implementation = function (key) {
      var result = this.getPropertyByteArray(key);
      var id = key === 'deviceUniqueId' ? 'drm.widevine_id' : 'drm.vendor';
      writeEvent(id, 'MediaDrm.getPropertyByteArray', safeStr(key), 'bytes=' + result.length, null);
      return result;
    };
    MD.getPropertyString.implementation = function (key) {
      var result = this.getPropertyString(key);
      writeEvent('drm.version', 'MediaDrm.getPropertyString', safeStr(key), safeStr(result), null);
      return result;
    };
  } catch (e) {}
}

function hookAdvertisingId() {
  try {
    var AIC = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient');
    AIC.getAdvertisingIdInfo.overload('android.content.Context').implementation = function (ctx) {
      var result = this.getAdvertisingIdInfo(ctx);
      try {
        var id = result.getId();
        var limited = result.isLimitAdTrackingEnabled();
        writeEvent('ad.gaid', 'AdvertisingIdClient.getAdvertisingIdInfo', '', safeStr(id) + ' limited=' + limited, 'AD_ID');
      } catch (e) {}
      return result;
    };
  } catch (e) {}
}

function hookAccounts() {
  try {
    var AM = Java.use('android.accounts.AccountManager');
    ['getAccounts', 'getAccountsByType', 'getAccountsAsUser'].forEach(function (m) {
      try {
        AM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('account.list', 'AccountManager.' + m, safeStr(arguments[0]), 'count=' + (result ? result.length : 0), 'GET_ACCOUNTS');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookNetworkInterface() {
  try {
    var NI = Java.use('java.net.NetworkInterface');
    NI.getHardwareAddress.implementation = function () {
      var result = this.getHardwareAddress();
      writeEvent('net.hardware_address', 'NetworkInterface.getHardwareAddress', this.getName(), bytesToHex(result), null);
      return result;
    };
  } catch (e) {}
}

function bytesToHex(bytes) {
  if (!bytes) return '';
  var hex = [];
  for (var i = 0; i < bytes.length; i++) {
    hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
  }
  return hex.join(':');
}

function hookPackageManager() {
  try {
    var PM = Java.use('android.content.pm.PackageManager');
    PM.getInstallerPackageName.implementation = function (pkg) {
      var result = this.getInstallerPackageName(pkg);
      writeEvent('install.installer', 'PackageManager.getInstallerPackageName', safeStr(pkg), safeStr(result), null);
      return result;
    };
  } catch (e) {}
}

function hookContentResolver() {
  try {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var uri = arguments[0] ? safeStr(arguments[0].toString()) : '';
        var result = overload.apply(this, arguments);
        if (uri.indexOf('settings') >= 0 || uri.indexOf('telephony') >= 0 || uri.indexOf('gsf') >= 0 ||
            uri.indexOf('contacts') >= 0 || uri.indexOf('sms') >= 0 || uri.indexOf('mms') >= 0 ||
            uri.indexOf('call_log') >= 0 || uri.indexOf('calendar') >= 0 || uri.indexOf('media') >= 0 ||
            uri.indexOf('browser') >= 0 || uri.indexOf('voicemail') >= 0 || uri.indexOf('blocked') >= 0) {
          var rows = 0;
          try { rows = result ? result.getCount() : 0; } catch (e) {}
          writeEvent('cp.settings_secure', 'ContentResolver.query', uri, 'rows=' + rows, null);
        }
        return result;
      };
    });
  } catch (e) {}
}

function formatLocation(loc) {
  if (!loc) return '';
  try {
    return 'lat=' + loc.getLatitude() + ' lon=' + loc.getLongitude() +
      ' acc=' + loc.getAccuracy() + ' provider=' + loc.getProvider() +
      ' time=' + loc.getTime();
  } catch (e) {
    return safeStr(loc);
  }
}

function hookLocation() {
  try {
    var LM = Java.use('android.location.LocationManager');
    var methods = [
      'getLastKnownLocation', 'requestLocationUpdates', 'requestSingleUpdate',
      'getCurrentLocation', 'removeUpdates', 'getProviders', 'getAllProviders',
      'isProviderEnabled', 'getBestProvider', 'addNmeaListener',
      'registerGnssStatusCallback', 'registerGnssMeasurementsCallback',
      'registerGnssNavigationMessageCallback', 'addGpsStatusListener',
      'sendExtraCommand', 'getGnssYearOfHardware'
    ];
    methods.forEach(function (m) {
      try {
        LM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var args = [];
            for (var i = 0; i < arguments.length; i++) args.push(safeStr(arguments[i]));
            var result = overload.apply(this, arguments);
            var response = (m.indexOf('getLast') === 0 || m === 'getCurrentLocation')
              ? formatLocation(result) : safeStr(result);
            writeEvent('location.gps', 'LocationManager.' + m, args.join(', '), response, 'ACCESS_FINE_LOCATION');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var Loc = Java.use('android.location.Location');
    Loc.getLatitude.implementation = function () {
      var lat = this.getLatitude();
      var lon = this.getLongitude();
      writeEvent('location.gps', 'Location.getLatitude', this.getProvider(), 'lat=' + lat + ' lon=' + lon, 'ACCESS_FINE_LOCATION');
      return lat;
    };
  } catch (e) {}

  try {
    var Listener = Java.use('android.location.LocationListener');
    Listener.onLocationChanged.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var loc = arguments[0];
        writeEvent('location.gps', 'LocationListener.onLocationChanged', '', formatLocation(loc), 'ACCESS_FINE_LOCATION');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}

  try {
    var CB = Java.use('android.location.LocationCallback');
    CB.onLocationResult.implementation = function (result) {
      var text = '';
      try {
        var list = result.getLocations();
        for (var i = 0; i < list.size(); i++) text += formatLocation(list.get(i)) + '; ';
      } catch (e) { text = safeStr(result); }
      writeEvent('location.fused', 'LocationCallback.onLocationResult', '', text, 'ACCESS_FINE_LOCATION');
      return this.onLocationResult(result);
    };
  } catch (e) {}

  try {
    var FLP = Java.use('com.google.android.gms.location.FusedLocationProviderClient');
    ['getLastLocation', 'getCurrentLocation', 'requestLocationUpdates', 'getLastLocation'].forEach(function (m) {
      try {
        FLP[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            writeEvent('location.fused', 'FusedLocationProviderClient.' + m, safeStr(arguments[0]), 'Task scheduled', 'ACCESS_FINE_LOCATION');
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var LR = Java.use('com.google.android.gms.location.LocationResult');
    LR.getLastLocation.implementation = function () {
      var loc = this.getLastLocation();
      writeEvent('location.fused', 'LocationResult.getLastLocation', '', formatLocation(loc), 'ACCESS_FINE_LOCATION');
      return loc;
    };
  } catch (e) {}

  try {
    var TM = Java.use('android.telephony.TelephonyManager');
    ['getAllCellInfo', 'getCellLocation', 'requestCellInfoUpdate', 'getNeighboringCellInfo'].forEach(function (m) {
      try {
        TM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('location.cell', 'TelephonyManager.' + m, '', safeStr(result), 'ACCESS_FINE_LOCATION');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookNativeProperties() {
  var addr = Module.findExportByName('libc.so', '__system_property_get');
  if (!addr) return;
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          this.key = Memory.readUtf8String(args[0]);
          this.valueBuf = args[1];
        } catch (e) {
          this.key = '';
        }
      },
      onLeave: function (retval) {
        if (!isInterestingProperty(this.key)) return;
        var response;
        var len = retval.toInt32();
        if (len > 0 && this.valueBuf) {
          response = Memory.readUtf8String(this.valueBuf);
        } else if (len === 0) {
          response = '(пусто — не найдено или access denied)';
        } else {
          response = '(ошибка, код=' + len + ')';
        }
        writeEvent(mapPropertyToId(this.key), '__system_property_get', this.key, response, null);
      }
    });
  } catch (e) {}
}

function hookCamera() {
  try {
    var CM = Java.use('android.hardware.camera2.CameraManager');
    ['openCamera', 'openCameraForUid', 'getCameraIdList'].forEach(function (m) {
      try {
        CM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('location.gps', 'CameraManager.' + m, safeStr(arguments[0]), safeStr(result), 'CAMERA');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Cam = Java.use('android.hardware.Camera');
    Cam.open.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('location.gps', 'Camera.open', safeStr(arguments[0]), 'opened', 'CAMERA');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookAudio() {
  try {
    var AR = Java.use('android.media.AudioRecord');
    AR.startRecording.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('location.gps', 'AudioRecord.startRecording', '', 'recording', 'RECORD_AUDIO');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var MR = Java.use('android.media.MediaRecorder');
    MR.start.implementation = function () {
      writeEvent('location.gps', 'MediaRecorder.start', '', 'recording', 'RECORD_AUDIO');
      return this.start();
    };
  } catch (e) {}
  try {
    var AM = Java.use('android.media.AudioManager');
    ['getMode', 'setMode', 'isMicrophoneMute'].forEach(function (m) {
      try {
        AM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('location.gps', 'AudioManager.' + m, '', safeStr(result), 'RECORD_AUDIO');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookSensors() {
  try {
    var SM = Java.use('android.hardware.SensorManager');
    SM.registerListener.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var sensor = '';
        try { sensor = safeStr(arguments[1]); } catch (e) {}
        writeEvent('location.gps', 'SensorManager.registerListener', sensor, 'registered', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookClipboard() {
  try {
    var CL = Java.use('android.content.ClipboardManager');
    ['getPrimaryClip', 'setPrimaryClip', 'getText', 'hasPrimaryClip'].forEach(function (m) {
      try {
        CL[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('location.gps', 'ClipboardManager.' + m, '', safeStr(result), 'READ_CLIPBOARD');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookSms() {
  try {
    var SM = Java.use('android.telephony.SmsManager');
    ['sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage', 'getDefault'].forEach(function (m) {
      try {
        SM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var args = [];
            for (var i = 0; i < Math.min(arguments.length, 3); i++) args.push(safeStr(arguments[i]));
            var result = overload.apply(this, arguments);
            writeEvent('location.gps', 'SmsManager.' + m, args.join(', '), safeStr(result), 'SEND_SMS');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookNetworkDeep() {
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        writeEvent('net.hostname', 'URL.openConnection', safeStr(this.toString()), safeStr(result), null);
        return result;
      };
    });
  } catch (e) {}
  try {
    var CM = Java.use('android.net.ConnectivityManager');
    ['getActiveNetworkInfo', 'getActiveNetwork', 'requestNetwork', 'registerDefaultNetworkCallback'].forEach(function (m) {
      try {
        CM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('net.link_addresses', 'ConnectivityManager.' + m, '', safeStr(result), null);
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookBiometric() {
  try {
    var BP = Java.use('android.hardware.biometrics.BiometricPrompt');
    BP.authenticate.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('attest.key', 'BiometricPrompt.authenticate', '', 'prompt', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookMediaProjection() {
  try {
    var MPM = Java.use('android.media.projection.MediaProjectionManager');
    MPM.createScreenCaptureIntent.implementation = function () {
      writeEvent('location.gps', 'MediaProjectionManager.createScreenCaptureIntent', '', 'screen capture', null);
      return this.createScreenCaptureIntent();
    };
  } catch (e) {}
}

function looksSensitive(text) {
  var s = String(text || '').toLowerCase();
  return /lat|lon|gps|location|imei|android_id|ssid|bssid|token|device|track|coord|http/.test(s);
}

function hookOkHttp() {
  try {
    var RealCall = Java.use('okhttp3.RealCall');
    RealCall.execute.implementation = function () {
      var req = this.request();
      var url = '';
      var method = '';
      try { url = req.url().toString(); method = req.method(); } catch (e) {}
      var resp = this.execute();
      var code = '';
      try { code = '' + resp.code(); } catch (e) {}
      writeEvent('net.http', 'OkHttp.execute', method + ' ' + url, 'HTTP ' + code, null);
      return resp;
    };
    RealCall.enqueue.implementation = function (cb) {
      var req = this.request();
      try {
        writeEvent('net.http', 'OkHttp.enqueue', req.method() + ' ' + req.url().toString(), 'async', null);
      } catch (e) {}
      return this.enqueue(cb);
    };
  } catch (e) {}
  try {
    var Client = Java.use('okhttp3.OkHttpClient');
    Client.newCall.implementation = function (request) {
      try {
        writeEvent('net.http', 'OkHttp.newCall', request.method() + ' ' + request.url().toString(), '', null);
      } catch (e) {}
      return this.newCall(request);
    };
  } catch (e) {}
}

function hookHttpUrlConnection() {
  try {
    var Http = Java.use('java.net.HttpURLConnection');
    Http.connect.implementation = function () {
      writeEvent('net.http', 'HttpURLConnection.connect', safeStr(this.getURL()), '', null);
      return this.connect();
    };
    Http.getResponseCode.implementation = function () {
      var code = this.getResponseCode();
      writeEvent('net.http', 'HttpURLConnection.getResponseCode', safeStr(this.getURL()), '' + code, null);
      return code;
    };
  } catch (e) {}
}

function hookWebView() {
  try {
    var WV = Java.use('android.webkit.WebView');
    WV.loadUrl.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('net.webview', 'WebView.loadUrl', safeStr(arguments[0]), '', null);
        return overload.apply(this, arguments);
      };
    });
    try {
      WV.evaluateJavascript.implementation = function (script, cb) {
        writeEvent('net.webview', 'WebView.evaluateJavascript', safeStr(script).substring(0, 200), '', null);
        return this.evaluateJavascript(script, cb);
      };
    } catch (e) {}
    try {
      WV.loadDataWithBaseURL.overloads.forEach(function (overload) {
        overload.implementation = function () {
          writeEvent('net.webview', 'WebView.loadDataWithBaseURL', safeStr(arguments[0]), '', null);
          return overload.apply(this, arguments);
        };
      });
    } catch (e) {}
  } catch (e) {}
}

function hookSqlite() {
  try {
    var DB = Java.use('android.database.sqlite.SQLiteDatabase');
    DB.rawQuery.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var sql = safeStr(arguments[0]);
        var result = overload.apply(this, arguments);
        if (looksSensitive(sql)) {
          var rows = 0;
          try { rows = result ? result.getCount() : 0; } catch (e) {}
          writeEvent('storage.sqlite', 'SQLiteDatabase.rawQuery', sql, 'rows=' + rows, null);
        }
        return result;
      };
    });
    ['insert', 'update', 'delete', 'execSQL'].forEach(function (m) {
      try {
        DB[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var args = [];
            for (var i = 0; i < Math.min(arguments.length, 2); i++) args.push(safeStr(arguments[i]));
            var joined = args.join(' ');
            var result = overload.apply(this, arguments);
            if (looksSensitive(joined)) {
              writeEvent('storage.sqlite', 'SQLiteDatabase.' + m, joined, safeStr(result), null);
            }
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookSharedPrefs() {
  try {
    var SP = Java.use('android.app.SharedPreferencesImpl');
    ['getString', 'getLong', 'getInt', 'getBoolean', 'getFloat'].forEach(function (m) {
      try {
        SP[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var key = safeStr(arguments[0]);
            var result = overload.apply(this, arguments);
            if (looksSensitive(key) || looksSensitive(result)) {
              writeEvent('storage.prefs', 'SharedPreferences.' + m, key, safeStr(result), null);
            }
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    ['putString', 'putLong', 'putInt'].forEach(function (m) {
      try {
        Editor[m].implementation = function (key, value) {
          if (looksSensitive(key) || looksSensitive(value)) {
            writeEvent('storage.prefs', 'SharedPreferences.Editor.' + m, safeStr(key), safeStr(value), null);
          }
          return this[m](key, value);
        };
      } catch (e) {}
    });
  } catch (e) {}
}

function hookSensitiveFiles() {
  try {
    var FIS = Java.use('java.io.FileInputStream');
    FIS.$init.overload('java.io.File').implementation = function (file) {
      var path = '';
      try { path = file.getAbsolutePath(); } catch (e) {}
      if (looksSensitive(path)) {
        writeEvent('storage.file', 'FileInputStream', path, '', null);
      }
      return this.$init(file);
    };
  } catch (e) {}
  try {
    var FOS = Java.use('java.io.FileOutputStream');
    FOS.$init.overload('java.io.File').implementation = function (file) {
      var path = '';
      try { path = file.getAbsolutePath(); } catch (e) {}
      if (looksSensitive(path)) {
        writeEvent('storage.file', 'FileOutputStream', path, '', null);
      }
      return this.$init(file);
    };
  } catch (e) {}
}

function hookWorkAndGeofence() {
  try {
    var WM = Java.use('androidx.work.WorkManager');
    WM.enqueue.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('location.activity', 'WorkManager.enqueue', safeStr(arguments[0]), 'enqueued', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var GF = Java.use('com.google.android.gms.location.GeofencingClient');
    GF.addGeofences.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('location.geofence', 'GeofencingClient.addGeofences', safeStr(arguments[0]), 'added', 'ACCESS_FINE_LOCATION');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var AR = Java.use('com.google.android.gms.location.ActivityRecognitionClient');
    AR.requestActivityUpdates.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('location.activity', 'ActivityRecognitionClient.requestActivityUpdates', safeStr(arguments[0]), 'requested', 'ACTIVITY_RECOGNITION');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookCronetVolleyRetrofit() {
  try {
    var Engine = Java.use('org.chromium.net.CronetEngine');
    Engine.newUrlRequestBuilder.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('net.http', 'Cronet.newUrlRequestBuilder', safeStr(arguments[0]), '', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Req = Java.use('com.android.volley.Request');
    Req.getUrl.implementation = function () {
      var url = this.getUrl();
      writeEvent('net.http', 'Volley.Request.getUrl', url, '', null);
      return url;
    };
  } catch (e) {}
  try {
    var Service = Java.use('retrofit2.OkHttpCall');
    Service.request.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var req = overload.apply(this, arguments);
        try { writeEvent('net.http', 'Retrofit.request', req.url().toString(), req.method(), null); } catch (e) {}
        return req;
      };
    });
  } catch (e) {}
}

function hookHmsAndFlutter() {
  try {
    var HMS = Java.use('com.huawei.hms.location.FusedLocationProviderClient');
    ['getLastLocation', 'getCurrentLocation', 'requestLocationUpdates'].forEach(function (m) {
      try {
        HMS[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            writeEvent('location.gms', 'HmsFusedLocation.' + m, safeStr(arguments[0]), 'Task', 'ACCESS_FINE_LOCATION');
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var CH = Java.use('io.flutter.plugin.common.MethodChannel');
    CH.invokeMethod.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var name = safeStr(arguments[0]);
        if (looksSensitive(name) || looksSensitive(arguments[1])) {
          writeEvent('location.gps', 'Flutter.MethodChannel', name, safeStr(arguments[1]), null);
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookSniAndIntent() {
  try {
    var Sock = Java.use('javax.net.ssl.SSLSocket');
    Sock.getSession.implementation = function () {
      var session = this.getSession();
      try {
        var host = session.getPeerHost();
        if (host) writeEvent('net.sni', 'SSLSocket.getPeerHost', host, '', null);
      } catch (e) {}
      return session;
    };
  } catch (e) {}
  try {
    var Https = Java.use('javax.net.ssl.HttpsURLConnection');
    Https.getURL.implementation = function () {
      var url = this.getURL();
      writeEvent('net.sni', 'HttpsURLConnection.getURL', safeStr(url), '', null);
      return url;
    };
  } catch (e) {}
  try {
    var Intent = Java.use('android.content.Intent');
    Intent.getParcelableExtra.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        try {
          if (result && result.getClass && ('' + result.getClass().getName()).indexOf('Location') >= 0) {
            writeEvent('location.gps', 'Intent.getParcelableExtra(Location)', safeStr(arguments[0]), formatLocation(result), 'ACCESS_FINE_LOCATION');
          }
        } catch (e) {}
        return result;
      };
    });
  } catch (e) {}
  try {
    var WR = Java.use('android.net.wifi.rtt.WifiRttManager');
    WR.startRanging.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('location.wifi_rtt', 'WifiRttManager.startRanging', safeStr(arguments[0]), 'ranging', 'NEARBY_WIFI_DEVICES');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookNativeNetMeta() {
  try {
    var getaddr = Module.findExportByName('libc.so', 'getaddrinfo');
    if (getaddr) {
      Interceptor.attach(getaddr, {
        onEnter: function (args) {
          try { this.host = Memory.readUtf8String(args[0]); } catch (e) { this.host = ''; }
        },
        onLeave: function () {
          if (this.host && looksSensitive(this.host)) {
            writeEvent('net.dns', 'getaddrinfo', this.host, '', null);
          }
        }
      });
    }
  } catch (e) {}
  try {
    var sni = Module.findExportByName('libssl.so', 'SSL_get_servername') ||
      Module.findExportByName('libssl.so', 'SSL_get_servername');
    if (sni) {
      Interceptor.attach(sni, {
        onLeave: function (retval) {
          try {
            var name = Memory.readUtf8String(retval);
            if (name) writeEvent('net.sni', 'SSL_get_servername', name, '', null);
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  try {
    var dlopen = Module.findExportByName(null, 'android_dlopen_ext') || Module.findExportByName('libdl.so', 'dlopen');
    if (dlopen) {
      Interceptor.attach(dlopen, {
        onEnter: function (args) {
          try { this.path = Memory.readUtf8String(args[0]); } catch (e) { this.path = ''; }
        },
        onLeave: function () {
          if (this.path && /loc|gps|gnss|map|cronet|okhttp|mqtt/i.test(this.path)) {
            writeEvent('location.hal', 'dlopen', this.path, 'loaded', null);
          }
        }
      });
    }
  } catch (e) {}
}

function installJavaHooks() {
  writeEvent('frida.init', 'Frida hooks loaded', TARGET_PKG, '', null);
  hookBuild();
  hookSystemProperties();
  hookSettings();
  hookTelephonyManager();
  hookSubscriptionManager();
  hookWifiAndBluetooth();
  hookMediaDrm();
  hookAdvertisingId();
  hookAccounts();
  hookNetworkInterface();
  hookPackageManager();
  hookContentResolver();
  hookLocation();
  hookCamera();
  hookAudio();
  hookSensors();
  hookClipboard();
  hookSms();
  hookNetworkDeep();
  hookBiometric();
  hookMediaProjection();
  hookOkHttp();
  hookHttpUrlConnection();
  hookWebView();
  hookSqlite();
  hookSharedPrefs();
  hookSensitiveFiles();
  hookWorkAndGeofence();
  hookCronetVolleyRetrofit();
  hookHmsAndFlutter();
  hookSniAndIntent();
}

// Хуки ставим после старта приложения, чтобы не блокировать запуск.
setTimeout(function () {
  if (Java.available) {
    Java.perform(function () {
      try { installJavaHooks(); } catch (e) {}
    });
  }
  try { hookNativeProperties(); } catch (e) {}
  try { hookNativeNetMeta(); } catch (e) {}
}, 1500);
