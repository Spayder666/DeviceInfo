'use strict';

var EVENT_FILE = '/data/local/tmp/access_monitor/events.jsonl';
var TARGET_PKG = '__TARGET_PACKAGE__';
var MITM_ENABLED = __MITM_ENABLED__;

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

var lastReq = {};
function writeReq(identifierId, action, request, response, permission) {
  var key = (identifierId || '') + '|' + (action || '') + '|' + (request || '');
  var now = Date.now();
  if (lastReq[key] && now - lastReq[key] < 800) return;
  lastReq[key] = now;
  writeEvent(identifierId, action, request, response, permission);
}

var onceReq = {};
function writeOnce(identifierId, action, request, response, permission) {
  var key = (identifierId || '') + '|' + (action || '') + '|' + (request || '');
  if (onceReq[key]) return;
  onceReq[key] = 1;
  writeEvent(identifierId, action, request, response, permission);
}

function classifyUri(uri) {
  var u = String(uri || '').toLowerCase();
  if (u.indexOf('contacts') >= 0) return 'cp.contacts';
  if (u.indexOf('sms') >= 0 || u.indexOf('mms') >= 0) return 'cp.sms';
  if (u.indexOf('call_log') >= 0) return 'cp.call_log';
  if (u.indexOf('calendar') >= 0) return 'cp.calendar';
  if (u.indexOf('telephony') >= 0 || u.indexOf('icc') >= 0) return 'cp.telephony';
  if (u.indexOf('gsf') >= 0 || u.indexOf('gservices') >= 0) return 'ad.gsf_id';
  if (u.indexOf('settings/secure') >= 0) return 'settings.secure';
  if (u.indexOf('settings/global') >= 0) return 'settings.global';
  if (u.indexOf('settings/system') >= 0) return 'settings.system';
  if (u.indexOf('media') >= 0) return 'storage.media';
  if (u.indexOf('browser') >= 0) return 'cp.browser';
  if (u.indexOf('voicemail') >= 0) return 'cp.voicemail';
  if (u.indexOf('blocked') >= 0) return 'cp.blocked';
  if (u.indexOf('download') >= 0) return 'storage.downloads';
  if (u.indexOf('health') >= 0) return 'cp.other';
  if (u.indexOf('content://') === 0) return 'cp.other';
  return '';
}

function mapBuildField(name) {
  var map = {
    MODEL: 'build.model', DEVICE: 'build.device', MANUFACTURER: 'build.manufacturer',
    BRAND: 'build.brand', PRODUCT: 'build.product', HARDWARE: 'build.hardware',
    BOARD: 'build.board', FINGERPRINT: 'build.fingerprint', SERIAL: 'build.serial',
    ID: 'build.id', DISPLAY: 'build.display', HOST: 'build.host', TAGS: 'build.tags',
    TYPE: 'build.type', USER: 'build.user', RADIO: 'build.radio', BOOTLOADER: 'build.bootloader',
    SDK_INT: 'version.sdk', RELEASE: 'version.release', INCREMENTAL: 'version.incremental',
    SECURITY_PATCH: 'version.security_patch', CODENAME: 'version.codename'
  };
  return map[name] || 'build.model';
}

function classifySettingsKey(key) {
  var k = String(key || '');
  if (k === 'android_id') return 'settings.android_id';
  if (k === 'bluetooth_address') return 'settings.bluetooth_address';
  if (k === 'bluetooth_name') return 'settings.bluetooth_name';
  if (k === 'device_name') return 'settings.device_name';
  if (k === 'adb_enabled' || k === 'development_settings_enabled') return 'root.adb';
  if (k.indexOf('accessibility') >= 0) return 'settings.accessibility';
  if (k.indexOf('notification_listener') >= 0) return 'settings.notification_listeners';
  if (k.indexOf('input_method') >= 0) return 'settings.input_method';
  if (k.indexOf('location') >= 0) return 'settings.location_mode';
  if (k.indexOf('mock_location') >= 0) return 'settings.mock_location';
  if (k.indexOf('http_proxy') >= 0) return 'net.proxy';
  return 'settings.secure';
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
    ['getSimCarrierIdName', 'tel.carrier_name', null],
    ['getSimSpecificCarrierId', 'tel.specific_carrier_id', null],
    ['getSimSpecificCarrierIdName', 'tel.carrier_name', null],
    ['getVoiceMailNumber', 'tel.voicemail', 'READ_PHONE_STATE'],
    ['getVoiceMailAlphaTag', 'tel.voicemail_tag', 'READ_PHONE_STATE'],
    ['getSimState', 'tel.sim_state', null],
    ['getPhoneType', 'tel.phone_type', null],
    ['getPhoneCount', 'tel.modem_count', null],
    ['getActiveModemCount', 'tel.modem_count', null],
    ['getSupportedModemCount', 'tel.modem_count', null],
    ['isMultiSimSupported', 'tel.multi_sim', null],
    ['getMaxNumberOfSimultaneouslyActiveSims', 'tel.multi_sim', null],
    ['hasIccCard', 'tel.has_icc', null],
    ['getNetworkType', 'tel.network_type', 'READ_PHONE_STATE'],
    ['getDataNetworkType', 'tel.network_type', 'READ_PHONE_STATE'],
    ['getVoiceNetworkType', 'tel.network_type', 'READ_PHONE_STATE'],
    ['getServiceState', 'tel.service_state', 'READ_PHONE_STATE'],
    ['getCallState', 'tel.phone_interface', null],
    ['getDataState', 'tel.phone_interface', null],
    ['getUiccCardsInfo', 'tel.has_icc', 'READ_PRIVILEGED_PHONE_STATE']
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
    ['getPhoneNumber', 'getActiveSubscriptionInfoList', 'getActiveSubscriptionInfoCount',
      'getActiveSubscriptionInfoCountMax', 'getActiveSubscriptionInfo',
      'getActiveSubscriptionInfoForSimSlotIndex', 'getDefaultSubscriptionId',
      'getDefaultDataSubscriptionId', 'getDefaultVoiceSubscriptionId',
      'getDefaultSmsSubscriptionId', 'getSubscriptionId'].forEach(function (m) {
      try {
        SM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent(m.indexOf('PhoneNumber') >= 0 ? 'sub.phone_number' : 'sub.subscription_id', 'SubscriptionManager.' + m, '', safeStr(result), 'READ_PHONE_NUMBERS');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}

  try {
    var SI = Java.use('android.telephony.SubscriptionInfo');
    ['getIccId', 'getSubscriptionId', 'getSimSlotIndex', 'getMccString', 'getMncString',
      'getCardId', 'getDisplayName', 'getCarrierName', 'getCountryIso', 'getNumber',
      'getMcc', 'getMnc'].forEach(function (m) {
      try {
        SI[m].implementation = function () {
          var result = this[m]();
          var sid = m === 'getIccId' ? 'sub.iccid' : (m === 'getNumber' ? 'sub.phone_number' : 'sub.subscription_id');
          writeEvent(sid, 'SubscriptionInfo.' + m, '', safeStr(result), null);
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
      try {
        Cls.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, key) {
          var result = this.getString(cr, key);
          writeEvent(classifySettingsKey(key), c[0] + '.getString', safeStr(key), safeStr(result), null);
          return result;
        };
      } catch (e) {}
      try {
        Cls.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, key, def) {
          var result = this.getInt(cr, key, def);
          writeEvent(classifySettingsKey(key), c[0] + '.getInt', safeStr(key), safeStr(result), null);
          return result;
        };
      } catch (e) {}
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
    key === 'ro.build.version.security_patch' ||
    key === 'ro.secure' ||
    key === 'ro.debuggable' ||
    key === 'ro.build.tags' ||
    key === 'ro.build.type' ||
    key === 'ro.kernel.qemu' ||
    key === 'ro.hardware' ||
    key.indexOf('ro.boot.verifiedboot') === 0 ||
    key.indexOf('ro.boot.flash.locked') === 0 ||
    key.indexOf('ro.boot.vbmeta') === 0 ||
    key.indexOf('ro.boot.warranty') === 0 ||
    key.indexOf('ro.boot.selinux') === 0 ||
    key.indexOf('init.svc.magisk') === 0 ||
    key.indexOf('persist.sys.magisk') === 0 ||
    key.indexOf('persist.sys.xposed') === 0 ||
    key.indexOf('persist.sys.taichi') === 0 ||
    key.indexOf('ro.lsposed') === 0 ||
    key.indexOf('ro.edxposed') === 0 ||
    key.indexOf('ro.magisk') === 0 ||
    key.indexOf('ro.boot.zygisk') === 0 ||
    key.indexOf('persist.zygisk') === 0 ||
    key === 'ro.dalvik.vm.native.bridge' ||
    key.indexOf('ro.product.') === 0 ||
    key.indexOf('ro.build.') === 0 ||
    key.indexOf('ro.boot.') === 0 ||
    key.indexOf('ro.serial') === 0 ||
    key.indexOf('persist.sys.timezone') === 0 ||
    key.indexOf('persist.sys.locale') === 0 ||
    key === 'ro.opengles.version' ||
    key === 'ro.sf.lcd_density' ||
    key.indexOf('gsm.operator') === 0 ||
    key.indexOf('gsm.sim') === 0;
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
    'persist.radio.imei': 'prop.persist.radio.imei',
    'ro.secure': 'root.props',
    'ro.debuggable': 'root.props',
    'ro.build.tags': 'root.props',
    'ro.build.type': 'root.props',
    'ro.kernel.qemu': 'root.emulator',
    'ro.hardware': 'root.emulator',
    'ro.boot.verifiedbootstate': 'attest.verified_boot',
    'ro.boot.flash.locked': 'attest.verified_boot',
    'ro.boot.vbmeta.device_state': 'attest.verified_boot'
  };
  if (key.indexOf('lsposed') >= 0 || key.indexOf('lspd') >= 0) return 'root.lsposed';
  if (key.indexOf('xposed') >= 0 || key.indexOf('taichi') >= 0) return 'root.xposed';
  if (key.indexOf('magisk') >= 0 || key.indexOf('zygisk') >= 0) return 'root.magisk';
  if (key.indexOf('qemu') >= 0 || key.indexOf('goldfish') >= 0) return 'root.emulator';
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
          var wid = m === 'getBSSID' ? 'wifi.bssid' : (m === 'getSSID' ? 'wifi.ssid' : (m === 'getIpAddress' ? 'wifi.ip' : (m === 'getNetworkId' ? 'wifi.network_id' : 'wifi.mac')));
          writeEvent(wid, 'WifiInfo.' + m, '', safeStr(result), 'ACCESS_FINE_LOCATION');
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
  try {
    var ASM = Java.use('com.google.android.gms.appset.AppSetIdClient');
    ASM.getAppSetIdInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('ad.app_set_id', 'AppSetIdClient.getAppSetIdInfo', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var AS = Java.use('com.google.android.gms.appset.AppSet');
    AS.getClient.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('ad.app_set_id', 'AppSet.getClient', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
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
  var classes = ['android.app.ApplicationPackageManager', 'android.content.pm.PackageManager'];
  classes.forEach(function (name) {
    try {
      var PM = Java.use(name);
      try {
        PM.getInstallerPackageName.overloads.forEach(function (overload) {
          overload.implementation = function () {
            var pkg = safeStr(arguments[0]);
            var result = overload.apply(this, arguments);
            writeReq('install.installer', name + '.getInstallerPackageName', pkg, safeStr(result), null);
            return result;
          };
        });
      } catch (e) {}
      ['getPackageInfo', 'getApplicationInfo'].forEach(function (m) {
        try {
          PM[m].overloads.forEach(function (overload) {
            overload.implementation = function () {
              var pkg = safeStr(arguments[0]);
              var flags = safeStr(arguments[1]);
              var result = overload.apply(this, arguments);
              if (isRootPkg(pkg)) writeRoot(classifyClass(pkg), name + '.' + m, pkg, 'found');
              else writeReq(m === 'getPackageInfo' ? 'install.package_info' : 'install.application_info', name + '.' + m, pkg + ' flags=' + flags, 'ok', null);
              return result;
            };
          });
        } catch (e) {}
      });
      ['getInstalledPackages', 'getInstalledApplications'].forEach(function (scan) {
        try {
          PM[scan].overloads.forEach(function (overload) {
            overload.implementation = function () {
              var result = overload.apply(this, arguments);
              writeReq('pkg.installed', name + '.' + scan, safeStr(arguments[0]), 'count=' + (result ? result.size() : 0), 'QUERY_ALL_PACKAGES');
              return result;
            };
          });
        } catch (e) {}
      });
      ['queryIntentActivities', 'queryBroadcastReceivers', 'queryIntentServices', 'queryContentProviders'].forEach(function (q) {
        try {
          PM[q].overloads.forEach(function (overload) {
            overload.implementation = function () {
              var result = overload.apply(this, arguments);
              writeReq('pkg.query_intent', name + '.' + q, safeStr(arguments[0]), 'count=' + (result ? result.size() : 0), null);
              return result;
            };
          });
        } catch (e) {}
      });
    } catch (e) {}
  });
}

function hookContentResolver() {
  try {
    var CR = Java.use('android.content.ContentResolver');
    ['query', 'insert', 'update', 'delete'].forEach(function (m) {
      try {
        CR[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var uri = arguments[0] ? safeStr(arguments[0].toString()) : '';
            var id = classifyUri(uri);
            var result = overload.apply(this, arguments);
            if (id) {
              var extra = '';
              try { if (m === 'query' && result) extra = 'rows=' + result.getCount(); } catch (e) {}
              writeReq(id, 'ContentResolver.' + m, uri, extra, null);
            }
            return result;
          };
        });
      } catch (e) {}
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
            writeEvent(m === 'getCameraIdList' ? 'camera.ids' : 'camera.open', 'CameraManager.' + m, safeStr(arguments[0]), safeStr(result), 'CAMERA');
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
        writeEvent('camera.open', 'Camera.open', safeStr(arguments[0]), 'opened', 'CAMERA');
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
        writeEvent('mic.record', 'AudioRecord.startRecording', '', 'recording', 'RECORD_AUDIO');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var MR = Java.use('android.media.MediaRecorder');
    MR.start.implementation = function () {
      writeEvent('mic.record', 'MediaRecorder.start', '', 'recording', 'RECORD_AUDIO');
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
            writeEvent('mic.record', 'AudioManager.' + m, '', safeStr(result), 'RECORD_AUDIO');
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
        writeEvent('sensor.register', 'SensorManager.registerListener', sensor, 'registered', null);
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
            writeEvent('clipboard.primary', 'ClipboardManager.' + m, '', safeStr(result), 'READ_CLIPBOARD');
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
            writeEvent(m === 'getDefault' ? 'sms.inbox' : 'sms.send', 'SmsManager.' + m, args.join(', '), safeStr(result), 'SEND_SMS');
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
        writeEvent('hw.biometric', 'BiometricPrompt.authenticate', '', 'prompt', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookMediaProjection() {
  try {
    var MPM = Java.use('android.media.projection.MediaProjectionManager');
    MPM.createScreenCaptureIntent.implementation = function () {
      writeEvent('display.capture', 'MediaProjectionManager.createScreenCaptureIntent', '', 'screen capture', null);
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
          if (this.path && /magisk|zygisk|xposed|lsposed|frida|gadget|riru|substrate/i.test(this.path)) {
            writeRoot('root.maps', 'dlopen', this.path, 'loaded');
          }
        }
      });
    }
  } catch (e) {}
}

var lastRoot = {};

function writeRoot(id, action, req, resp) {
  var key = id + '|' + action + '|' + req;
  var now = Date.now();
  if (lastRoot[key] && now - lastRoot[key] < 1200) return;
  lastRoot[key] = now;
  writeEvent(id, action, req, resp, null);
}

function isRootPath(p) {
  if (!p) return false;
  var s = String(p).toLowerCase();
  return /\/su$|\/su\/|superuser|supersu|magisk|zygisk|ksu|apatch|busybox|xposed|lsposed|lspd|lsplant|lspatch|riru|frida|gadget|linjector|\/data\/adb|\/sbin\/\.|debug_ramdisk|qemu_pipe|goldfish_pipe|\/sys\/qemu|XposedBridge\.jar|app_process_xposed|libxposed|sandhook|yahfa|dobby|libwhale/.test(s) ||
    isProcInjectPath(s);
}

function isProcInjectPath(p) {
  if (!p) return false;
  var s = String(p).toLowerCase();
  return /\/proc\/(self|\d+)\/(maps|smaps|status|task|mounts|mountinfo|net\/tcp|net\/unix)/.test(s) ||
    s.indexOf('/proc/net/tcp') >= 0 || s.indexOf('/proc/net/unix') >= 0;
}

function classifyPath(path) {
  var s = String(path || '').toLowerCase();
  if (/qemu|goldfish|ranchu/.test(s)) return 'root.emulator';
  if (/lsposed|\/lspd|lsplant|zygisk_lsposed|riru_lsposed/.test(s)) return 'root.lsposed';
  if (/lspatch|virtualxposed|taichi|io\.va\.exposed/.test(s)) return 'root.lspatch';
  if (/frida|gadget|gum-js|linjector/.test(s)) return 'root.frida_detect';
  if (/xposed/.test(s)) return 'root.xposed';
  if (isProcInjectPath(s) || /sandhook|yahfa|dobby|whale|epic|substrate|memfd/.test(s)) return 'root.inject';
  if (/magisk|zygisk/.test(s)) return 'root.magisk';
  return 'root.su';
}

function classifyClass(name) {
  var s = String(name || '').toLowerCase();
  if (/lsposed|lspd|lsplant/.test(s)) return 'root.lsposed';
  if (/lspatch|virtualxposed|taichi/.test(s)) return 'root.lspatch';
  if (/xposed/.test(s)) return 'root.xposed';
  if (/frida|gadget/.test(s)) return 'root.frida_detect';
  if (/talsec|freerasp|threatlistener/.test(s)) return 'root.talsec';
  if (/jailmonkey|flutter_jailbreak|iroot|roottools/.test(s)) return 'root.rootbeer';
  return 'root.rootbeer';
}

function isRootCmd(cmd) {
  if (!cmd) return false;
  return /(^|[\/\s])su(\s|$)|which\s+su|magisk|getenforce|busybox|resetprop|zygisk|ksud|apatch|id\s+-u|\bps\b|frida-server|cat\s+\/proc/.test(String(cmd).toLowerCase());
}

function isRootPkg(pkg) {
  if (!pkg) return false;
  var s = String(pkg).toLowerCase();
  return /magisk|supersu|superuser|kernelsu|ksunext|lsposed|lspatch|xposed|edxposed|apatch|kingroot|kingo|framaroot|hidemyroot|rootcloak|shamiko|me\.weishu|topjohnwu|chainfire|frida|saurik\.substrate|io\.va\.exposed|elderdrivers/.test(s);
}

function isHookClass(name) {
  if (!name) return false;
  return /rootbeer|xposed|lsposed|lspd|lsplant|lspatch|edxposed|magisk|frida|gadget|substrate|de\.robv\.android\.xposed|org\.lsposed|com\.scottyab\.rootbeer|com\.saurik\.substrate|me\.weishu|talsec|freerasp|jailmonkey|safetydetect|iroot|roottools|flutter_jailbreak|appcheck|play\.core\.integrity|kimchangyoun\.rootbeer/.test(String(name).toLowerCase());
}

function isFridaPort(port) {
  return (port >= 27040 && port <= 27050) || port === 23946;
}

function hookRootFiles() {
  try {
    var File = Java.use('java.io.File');
    ['exists', 'canRead', 'canExecute', 'canWrite', 'isFile', 'isDirectory'].forEach(function (m) {
      try {
        var orig = File[m];
        orig.implementation = function () {
          var path = '';
          try { path = this.getAbsolutePath(); } catch (e) {}
          var result = orig.call(this);
          if (isRootPath(path)) {
            writeRoot(classifyPath(path), 'File.' + m, path, safeStr(result));
          }
          return result;
        };
      } catch (e) {}
    });
  } catch (e) {}
}

function hookRootExec() {
  try {
    var RT = Java.use('java.lang.Runtime');
    RT.exec.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var cmd = '';
        try {
          var a0 = arguments[0];
          if (a0 && a0.getClass && a0.getClass().isArray && a0.getClass().isArray()) {
            var parts = [];
            for (var i = 0; i < a0.length; i++) parts.push(safeStr(a0[i]));
            cmd = parts.join(' ');
          } else {
            cmd = safeStr(a0);
          }
        } catch (e) { cmd = safeStr(arguments[0]); }
        var result = overload.apply(this, arguments);
        if (isRootCmd(cmd)) writeRoot('root.exec', 'Runtime.exec', cmd, 'started');
        return result;
      };
    });
  } catch (e) {}
  try {
    var PB = Java.use('java.lang.ProcessBuilder');
    PB.start.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var cmd = '';
        try { cmd = safeStr(this.command()); } catch (e) {}
        var result = overload.apply(this, arguments);
        if (isRootCmd(cmd)) writeRoot('root.exec', 'ProcessBuilder.start', cmd, 'started');
        return result;
      };
    });
  } catch (e) {}
}

function hookRootPackages() {
  var classes = ['android.app.ApplicationPackageManager', 'android.content.pm.PackageManager'];
  classes.forEach(function (name) {
    try {
      var PM = Java.use(name);
      try {
        PM.getPackageUid.overloads.forEach(function (overload) {
          overload.implementation = function () {
            var pkg = safeStr(arguments[0]);
            var result = overload.apply(this, arguments);
            if (isRootPkg(pkg)) writeRoot(classifyClass(pkg), name + '.getPackageUid', pkg, 'found');
            return result;
          };
        });
      } catch (e) {}
    } catch (e) {}
  });
}

function hookRootDebug() {
  try {
    var Debug = Java.use('android.os.Debug');
    var origDbg = Debug.isDebuggerConnected;
    origDbg.implementation = function () {
      var result = origDbg.call(this);
      writeRoot('root.debugger', 'Debug.isDebuggerConnected', '', safeStr(result));
      return result;
    };
  } catch (e) {}
  try {
    var SG = Java.use('android.provider.Settings$Global');
    var origGet = SG.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int');
    origGet.implementation = function (cr, key, def) {
      var result = origGet.call(this, cr, key, def);
      if (key === 'adb_enabled' || key === 'development_settings_enabled') {
        writeRoot('root.adb', 'Settings.Global.getInt', key, safeStr(result));
      }
      return result;
    };
  } catch (e) {}
}

function hookDetectorMethods(className, id, methods) {
  try {
    var Cls = Java.use(className);
    methods.forEach(function (m) {
      try {
        Cls[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeRoot(id, className.split('.').pop() + '.' + m, safeStr(arguments[0]), safeStr(result));
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookRootBeer() {
  var methods = [
    'isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps', 'detectPotentiallyDangerousApps',
    'detectTestKeys', 'checkForBusyBoxBinary', 'checkForSuBinary', 'checkSuExists',
    'checkForRWPaths', 'checkForDangerousProps', 'checkForRootNative', 'detectRootCloakingApps',
    'checkForMagiskBinary'
  ];
  hookDetectorMethods('com.scottyab.rootbeer.RootBeer', 'root.rootbeer', methods);
  hookDetectorMethods('com.kimchangyoun.rootbeerFresh.RootBeer', 'root.rootbeer', methods);
  try {
    var RN = Java.use('com.scottyab.rootbeer.RootBeerNative');
    RN.checkForRoot.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        writeRoot('root.rootbeer', 'RootBeerNative.checkForRoot', '', safeStr(result));
        return result;
      };
    });
  } catch (e) {}
  hookDetectorMethods('com.stericson.RootTools.RootTools', 'root.rootbeer', [
    'isRootAvailable', 'isAccessGiven', 'isBusyboxAvailable'
  ]);
  ['com.aheaditec.talsec.security.Talsec',
    'com.aheaditec.talsec_security.security.api.Talsec',
    'com.aheaditec.talsec.security.api.Talsec'].forEach(function (name) {
    hookDetectorMethods(name, 'root.talsec', ['start', 'stop', 'getThreats']);
  });
  try {
    var TL = Java.use('com.aheaditec.talsec_security.security.api.ThreatListener');
    ['onThreatDetected', 'threatDetected'].forEach(function (m) {
      try {
        TL[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            writeRoot('root.talsec', 'ThreatListener.' + m, safeStr(arguments[0]), '');
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  hookDetectorMethods('com.gantix.JailMonkey.Rooted.RootedCheck', 'root.rootbeer', ['isJailBroken', 'detectRoot']);
  hookDetectorMethods('io.github.edufolly.flutter_jailbreak_detection.FlutterJailbreakDetectionPlugin', 'root.rootbeer', [
    'isJailBroken', 'isRooted'
  ]);
}

function hookIntegrityApis() {
  try {
    var IM = Java.use('com.google.android.play.core.integrity.IntegrityManager');
    IM.requestIntegrityToken.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeRoot('ent.integrity', 'IntegrityManager.requestIntegrityToken', safeStr(arguments[0]), 'requested');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var ITR = Java.use('com.google.android.play.core.integrity.IntegrityTokenResponse');
    ITR.token.implementation = function () {
      var t = this.token();
      writeRoot('ent.verdict', 'IntegrityTokenResponse.token', 'len=' + (t ? t.length : 0), safeStr(t).substring(0, 240));
      return t;
    };
  } catch (e) {}
  try {
    var SIM = Java.use('com.google.android.play.core.integrity.StandardIntegrityManager');
    SIM.prepareIntegrityToken.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeRoot('ent.integrity', 'StandardIntegrityManager.prepareIntegrityToken', safeStr(arguments[0]), 'requested');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var SITP = Java.use('com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityTokenProvider');
    SITP.request.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeRoot('ent.integrity', 'StandardIntegrityTokenProvider.request', safeStr(arguments[0]), 'requested');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var SIT = Java.use('com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityToken');
    SIT.token.implementation = function () {
      var t = this.token();
      writeRoot('ent.verdict', 'StandardIntegrityToken.token', 'len=' + (t ? t.length : 0), safeStr(t).substring(0, 240));
      return t;
    };
  } catch (e) {}
  try {
    var SN = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
    SN.attest.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeRoot('ent.safetynet', 'SafetyNetClient.attest', '', 'requested');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Att = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse');
    Att.getJwsResult.implementation = function () {
      var jws = this.getJwsResult();
      writeRoot('ent.verdict', 'SafetyNet.getJwsResult', 'jws', safeStr(jws).substring(0, 400));
      return jws;
    };
  } catch (e) {}
  try {
    var SD = Java.use('com.huawei.hms.support.api.safetydetect.SafetyDetectClient');
    ['sysIntegrity', 'appsCheck', 'getWifiDetectStatus', 'userDetection'].forEach(function (m) {
      try {
        SD[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            writeRoot('ent.integrity', 'SafetyDetect.' + m, '', 'requested');
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var FAC = Java.use('com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProvider');
    FAC.getToken.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeRoot('ent.integrity', 'PlayIntegrityAppCheck.getToken', '', 'requested');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var KG = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
    var origCh = KG.setAttestationChallenge;
    origCh.implementation = function (challenge) {
      writeRoot('attest.key', 'KeyGenParameterSpec.setAttestationChallenge', 'len=' + (challenge ? challenge.length : 0), 'set');
      return origCh.call(this, challenge);
    };
  } catch (e) {}
}

function hookRootClassForName() {
  try {
    var Cls = Java.use('java.lang.Class');
    Cls.forName.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var name = safeStr(arguments[0]);
        if (isHookClass(name)) writeRoot(classifyClass(name), 'Class.forName', name, '');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookProcReaders() {
  try {
    var FIS = Java.use('java.io.FileInputStream');
    FIS.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var path = '';
        try {
          var a0 = arguments[0];
          path = a0 && a0.getAbsolutePath ? a0.getAbsolutePath() : safeStr(a0);
        } catch (e) {}
        if (isProcInjectPath(path) || isRootPath(path)) {
          writeRoot(classifyPath(path), 'FileInputStream', path, '');
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var RAF = Java.use('java.io.RandomAccessFile');
    RAF.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var path = '';
        try {
          var a0 = arguments[0];
          path = a0 && a0.getAbsolutePath ? a0.getAbsolutePath() : safeStr(a0);
        } catch (e) {}
        if (isProcInjectPath(path) || isRootPath(path)) {
          writeRoot(classifyPath(path), 'RandomAccessFile', path, '');
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Os = Java.use('android.system.Os');
    Os.open.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var path = safeStr(arguments[0]);
        var fd = overload.apply(this, arguments);
        if (isProcInjectPath(path) || isRootPath(path)) {
          writeRoot(classifyPath(path), 'Os.open', path, 'fd');
        }
        return fd;
      };
    });
  } catch (e) {}
  try {
    var Files = Java.use('java.nio.file.Files');
    ['readAllBytes', 'readAllLines', 'newBufferedReader', 'newInputStream'].forEach(function (m) {
      try {
        Files[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var path = safeStr(arguments[0]);
            if (isProcInjectPath(path) || isRootPath(path)) {
              writeRoot(classifyPath(path), 'Files.' + m, path, '');
            }
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookInjectSockets() {
  try {
    var Sock = Java.use('java.net.Socket');
    Sock.connect.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var ep = '';
        var port = -1;
        try {
          var addr = arguments[0];
          ep = safeStr(addr);
          if (addr && addr.getPort) port = addr.getPort();
        } catch (e) {}
        if (isFridaPort(port) || /2704[0-9]|23946/.test(ep)) {
          writeRoot('root.ports', 'Socket.connect', ep, '');
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Sock = Java.use('java.net.Socket');
    Sock.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var host = safeStr(arguments[0]);
        var port = typeof arguments[1] === 'number' ? arguments[1] : -1;
        if (isFridaPort(port)) writeRoot('root.ports', 'Socket.<init>', host + ':' + port, '');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookInjectThreads() {
  try {
    var Th = Java.use('java.lang.Thread');
    var origAll = Th.getAllStackTraces;
    origAll.implementation = function () {
      var result = origAll.call(this);
      writeRoot('root.stack', 'Thread.getAllStackTraces', '', 'threads=' + (result ? result.size() : 0));
      return result;
    };
  } catch (e) {}
  try {
    var Th = Java.use('java.lang.Thread');
    Th.enumerate.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeRoot('root.threads', 'Thread.enumerate', '', '');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookInjectClassLoader() {
  try {
    var CL = Java.use('java.lang.ClassLoader');
    var orig = CL.loadClass.overload('java.lang.String');
    orig.implementation = function (name) {
      if (isHookClass(name)) writeRoot(classifyClass(name), 'ClassLoader.loadClass', name, '');
      return orig.call(this, name);
    };
  } catch (e) {}
}

function hookInjectEnvAndLoad() {
  try {
    var Sys = Java.use('java.lang.System');
    var origEnv = Sys.getenv.overload('java.lang.String');
    origEnv.implementation = function (key) {
      var result = origEnv.call(this, key);
      if (key && /LD_PRELOAD|CLASSPATH|XPOSED|FRIDA|MAGISK/i.test(key)) {
        writeRoot('root.inject', 'System.getenv', key, safeStr(result));
      }
      return result;
    };
  } catch (e) {}
  try {
    var Sys = Java.use('java.lang.System');
    var origLoad = Sys.loadLibrary;
    origLoad.implementation = function (name) {
      if (/frida|xposed|lsposed|lspd|gadget|substrate|sandhook/i.test(safeStr(name))) {
        writeRoot(classifyClass(name), 'System.loadLibrary', name, '');
      }
      return origLoad.call(this, name);
    };
  } catch (e) {}
  try {
    var AM = Java.use('android.app.ActivityManager');
    var origProc = AM.getRunningAppProcesses;
    origProc.implementation = function () {
      var result = origProc.call(this);
      writeReq('pkg.running', 'ActivityManager.getRunningAppProcesses', '', 'count=' + (result ? result.size() : 0), null);
      return result;
    };
  } catch (e) {}
}

function hookNativeRootAccess() {
  ['access', 'faccessat', 'stat', 'lstat'].forEach(function (fn) {
    try {
      var addr = Module.findExportByName('libc.so', fn);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          var idx = fn === 'faccessat' ? 1 : 0;
          try { this.path = Memory.readUtf8String(args[idx]); } catch (e) { this.path = ''; }
        },
        onLeave: function (retval) {
          if (!this.path || !isRootPath(this.path)) return;
          writeRoot(classifyPath(this.path), 'native.' + fn, this.path, 'rc=' + retval.toInt32());
        }
      });
    } catch (e) {}
  });
  ['open', 'openat'].forEach(function (fn) {
    try {
      var addr = Module.findExportByName('libc.so', fn);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          var idx = fn === 'openat' ? 1 : 0;
          try { this.path = Memory.readUtf8String(args[idx]); } catch (e) { this.path = ''; }
        },
        onLeave: function (retval) {
          if (!this.path || !isRootPath(this.path)) return;
          writeRoot(classifyPath(this.path), 'native.' + fn, this.path, 'fd=' + retval.toInt32());
        }
      });
    } catch (e) {}
  });
  try {
    var dlsym = Module.findExportByName('libdl.so', 'dlsym') || Module.findExportByName(null, 'dlsym');
    if (dlsym) {
      Interceptor.attach(dlsym, {
        onEnter: function (args) {
          try { this.sym = Memory.readUtf8String(args[1]); } catch (e) { this.sym = ''; }
        },
        onLeave: function (retval) {
          if (!this.sym) return;
          if (!/frida_agent_main|gum_interceptor|MSHookFunction|xposedCallHandler|LSPosed|lspd|lsplant/.test(this.sym)) return;
          writeRoot('root.dlsym', 'dlsym', this.sym, retval.isNull() ? 'null' : 'hit');
        }
      });
    }
  } catch (e) {}
  try {
    var conn = Module.findExportByName('libc.so', 'connect');
    if (conn) {
      Interceptor.attach(conn, {
        onEnter: function (args) {
          try {
            var sa = args[1];
            var family = sa.readU16();
            if (family === 2) {
              var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
              if (isFridaPort(port)) writeRoot('root.ports', 'connect', 'port=' + port, '');
            }
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
}

function hookNativeSyscall() {
  try {
    var addr = Module.findExportByName('libc.so', 'syscall');
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        var nr = args[0].toInt32();
        this.nr = nr;
        this.interesting = (nr === 56 || nr === 48 || nr === 79 || nr === 221 || nr === 203 || nr === 117 ||
          nr === 5 || nr === 33 || nr === 11);
        if (!this.interesting) return;
        try {
          if (nr === 56 || nr === 48 || nr === 79) this.path = Memory.readUtf8String(args[2]);
          else if (nr === 221 || nr === 5 || nr === 33 || nr === 11) this.path = Memory.readUtf8String(args[1]);
          else this.path = 'nr=' + nr;
        } catch (e) { this.path = 'nr=' + nr; }
      },
      onLeave: function (retval) {
        if (!this.interesting) return;
        var p = this.path || '';
        if (p && (isRootPath(p) || isProcInjectPath(p) || this.nr === 117 || this.nr === 221 || this.nr === 11)) {
          writeRoot('root.svc', 'libc.syscall', 'nr=' + this.nr + ' ' + p, 'rc=' + retval.toInt32());
        }
      }
    });
  } catch (e) {}
}

function hookProcessIsolated() {
  try {
    var P = Java.use('android.os.Process');
    P.isIsolated.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var r = overload.apply(this, arguments);
        writeRoot('root.isolated', 'Process.isIsolated', '', safeStr(r));
        return r;
      };
    });
  } catch (e) {}
  try {
    var P = Java.use('android.os.Process');
    var origUid = P.myUid;
    origUid.implementation = function () {
      var uid = origUid.call(this);
      if (uid >= 99000 && uid <= 99999) {
        writeRoot('root.isolated', 'Process.myUid', '', '' + uid);
      }
      return uid;
    };
  } catch (e) {}
}

function hookVpnProxyPin() {
  try {
    var NC = Java.use('android.net.NetworkCapabilities');
    NC.hasTransport.implementation = function (t) {
      var r = this.hasTransport(t);
      if (t === 4) writeEvent('net.vpn', 'NetworkCapabilities.hasTransport(VPN)', '' + t, safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var CM = Java.use('android.net.ConnectivityManager');
    CM.getNetworkCapabilities.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var caps = overload.apply(this, arguments);
        var vpn = false;
        try { vpn = caps && caps.hasTransport(4); } catch (e) {}
        if (vpn) writeEvent('net.vpn', 'ConnectivityManager.getNetworkCapabilities', '', 'TRANSPORT_VPN', null);
        return caps;
      };
    });
  } catch (e) {}
  try {
    var NI = Java.use('java.net.NetworkInterface');
    NI.getName.implementation = function () {
      var name = this.getName();
      if (name && /^(tun|tap|ppp|wg)/.test(name)) {
        writeEvent('net.vpn', 'NetworkInterface.getName', name, '', null);
      }
      return name;
    };
  } catch (e) {}
  try {
    var VS = Java.use('android.net.VpnService');
    VS.prepare.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var r = overload.apply(this, arguments);
        writeEvent('net.vpn', 'VpnService.prepare', '', safeStr(r), null);
        return r;
      };
    });
  } catch (e) {}
  try {
    var Proxy = Java.use('android.net.Proxy');
    ['getDefaultHost', 'getDefaultPort', 'getHost', 'getPort'].forEach(function (m) {
      try {
        Proxy[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            writeEvent('net.proxy', 'android.net.Proxy.' + m, '', safeStr(r), null);
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Sys = Java.use('java.lang.System');
    var origGet = Sys.getProperty.overload('java.lang.String');
    origGet.implementation = function (key) {
      var r = origGet.call(this, key);
      if (key && /proxy/i.test(key)) writeEvent('net.proxy', 'System.getProperty', key, safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var PS = Java.use('java.net.ProxySelector');
    PS.select.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var r = overload.apply(this, arguments);
        writeEvent('net.proxy', 'ProxySelector.select', safeStr(arguments[0]), safeStr(r), null);
        return r;
      };
    });
  } catch (e) {}
  try {
    var Ex = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
    Ex.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('net.pin_fail', 'SSLPeerUnverifiedException', safeStr(arguments[0]), '', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var HS = Java.use('javax.net.ssl.SSLHandshakeException');
    HS.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var msg = safeStr(arguments[0]);
        if (/pin|trust|cert|anchor|hostname/i.test(msg)) {
          writeEvent('net.pin_fail', 'SSLHandshakeException', msg, '', null);
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  if (!MITM_ENABLED) {
    try {
      var Pinner = Java.use('okhttp3.CertificatePinner');
      Pinner.check.overloads.forEach(function (overload) {
        overload.implementation = function () {
          try {
            var r = overload.apply(this, arguments);
            writeEvent('net.pin_fail', 'CertificatePinner.check', safeStr(arguments[0]), 'ok', null);
            return r;
          } catch (err) {
            writeEvent('net.pin_fail', 'CertificatePinner.check FAIL', safeStr(arguments[0]), safeStr(err), null);
            throw err;
          }
        };
      });
    } catch (e) {}
  }
}

function hookRootDetection() {
  hookRootFiles();
  hookRootExec();
  hookRootPackages();
  hookRootDebug();
  hookRootBeer();
  hookIntegrityApis();
  hookRootClassForName();
  hookProcReaders();
  hookInjectSockets();
  hookInjectThreads();
  hookInjectClassLoader();
  hookInjectEnvAndLoad();
  hookProcessIsolated();
  hookVpnProxyPin();
}

function hookRequestSurface() {
  try {
    var Field = Java.use('java.lang.reflect.Field');
    var origGet = Field.get.overload('java.lang.Object');
    origGet.implementation = function (obj) {
      var result = origGet.call(this, obj);
      try {
        var cls = this.getDeclaringClass().getName();
        var name = this.getName();
        if (cls === 'android.os.Build' || cls === 'android.os.Build$VERSION') {
          writeOnce(cls.indexOf('VERSION') >= 0 ? 'version.release' : mapBuildField(name), 'Build.' + name + ' (reflect)', cls, safeStr(result), null);
        }
      } catch (e) {}
      return result;
    };
  } catch (e) {}
  try {
    var USM = Java.use('android.app.usage.UsageStatsManager');
    ['queryUsageStats', 'queryEvents', 'queryConfigurations'].forEach(function (m) {
      try {
        USM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeReq('pkg.usage', 'UsageStatsManager.' + m, safeStr(arguments[0]), safeStr(result), 'PACKAGE_USAGE_STATS');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Ctx = Java.use('android.app.ContextImpl');
    Ctx.checkSelfPermission.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var perm = safeStr(arguments[0]);
        var result = overload.apply(this, arguments);
        if (/PHONE|SMS|CONTACTS|LOCATION|CAMERA|RECORD|STORAGE|AD_ID|ACCOUNTS|CALENDAR|CALL_LOG|BODY_SENSORS|NEARBY|BLUETOOTH|PACKAGE/i.test(perm)) {
          writeReq('perm.check', 'checkSelfPermission', perm, safeStr(result), perm);
        }
        return result;
      };
    });
  } catch (e) {}
  try {
    var Act = Java.use('android.app.Activity');
    Act.requestPermissions.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('perm.check', 'Activity.requestPermissions', safeStr(arguments[0]), '', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var AOM = Java.use('android.app.AppOpsManager');
    ['checkOp', 'checkOpNoThrow', 'noteOp', 'noteOpNoThrow', 'unsafeCheckOp'].forEach(function (m) {
      try {
        AOM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeReq('perm.appops', 'AppOpsManager.' + m, safeStr(arguments[0]), safeStr(result), null);
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var DM = Java.use('android.util.DisplayMetrics');
    var orig = DM.setTo;
    orig.implementation = function (o) {
      writeOnce('display.metrics', 'DisplayMetrics.setTo', '', 'w=' + this.widthPixels + ' h=' + this.heightPixels + ' dpi=' + this.densityDpi, null);
      return orig.call(this, o);
    };
  } catch (e) {}
  try {
    var Win = Java.use('android.view.Display');
    ['getMetrics', 'getRealMetrics', 'getSize', 'getRealSize'].forEach(function (m) {
      try {
        Win[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            writeOnce('display.metrics', 'Display.' + m, '', '', null);
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Loc = Java.use('java.util.Locale');
    var origDef = Loc.getDefault.overload();
    origDef.implementation = function () {
      var r = origDef.call(this);
      writeOnce('locale.default', 'Locale.getDefault', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var TZ = Java.use('java.util.TimeZone');
    var origTz = TZ.getDefault;
    origTz.implementation = function () {
      var r = origTz.call(this);
      writeOnce('locale.default', 'TimeZone.getDefault', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var BM = Java.use('android.os.BatteryManager');
    BM.getIntProperty.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var r = overload.apply(this, arguments);
        writeReq('battery.status', 'BatteryManager.getIntProperty', safeStr(arguments[0]), safeStr(r), null);
        return r;
      };
    });
  } catch (e) {}
  try {
    var Nfc = Java.use('android.nfc.NfcAdapter');
    ['getDefaultAdapter', 'isEnabled', 'enableReaderMode'].forEach(function (m) {
      try {
        Nfc[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            writeReq('nfc.adapter', 'NfcAdapter.' + m, '', safeStr(r), null);
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var USB = Java.use('android.hardware.usb.UsbManager');
    USB.getDeviceList.implementation = function () {
      var r = this.getDeviceList();
      writeReq('usb.devices', 'UsbManager.getDeviceList', '', 'count=' + (r ? r.size() : 0), null);
      return r;
    };
  } catch (e) {}
  try {
    var SF = Java.use('android.os.StatFs');
    SF.$init.overload('java.lang.String').implementation = function (path) {
      writeReq('storage.statfs', 'StatFs', safeStr(path), '', null);
      return this.$init(path);
    };
  } catch (e) {}
  try {
    var Env = Java.use('android.os.Environment');
    ['getExternalStorageDirectory', 'getExternalStorageState', 'getDataDirectory'].forEach(function (m) {
      try {
        Env[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            writeOnce('storage.statfs', 'Environment.' + m, '', safeStr(r), null);
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var WS = Java.use('android.webkit.WebSettings');
    WS.getUserAgentString.implementation = function () {
      var ua = this.getUserAgentString();
      writeReq('webview.ua', 'WebSettings.getUserAgentString', '', safeStr(ua), null);
      return ua;
    };
  } catch (e) {}
  try {
    var FCM = Java.use('com.google.firebase.messaging.FirebaseMessaging');
    FCM.getToken.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('fcm.token', 'FirebaseMessaging.getToken', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var CM = Java.use('androidx.credentials.CredentialManager');
    CM.getCredential.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('cred.manager', 'CredentialManager.getCredential', safeStr(arguments[0]), 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Id = Java.use('com.google.android.gms.auth.api.identity.Identity');
    Id.getSignInClient.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('cred.phone_hint', 'Identity.getSignInClient', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var SR = Java.use('com.google.android.gms.auth.api.phone.SmsRetriever');
    SR.getClient.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('sms.retriever', 'SmsRetriever.getClient', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var LC = Java.use('com.google.android.vending.licensing.LicenseChecker');
    LC.checkAccess.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('play.license', 'LicenseChecker.checkAccess', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var SN = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
    SN.verifyWithRecaptcha.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('play.recaptcha', 'SafetyNet.verifyWithRecaptcha', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Settings = Java.use('android.provider.Settings');
    Settings.canDrawOverlays.implementation = function (ctx) {
      var r = this.canDrawOverlays(ctx);
      writeReq('settings.overlay', 'Settings.canDrawOverlays', '', safeStr(r), 'SYSTEM_ALERT_WINDOW');
      return r;
    };
  } catch (e) {}
  try {
    var AM = Java.use('android.view.accessibility.AccessibilityManager');
    AM.isEnabled.implementation = function () {
      var r = this.isEnabled();
      writeReq('settings.accessibility', 'AccessibilityManager.isEnabled', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var GLES = Java.use('android.opengl.GLES20');
    GLES.glGetString.implementation = function (name) {
      var r = this.glGetString(name);
      writeOnce('gpu.gl', 'GLES20.glGetString', '' + name, safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var WM = Java.use('android.net.wifi.WifiManager');
    ['getConnectionInfo', 'getConfiguredNetworks', 'getDhcpInfo', 'getScanResults'].forEach(function (m) {
      try {
        WM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            var id = m === 'getScanResults' ? 'wifi.scan_results' : 'wifi.mac';
            writeReq(id, 'WifiManager.' + m, '', safeStr(r), 'ACCESS_FINE_LOCATION');
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var BLE = Java.use('android.bluetooth.le.BluetoothLeScanner');
    BLE.startScan.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('bt.remote_mac', 'BluetoothLeScanner.startScan', '', 'scan', 'BLUETOOTH_SCAN');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var NI = Java.use('java.net.NetworkInterface');
    NI.getInetAddresses.implementation = function () {
      var r = this.getInetAddresses();
      writeReq('net.link_addresses', 'NetworkInterface.getInetAddresses', this.getName(), '', null);
      return r;
    };
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
  hookRequestSurface();
  hookRootDetection();
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
  try { hookNativeRootAccess(); } catch (e) {}
  try { hookNativeSyscall(); } catch (e) {}
  if (MITM_ENABLED) {
    try { installMitmHooks(); } catch (e) {}
  }
}, 1500);

function truncateHttp(buf, maxLen) {
  maxLen = maxLen || 1800;
  var s = '';
  try {
    if (buf && buf.readUtf8String) s = buf.readUtf8String();
    else s = String(buf);
  } catch (e) {
    try { s = Memory.readUtf8String(buf); } catch (e2) { return ''; }
  }
  if (!s) return '';
  if (s.length > maxLen) s = s.substring(0, maxLen) + '…';
  return s;
}

function looksHttpish(s) {
  if (!s || s.length < 4) return false;
  return /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|HTTP\/|PRI \*) |\b(content-type|application\/json|authorization|\"lat\"|\"lon\")/i.test(s) ||
    s.indexOf('{') === 0 || s.indexOf('[') === 0 ||
    s.indexOf('PRI * HTTP/2') === 0;
}

function installMitmHooks() {
  writeEvent('net.https', 'MITM HTTPS on', TARGET_PKG, 'SSL_read/write + unpin + OkHttp body', null);
  unpinCertificates();
  hookSslReadWrite();
  hookOkHttpBodies();
}

function unpinCertificates() {
  try {
    var X509 = Java.use('javax.net.ssl.X509TrustManager');
    var TrustAll = Java.registerClass({
      name: 'am.TrustAllTM',
      implements: [X509],
      methods: {
        checkClientTrusted: function (c, a) {},
        checkServerTrusted: function (c, a) {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overloads.forEach(function (overload) {
      overload.implementation = function (km, tm, sr) {
        var trust = Java.array('javax.net.ssl.TrustManager', [TrustAll.$new()]);
        return overload.call(this, km, trust, sr);
      };
    });
  } catch (e) {}
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeEvent('net.pin_fail', 'CertificatePinner.check (MITM bypass)', safeStr(arguments[0]), 'bypassed', null);
        return;
      };
    });
  } catch (e) {}
  try {
    var HV = Java.use('javax.net.ssl.HttpsURLConnection');
    HV.setDefaultHostnameVerifier(Java.use('javax.net.ssl.HostnameVerifier').$new({
      verify: function () { return true; }
    }));
  } catch (e) {}
  try {
    var NV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    NV.verify.overloads.forEach(function (overload) {
      overload.implementation = function () { return true; };
    });
  } catch (e) {}
  try {
    var TM = Java.use('android.webkit.WebViewClient');
    TM.onReceivedSslError.overloads.forEach(function (overload) {
      overload.implementation = function (view, handler, error) {
        try { handler.proceed(); } catch (e) {}
      };
    });
  } catch (e) {}
}

function hookSslReadWrite() {
  var libs = ['libssl.so', 'libconscrypt_jni.so', 'libcronet.so'];
  libs.forEach(function (lib) {
    ['SSL_write', 'SSL_read'].forEach(function (fn) {
      var addr = Module.findExportByName(lib, fn);
      if (!addr) return;
      try {
        Interceptor.attach(addr, {
          onEnter: function (args) {
            this.fn = fn;
            this.buf = args[1];
            this.len = args[2].toInt32();
          },
          onLeave: function (retval) {
            var n = retval.toInt32();
            if (n <= 0 || !this.buf) return;
            var take = Math.min(n, 1800);
            var text = '';
            try { text = this.buf.readUtf8String(take); } catch (e) {
              try { text = Memory.readUtf8String(this.buf); } catch (e2) { return; }
            }
            if (!looksHttpish(text) && text.indexOf('http') < 0) return;
            writeEvent('net.https', this.fn, TARGET_PKG, truncateHttp(text), null);
          }
        });
      } catch (e) {}
    });
  });
}

function hookOkHttpBodies() {
  try {
    var RealCall = Java.use('okhttp3.RealCall');
    RealCall.execute.implementation = function () {
      var req = this.request();
      var url = '';
      var method = '';
      var reqBody = '';
      try {
        url = req.url().toString();
        method = req.method();
        var body = req.body();
        if (body) {
          var Buffer = Java.use('okio.Buffer');
          var buf = Buffer.$new();
          body.writeTo(buf);
          reqBody = buf.readUtf8();
        }
      } catch (e) {}
      var resp = this.execute();
      var respText = '';
      var code = '';
      try {
        code = '' + resp.code();
        var peek = resp.peekBody(2048);
        respText = peek.string();
      } catch (e) {}
      writeEvent('net.https', 'OkHttp MITM ' + method, url, 'HTTP ' + code + ' ' + truncateHttp(reqBody + '\n---\n' + respText), null);
      return resp;
    };
  } catch (e) {}
}
