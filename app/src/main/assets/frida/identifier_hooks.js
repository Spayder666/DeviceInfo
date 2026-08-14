'use strict';

var EVENT_FILE = '/data/local/tmp/access_monitor/events.jsonl';
var TARGET_PKG = '__TARGET_PACKAGE__';

function writeEvent(identifierId, action, request, response, permission) {
  try {
    var JSONObject = Java.use('org.json.JSONObject');
    var obj = JSONObject.$new();
    obj.put('identifierId', identifierId);
    obj.put('action', action);
    if (request) obj.put('request', String(request));
    if (response) obj.put('response', String(response));
    if (permission) obj.put('permission', permission);
    obj.put('timestamp', Java.use('java.lang.System').currentTimeMillis());
    obj.put('source', 'frida');

    var File = Java.use('java.io.File');
    var FileWriter = Java.use('java.io.FileWriter');
    var dir = File.$new('/data/local/tmp/access_monitor');
    if (!dir.exists()) dir.mkdirs();
    var fw = FileWriter.$new(EVENT_FILE, true);
    fw.write(obj.toString() + '\n');
    fw.close();
  } catch (e) {
    send({ error: String(e) });
  }
}

function safeStr(v) {
  if (v === null || v === undefined) return '';
  try { return String(v); } catch (e) { return '<error>'; }
}

function hookTelephonyManager() {
  var TM = Java.use('android.telephony.TelephonyManager');
  var hooks = [
    ['getImei', 'tel.imei', 'READ_PRIVILEGED_PHONE_STATE'],
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
            if (key.indexOf('ro.') === 0 || key.indexOf('gsm.') === 0 || key.indexOf('persist.') === 0) {
              var id = mapPropertyToId(key);
              writeEvent(id, 'SystemProperties.' + m, key, safeStr(result), null);
            }
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
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

  try {
    var BuildVersion = Java.use('android.os.Build$VERSION');
    var fields = ['RELEASE', 'SDK_INT', 'INCREMENTAL', 'SECURITY_PATCH', 'CODENAME'];
    fields.forEach(function (f) {
      try {
        var field = BuildVersion.class.getDeclaredField(f);
        field.setAccessible(true);
      } catch (e) {}
    });
  } catch (e) {}

  // Log Build static field reads via reflection hook on Build class init values
  try {
    var fields = [
      ['MODEL', 'build.model'], ['MANUFACTURER', 'build.manufacturer'], ['DEVICE', 'build.device'],
      ['BRAND', 'build.brand'], ['PRODUCT', 'build.product'], ['HARDWARE', 'build.hardware'],
      ['BOARD', 'build.board'], ['BOOTLOADER', 'build.bootloader'], ['DISPLAY', 'build.display'],
      ['FINGERPRINT', 'build.fingerprint'], ['ID', 'build.id'], ['HOST', 'build.host'],
      ['TAGS', 'build.tags'], ['TYPE', 'build.type'], ['USER', 'build.user'],
      ['SOC_MANUFACTURER', 'build.soc_manufacturer'], ['SOC_MODEL', 'build.soc_model'],
      ['SKU', 'build.sku'], ['ODM_SKU', 'build.odm_sku'], ['RADIO', 'build.radio'],
      ['TIME', 'build.time'], ['SUPPORTED_ABIS', 'build.supported_abis']
    ];
    fields.forEach(function (f) {
      try {
        var fieldObj = Build[f[0]];
        var val = fieldObj ? fieldObj.value : '<unknown>';
        writeEvent(f[1], 'Build.' + f[0], 'static field read', safeStr(val), null);
      } catch (e) {}
    });
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
        if (uri.indexOf('settings') >= 0 || uri.indexOf('telephony') >= 0 || uri.indexOf('gsf') >= 0) {
          writeEvent('cp.settings_secure', 'ContentResolver.query', uri, 'rows=' + (result ? result.getCount() : 0), null);
        }
        return result;
      };
    });
  } catch (e) {}
}

function hookLocation() {
  try {
    var LM = Java.use('android.location.LocationManager');
    ['getLastKnownLocation', 'requestLocationUpdates', 'getCurrentLocation'].forEach(function (m) {
      try {
        LM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeEvent('location.gps', 'LocationManager.' + m, safeStr(arguments[0]), safeStr(result), 'ACCESS_FINE_LOCATION');
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

Java.perform(function () {
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
});
