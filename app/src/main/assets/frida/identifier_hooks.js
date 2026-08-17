'use strict';

var TARGET_PKG = '__TARGET_PACKAGE__';
var INJECT_NONCE = '__INJECT_NONCE__';
var MITM_ENABLED = __MITM_ENABLED__;

(function () {
  var line = '{"identifierId":"frida.boot","action":"Frida: скрипт загружен","request":"' +
    TARGET_PKG + '","response":"early","package":"' + TARGET_PKG +
    '","timestamp":' + Date.now() + ',"source":"frida","nonce":"' + INJECT_NONCE + '"}';
  try { console.log('AMF ' + line); } catch (e) {}
})();
var EVENT_FILES = [
  '/data/user/0/' + TARGET_PKG + '/cache/access_monitor_events.jsonl',
  '/data/data/' + TARGET_PKG + '/cache/access_monitor_events.jsonl',
  '/data/local/tmp/access_monitor/events.jsonl'
];

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
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/[\x00-\x1f]/g, function (c) {
      return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
    });
}

var logWrite = null;
var logTag = null;
var inNativeHook = 0;
var fileQueue = [];

function writeAndroidLog(line) {
  try {
    if (!logWrite) {
      var addr = Module.findExportByName('liblog.so', '__android_log_write');
      if (!addr) addr = Module.findExportByName(null, '__android_log_write');
      if (!addr) return;
      logWrite = new NativeFunction(addr, 'int', ['int', 'pointer', 'pointer']);
      logTag = Memory.allocUtf8String('AccessMonFrida');
    }
    var text = line.length > 3500 ? line.substring(0, 3500) : line;
    logWrite(4, logTag, Memory.allocUtf8String(text));
  } catch (e) {}
}

function appendEventFile(line) {
  var io = initNativeIo();
  if (!io) return;
  var payload = line + '\n';
  var mode = Memory.allocUtf8String('a');
  var buf = Memory.allocUtf8String(payload);
  for (var i = 0; i < EVENT_FILES.length; i++) {
    try {
      var path = Memory.allocUtf8String(EVENT_FILES[i]);
      var fp = io.fopen(path, mode);
      if (fp.isNull()) continue;
      io.fwrite(buf, 1, payload.length, fp);
      io.fclose(fp);
      return;
    } catch (e) {}
  }
}

function writeLine(line, forceQueue) {
  try { console.log('AMF ' + line); } catch (e) {}
  writeAndroidLog(line);
  if (forceQueue || inNativeHook > 0) {
    if (fileQueue.length < 250) fileQueue.push(line);
    return;
  }
  appendEventFile(line);
}

setInterval(function () {
  if (inNativeHook > 0 || fileQueue.length === 0) return;
  var batch = fileQueue.splice(0, 30);
  for (var i = 0; i < batch.length; i++) {
    try { appendEventFile(batch[i]); } catch (e) {}
  }
}, 500);

function writeEvent(identifierId, action, request, response, permission, opts) {
  opts = opts || {};
  var ts = Date.now();
  var req = request || action || identifierId || '';
  var res = (response === null || response === undefined) ? '' : String(response);
  var line = '{"identifierId":"' + jsonEscape(identifierId || '') +
    '","action":"' + jsonEscape(action || '') +
    '","request":"' + jsonEscape(req) +
    '","response":"' + jsonEscape(res) +
    '","permission":"' + jsonEscape(permission || '') +
    '","package":"' + jsonEscape(TARGET_PKG) +
    '","timestamp":' + ts +
    ',"source":"frida"' +
    ',"nonce":"' + jsonEscape(INJECT_NONCE) + '"';
  if (opts.cached) line += ',"cached":true';
  line += '}';
  writeLine(line, !!(opts && opts.async));
}

var lastReq = {};
function writeReq(identifierId, action, request, response, permission, opts) {
  var key = (identifierId || '') + '|' + (action || '') + '|' + (request || '');
  var now = Date.now();
  if (lastReq[key] && now - lastReq[key] < 800) return;
  lastReq[key] = now;
  writeEvent(identifierId, action, request, response, permission, opts);
}

var onceReq = {};
function writeOnce(identifierId, action, request, response, permission, opts) {
  var key = (identifierId || '') + '|' + (action || '') + '|' + (request || '');
  if (onceReq[key]) return;
  onceReq[key] = 1;
  writeEvent(identifierId, action, request, response, permission, opts);
}

function classifyBrowserJs(script) {
  var s = String(script || '');
  if (!s) return '';
  if (/FingerprintJS|fingerprintjs|creepjs|ClientJS|ThumbmarkJS|getFingerprint\(/i.test(s)) return 'browser.fp_lib';
  if (/toDataURL|getImageData|OffscreenCanvas/i.test(s)) return 'browser.canvas';
  if (/WEBGL_debug_renderer_info|UNMASKED_VENDOR|UNMASKED_RENDERER|getSupportedExtensions|webgl/i.test(s)) return 'browser.webgl';
  if (/OfflineAudioContext|AudioContext|createOscillator|createDynamicsCompressor/i.test(s)) return 'browser.audio';
  if (/queryLocalFonts|document\.fonts|offsetWidth.{0,40}font|measureText/i.test(s)) return 'browser.fonts';
  if (/speechSynthesis|getVoices/i.test(s)) return 'browser.speech';
  if (/userAgentData\.|navigator\.userAgentData/i.test(s) && !/getHighEntropyValues|Sec-CH-UA/i.test(s)) return 'browser.ua_data';
  if (/userAgentData|getHighEntropyValues|Sec-CH-UA/i.test(s)) return 'browser.ch_ua';
  if (/hardwareConcurrency/i.test(s)) return 'browser.hardware_concurrency';
  if (/deviceMemory/i.test(s)) return 'browser.device_memory';
  if (/enumerateDevices|getUserMedia|mediaDevices/i.test(s)) return 'browser.media_devices';
  if (/RTCPeerConnection|iceCandidate|stun:/i.test(s)) return 'net.stun';
  if (/indexedDB|localStorage|sessionStorage|openDatabase/i.test(s)) return 'browser.storage_js';
  if (/storage\.estimate|navigator\.storage/i.test(s)) return 'browser.storage_est';
  if (/matchMedia|prefers-color-scheme|prefers-reduced-motion|color-gamut|dynamic-range/i.test(s)) return 'browser.css_media';
  if (/Intl\.DateTimeFormat|resolvedOptions/i.test(s)) return 'browser.intl';
  if (/navigator\.languages/i.test(s)) return 'browser.languages';
  if (/webdriver|HeadlessChrome|domAutomation/i.test(s)) return 'browser.webdriver';
  if (/permissions\.query/i.test(s)) return 'browser.permissions_js';
  if (/navigator\.connection|effectiveType/i.test(s)) return 'browser.connection';
  if (/getBattery/i.test(s)) return 'browser.battery_js';
  if (/navigator\.gpu|requestAdapter|WebGPU/i.test(s)) return 'browser.webgpu';
  if (/devicePixelRatio|colorDepth|pixelDepth|screen\.(width|height)/i.test(s)) return 'browser.screen_js';
  if (/navigator\.(platform|vendor|plugins|mimeTypes|pdfViewerEnabled)/i.test(s)) return 'browser.navigator';
  if (/Math\.(tan|sinh|cosh|expm1)/i.test(s)) return 'browser.math';
  if (/getClientRects/i.test(s)) return 'browser.domrect';
  if (/Worker\(|SharedWorker|serviceWorker\.register/i.test(s)) return 'browser.worker';
  if (/Notification\.requestPermission/i.test(s)) return 'browser.notification_js';
  if (/requestMediaKeySystemAccess|MediaKeys|PROTECTED_MEDIA/i.test(s)) return 'browser.eme';
  if (/navigator\.credentials|PublicKeyCredential/i.test(s)) return 'browser.webauthn_js';
  if (/browsingTopics|sharedStorage|privateAggregation/i.test(s)) return 'browser.topics_js';
  if (/performance\.memory|jsHeapSizeLimit/i.test(s)) return 'browser.performance';
  if (/addJavascriptInterface|evaluateJavascript/i.test(s)) return 'browser.js_interface';
  return '';
}

function classifyUri(uri) {
  var u = String(uri || '').toLowerCase();
  if (u.indexOf('profile') >= 0 && u.indexOf('contact') >= 0) return 'contacts.profile';
  if (u.indexOf('contacts') >= 0) return 'contacts.query';
  if (u.indexOf('mms') >= 0) return 'mms.query';
  if (u.indexOf('sms') >= 0) return 'sms.inbox';
  if (u.indexOf('call_log') >= 0) return 'call_log.query';
  if (u.indexOf('calendar') >= 0) return 'calendar.query';
  if (u.indexOf('icc') >= 0) return 'contacts.sim';
  if (u.indexOf('telephony') >= 0) return 'cp.telephony';
  if (u.indexOf('gsf') >= 0 || u.indexOf('gservices') >= 0) return 'ad.gsf_id';
  if (u.indexOf('settings/secure') >= 0) return 'settings.secure';
  if (u.indexOf('settings/global') >= 0) return 'settings.global';
  if (u.indexOf('settings/system') >= 0) return 'settings.system';
  if (u.indexOf('media') >= 0) return 'storage.media';
  if (u.indexOf('browser') >= 0) return 'browser.history';
  if (u.indexOf('voicemail') >= 0) return 'voicemail.query';
  if (u.indexOf('blocked') >= 0) return 'blocked.query';
  if (u.indexOf('download') >= 0) return 'storage.downloads';
  if (u.indexOf('health') >= 0) return 'health.connect';
  if (u.indexOf('document') >= 0) return 'hw.saf';
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
  if (k === 'adb_enabled') return 'settings.adb';
  if (k === 'development_settings_enabled') return 'settings.development';
  if (k.indexOf('animation_scale') >= 0 || k.indexOf('animator_duration') >= 0) return 'settings.animation';
  if (k === 'data_roaming') return 'settings.data_roaming';
  if (k.indexOf('touch_exploration') >= 0) return 'settings.touch_exploration';
  if (k === 'alarm_alert') return 'settings.alarm';
  if (k === 'date_format') return 'settings.date_format';
  if (k === 'font_scale') return 'settings.font_scale';
  if (k === 'screen_off_timeout') return 'settings.screen_off';
  if (k === 'time_12_24') return 'settings.time_12_24';
  if (k === 'screen_brightness' || k === 'screen_brightness_mode') return 'settings.brightness';
  if (k === 'boot_count') return 'settings.boot_count';
  if (k.indexOf('airplane_mode') >= 0) return 'settings.airplane';
  if (k.indexOf('auto_time') >= 0) return 'settings.auto_time';
  if (k.indexOf('private_dns') >= 0) return 'settings.private_dns';
  if (k === 'install_non_market_apps') return 'settings.unknown_sources';
  if (k === 'stay_on_while_plugged_in') return 'settings.stay_on';
  if (k.indexOf('end_button') >= 0) return 'settings.end_button';
  if (k.indexOf('accessibility') >= 0) return 'settings.accessibility';
  if (k.indexOf('notification_listener') >= 0) return 'settings.notification_listeners';
  if (k.indexOf('input_method') >= 0) return 'settings.input_method';
  if (k.indexOf('mock_location') >= 0) return 'settings.mock_location';
  if (k.indexOf('location') >= 0) return 'settings.location_mode';
  if (k.indexOf('http_proxy') >= 0) return 'net.proxy';
  if (k === 'advertising_id' || k === 'ad_aaid' || k === 'ads_aaid' || k.indexOf('aaid') >= 0) return 'ad.gaid';
  if (k.indexOf('samsungaccount') >= 0) return 'oem.samsung_account';
  if (k.indexOf('sem_auto_wifi') >= 0) return 'oem.samsung_wifi';
  if (k.indexOf('dsa_sim') >= 0) return 'oem.samsung_imsi';
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
    ['getUiccCardsInfo', 'tel.has_icc', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getMsisdn', 'tel.msisdn', 'READ_PHONE_NUMBERS'],
    ['getManufacturerCode', 'tel.manufacturer_code', null],
    ['getIccAuthentication', 'tel.icc_auth', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getIsimImpi', 'tel.isim', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getIsimImpu', 'tel.isim', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getIsimDomain', 'tel.isim', 'READ_PRIVILEGED_PHONE_STATE'],
    ['getCardIdForDefaultEuicc', 'tel.eid', 'READ_PRIVILEGED_PHONE_STATE'],
    ['registerTelephonyCallback', 'tel.callback', 'READ_PHONE_STATE'],
    ['listen', 'tel.callback', 'READ_PHONE_STATE'],
    ['isNetworkRoaming', 'tel.network_operator', null],
    ['getSignalStrength', 'location.cell', 'READ_PHONE_STATE'],
    ['getEmergencyNumberList', 'tel.phone_interface', null],
    ['iccOpenLogicalChannel', 'tel.icc_auth', 'MODIFY_PHONE_STATE']
  ];

  hooks.forEach(function (h) {
    var method = h[0], id = h[1], perm = h[2];
    try {
      TM[method].overloads.forEach(function (overload) {
        overload.implementation = function () {
          var args = [];
          for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
          var result = overload.apply(this, arguments);
          writeEvent(id, 'TelephonyManager.' + method, summarizeArgs(args), summarizeResult(result), perm);
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
      'getMcc', 'getMnc', 'getCardString', 'isEmbedded', 'getPortIndex', 'getGroupUuid'].forEach(function (m) {
      try {
        SI[m].implementation = function () {
          var result = this[m]();
          var sid = 'sub.subscription_id';
          if (m === 'getIccId') sid = 'sub.iccid';
          else if (m === 'getNumber') sid = 'sub.phone_number';
          else if (m === 'getCardString') sid = 'sub.card_string';
          else if (m === 'isEmbedded') sid = 'sub.embedded';
          else if (m === 'getSimSlotIndex') sid = 'sub.sim_slot';
          else if (m === 'getMccString' || m === 'getMcc') sid = 'sub.mcc';
          else if (m === 'getMncString' || m === 'getMnc') sid = 'sub.mnc';
          else if (m === 'getCardId') sid = 'sub.card_id';
          else if (m === 'getPortIndex') sid = 'sub.port_index';
          else if (m === 'getGroupUuid') sid = 'sub.group_uuid';
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
      try {
        Cls.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, key, def) {
          var result = this.getLong(cr, key, def);
          writeEvent(classifySettingsKey(key), c[0] + '.getLong', safeStr(key), safeStr(result), null);
          return result;
        };
      } catch (e) {}
      try {
        Cls.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, key, def) {
          var result = this.getFloat(cr, key, def);
          writeEvent(classifySettingsKey(key), c[0] + '.getFloat', safeStr(key), safeStr(result), null);
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
  return key.indexOf('ro.product.') === 0 ||
    key.indexOf('ro.build.') === 0 ||
    key.indexOf('ro.soc.') === 0 ||
    key.indexOf('ro.serial') === 0 ||
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
    key.indexOf('gsm.sim') === 0 ||
    key.indexOf('ril.serial') === 0 ||
    key.indexOf('ro.odm.build') === 0 ||
    key.indexOf('ro.build.version.emui') === 0 ||
    key.indexOf('hw_sc.build') === 0;
}

function mapPropertyToId(key) {
  var map = {
    'ro.product.model': 'build.model',
    'ro.product.manufacturer': 'build.manufacturer',
    'ro.product.device': 'build.device',
    'ro.product.brand': 'build.brand',
    'ro.product.name': 'build.product',
    'ro.hardware': 'build.hardware',
    'ro.product.board': 'build.board',
    'ro.bootloader': 'build.bootloader',
    'ro.build.display.id': 'build.display',
    'ro.build.fingerprint': 'build.fingerprint',
    'ro.build.id': 'build.id',
    'ro.build.host': 'build.host',
    'ro.build.tags': 'build.tags',
    'ro.build.type': 'build.type',
    'ro.build.user': 'build.user',
    'ro.soc.manufacturer': 'build.soc_manufacturer',
    'ro.soc.model': 'build.soc_model',
    'ro.boot.hardware.sku': 'build.sku',
    'ro.boot.product.hardware.sku': 'build.odm_sku',
    'ro.build.date.utc': 'build.time',
    'ro.product.cpu.abilist': 'build.supported_abis',
    'ro.product.cpu.abilist32': 'build.supported_32_bit_abis',
    'ro.product.cpu.abilist64': 'build.supported_64_bit_abis',
    'ro.boot.qemu': 'build.is_emulator',
    'ro.kernel.qemu': 'build.is_emulator',
    'ro.treble.enabled': 'build.is_treble_enabled',
    'ro.build.version.release': 'version.release',
    'ro.build.version.sdk': 'version.sdk',
    'ro.build.version.incremental': 'version.incremental',
    'ro.build.version.codename': 'version.codename',
    'ro.build.version.security_patch': 'version.security_patch',
    'ro.build.version.base_os': 'version.base_os',
    'ro.build.version.preview_sdk': 'version.preview_sdk',
    'ro.product.first_api_level': 'version.first_sdk',
    'ro.odm.build.media_performance_class': 'version.mpc',
    'ro.bootimage.build.fingerprint': 'prop.bootimage.fingerprint',
    'ro.serialno': 'prop.serialno',
    'ro.boot.serialno': 'prop.boot.serialno',
    'ril.serialnumber': 'prop.ril.serial',
    'gsm.version.baseband': 'prop.gsm.version.baseband',
    'gsm.sim.state': 'prop.gsm.sim.state',
    'persist.radio.imei': 'prop.persist.radio.imei',
    'persist.radio.factory_sn': 'prop.persist.radio.factory_sn',
    'net.hostname': 'prop.net.hostname',
    'ro.com.google.gmsversion': 'prop.gms.version',
    'ro.boot.hardware': 'prop.boot.hardware',
    'persist.sys.timezone': 'prop.timezone',
    'persist.sys.locale': 'prop.locale',
    'ro.sf.lcd_density': 'prop.density',
    'ro.opengles.version': 'prop.opengles',
    'ro.secure': 'root.props',
    'ro.debuggable': 'root.props',
    'ro.boot.verifiedbootstate': 'attest.verified_boot',
    'ro.boot.flash.locked': 'attest.flash_locked',
    'ro.boot.vbmeta.device_state': 'attest.verified_boot',
    'ro.boot.vbmeta.digest': 'attest.vbmeta',
    'ro.boot.warranty_bit': 'attest.warranty',
    'ro.build.version.emui': 'fraud.harmony',
    'hw_sc.build.platform.version': 'fraud.harmony'
  };
  if (key.indexOf('lsposed') >= 0 || key.indexOf('lspd') >= 0) return 'root.lsposed';
  if (key.indexOf('xposed') >= 0 || key.indexOf('taichi') >= 0) return 'root.xposed';
  if (key.indexOf('magisk') >= 0 || key.indexOf('zygisk') >= 0) return 'root.magisk';
  if (key.indexOf('ksu') >= 0 || key.indexOf('apatch') >= 0) return 'root.ksu';
  if (key.indexOf('qemu') >= 0 || key.indexOf('goldfish') >= 0 || key.indexOf('ranchu') >= 0) return 'root.emulator';
  if (key.indexOf('selinux') >= 0) return 'root.selinux';
  if (key.indexOf('emui') >= 0 || key.indexOf('harmony') >= 0 || key.indexOf('hw_sc.build') >= 0) return 'fraud.harmony';
  if (key.indexOf('ro.product.') === 0) return 'prop.product.model';
  if (key.indexOf('ro.build.') === 0) return 'prop.build.fingerprint';
  if (key.indexOf('ro.hardware') === 0) return 'prop.hardware';
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
    var Build2 = Java.use('android.os.Build');
    if (Build2.getRadioVersion) {
      Build2.getRadioVersion.implementation = function () {
        var result = this.getRadioVersion();
        writeEvent('build.radio', 'Build.getRadioVersion()', '', safeStr(result), null);
        return result;
      };
    }
  } catch (e) {}
  hookBuildGetstatic();
}

var buildWatchIds = [];
var buildWatchValues = [];
var buildGetstaticHooked = false;

function attachNamedExport(mod, names, opts) {
  for (var i = 0; i < names.length; i++) {
    var addr = null;
    try { addr = Module.findExportByName(mod, names[i]); } catch (e) { addr = null; }
    if (!addr) {
      try { addr = Module.findExportByName(null, names[i]); } catch (e2) { addr = null; }
    }
    if (!addr) continue;
    try {
      Interceptor.attach(addr, opts);
      return true;
    } catch (e) {}
  }
  return false;
}

function hookBuildGetstatic() {
  if (buildGetstaticHooked) return;
  buildGetstaticHooked = true;
  var reportBuild = new NativeCallback(function (idx) {
    inNativeHook++;
    try {
      var id = buildWatchIds[idx];
      if (id) writeOnce(id, 'Build.getstatic', id, buildWatchValues[idx] || '', null, { async: true });
    } catch (e) {
    } finally {
      inNativeHook--;
    }
  }, 'void', ['int']);

  var cm;
  try {
    cm = new CModule([
      '#include <gum/guminterceptor.h>',
      'extern void report_build(int idx);',
      '#define MAXW 64',
      'static void *objs[MAXW];',
      'static int obj_idx[MAXW];',
      'static int nobj;',
      'static void *fields[MAXW];',
      'static int field_idx[MAXW];',
      'static int nfield;',
      'void am_add_obj(void *p, int idx) { if (p && nobj < MAXW) { objs[nobj] = p; obj_idx[nobj] = idx; nobj++; } }',
      'void am_add_field(void *p, int idx) { if (p && nfield < MAXW) { fields[nfield] = p; field_idx[nfield] = idx; nfield++; } }',
      'static int find_obj(void *p) { int i; if (!p) return -1; for (i = 0; i < nobj; i++) if (objs[i] == p) return obj_idx[i]; return -1; }',
      'static int find_field(void *p) { int i; if (!p) return -1; for (i = 0; i < nfield; i++) if (fields[i] == p) return field_idx[i]; return -1; }',
      'void on_get_obj_leave(GumInvocationContext *ic) {',
      '  void *ret = gum_invocation_context_get_return_value(ic);',
      '  int idx = find_obj(ret);',
      '  if (idx >= 0) report_build(idx);',
      '}',
      'void on_get_field_enter(GumInvocationContext *ic) {',
      '  void *self = gum_invocation_context_get_nth_argument(ic, 0);',
      '  int idx = find_field(self);',
      '  if (idx >= 0) report_build(idx);',
      '}'
    ].join('\n'), { report_build: reportBuild });
  } catch (e) {
    return;
  }

  function addWatch(id, fid, obj, value) {
    var idx = buildWatchIds.length;
    buildWatchIds.push(id);
    buildWatchValues.push(value || '');
    try { if (fid && !fid.isNull()) cm.am_add_field(fid, idx); } catch (e) {}
    try { if (obj && !obj.isNull()) cm.am_add_obj(obj, idx); } catch (e) {}
  }

  var specs = [
    ['android/os/Build', 'MODEL', 'Ljava/lang/String;', 'build.model'],
    ['android/os/Build', 'DEVICE', 'Ljava/lang/String;', 'build.device'],
    ['android/os/Build', 'MANUFACTURER', 'Ljava/lang/String;', 'build.manufacturer'],
    ['android/os/Build', 'BRAND', 'Ljava/lang/String;', 'build.brand'],
    ['android/os/Build', 'PRODUCT', 'Ljava/lang/String;', 'build.product'],
    ['android/os/Build', 'HARDWARE', 'Ljava/lang/String;', 'build.hardware'],
    ['android/os/Build', 'BOARD', 'Ljava/lang/String;', 'build.board'],
    ['android/os/Build', 'BOOTLOADER', 'Ljava/lang/String;', 'build.bootloader'],
    ['android/os/Build', 'DISPLAY', 'Ljava/lang/String;', 'build.display'],
    ['android/os/Build', 'FINGERPRINT', 'Ljava/lang/String;', 'build.fingerprint'],
    ['android/os/Build', 'ID', 'Ljava/lang/String;', 'build.id'],
    ['android/os/Build', 'HOST', 'Ljava/lang/String;', 'build.host'],
    ['android/os/Build', 'TAGS', 'Ljava/lang/String;', 'build.tags'],
    ['android/os/Build', 'TYPE', 'Ljava/lang/String;', 'build.type'],
    ['android/os/Build', 'USER', 'Ljava/lang/String;', 'build.user'],
    ['android/os/Build', 'RADIO', 'Ljava/lang/String;', 'build.radio'],
    ['android/os/Build', 'SOC_MANUFACTURER', 'Ljava/lang/String;', 'build.soc_manufacturer'],
    ['android/os/Build', 'SOC_MODEL', 'Ljava/lang/String;', 'build.soc_model'],
    ['android/os/Build', 'SKU', 'Ljava/lang/String;', 'build.sku'],
    ['android/os/Build', 'ODM_SKU', 'Ljava/lang/String;', 'build.odm_sku'],
    ['android/os/Build', 'SERIAL', 'Ljava/lang/String;', 'build.serial'],
    ['android/os/Build', 'SUPPORTED_ABIS', '[Ljava/lang/String;', 'build.supported_abis'],
    ['android/os/Build', 'SUPPORTED_32_BIT_ABIS', '[Ljava/lang/String;', 'build.supported_32_bit_abis'],
    ['android/os/Build', 'SUPPORTED_64_BIT_ABIS', '[Ljava/lang/String;', 'build.supported_64_bit_abis'],
    ['android/os/Build', 'TIME', 'J', 'build.time'],
    ['android/os/Build', 'IS_EMULATOR', 'Z', 'build.is_emulator'],
    ['android/os/Build', 'IS_TREBLE_ENABLED', 'Z', 'build.is_treble_enabled'],
    ['android/os/Build$VERSION', 'SDK_INT', 'I', 'version.sdk'],
    ['android/os/Build$VERSION', 'RELEASE', 'Ljava/lang/String;', 'version.release'],
    ['android/os/Build$VERSION', 'INCREMENTAL', 'Ljava/lang/String;', 'version.incremental'],
    ['android/os/Build$VERSION', 'CODENAME', 'Ljava/lang/String;', 'version.codename'],
    ['android/os/Build$VERSION', 'SECURITY_PATCH', 'Ljava/lang/String;', 'version.security_patch'],
    ['android/os/Build$VERSION', 'BASE_OS', 'Ljava/lang/String;', 'version.base_os'],
    ['android/os/Build$VERSION', 'PREVIEW_SDK_INT', 'I', 'version.preview_sdk'],
    ['android/os/Build$VERSION', 'FIRST_SDK_INT', 'I', 'version.first_sdk'],
    ['android/os/Build$VERSION', 'MEDIA_PERFORMANCE_CLASS', 'I', 'version.mpc']
  ];

  try {
    var env = Java.vm.getEnv();
    specs.forEach(function (spec) {
      try {
        var klass = env.findClass(spec[0]);
        var fid = env.getStaticFieldId(klass, spec[1], spec[2]);
        if (!fid || fid.isNull()) return;
        var obj = null;
        var value = '';
        if (spec[2].indexOf('Ljava/lang/String;') >= 0 || spec[2].charAt(0) === '[') {
          try { obj = env.getStaticObjectField(klass, fid); } catch (e2) { obj = null; }
          try { if (obj) value = env.getStringUtf8(obj) || ''; } catch (e2) {}
        } else if (spec[2] === 'I') {
          try { value = '' + env.getStaticIntField(klass, fid); } catch (e2) {}
        } else if (spec[2] === 'J') {
          try { value = '' + env.getStaticLongField(klass, fid); } catch (e2) {}
        } else if (spec[2] === 'Z') {
          try { value = env.getStaticBooleanField(klass, fid) ? 'true' : 'false'; } catch (e2) {}
        }
        addWatch(spec[3], fid, obj, value);
      } catch (e) {}
    });
  } catch (e) {}

  try {
    [['android.os.Build', 'MODEL', 'build.model'],
      ['android.os.Build', 'FINGERPRINT', 'build.fingerprint'],
      ['android.os.Build', 'MANUFACTURER', 'build.manufacturer'],
      ['android.os.Build$VERSION', 'RELEASE', 'version.release']].forEach(function (pair) {
      try {
        var f = Java.use(pair[0]).class.getDeclaredField(pair[1]);
        f.setAccessible(true);
        var v = f.get(null);
        var h = v && (v.$h || v.handle);
        if (h) {
          var idx = buildWatchIds.indexOf(pair[2]);
          if (idx < 0) {
            idx = buildWatchIds.length;
            buildWatchIds.push(pair[2]);
            buildWatchValues.push(safeStr(v));
          }
          cm.am_add_obj(h, idx);
        }
      } catch (e) {}
    });
  } catch (e) {}

  // One compiled-code getter each. No libart enumerateSymbols / ArtField::Get*.
  attachNamedExport('libart.so', [
    'art_quick_get_obj_static',
    'artGetObjStaticFromCompiledCode'
  ], { onLeave: cm.on_get_obj_leave });
  attachNamedExport('libart.so', [
    'art_quick_get_32_static',
    'artGet32StaticFromCompiledCode'
  ], { onEnter: cm.on_get_field_enter });
}

function hookWifiAndBluetooth() {
  try {
    var WifiInfo = Java.use('android.net.wifi.WifiInfo');
    ['getMacAddress', 'getBSSID', 'getSSID', 'getNetworkId', 'getIpAddress',
      'getApMldMacAddress', 'getPasspointFqdn', 'getRandomizedMacAddress',
      'getWifiStandard', 'getFrequency'].forEach(function (m) {
      try {
        WifiInfo[m].implementation = function () {
          var result = this[m]();
          var wid = 'wifi.mac';
          if (m === 'getBSSID') wid = 'wifi.bssid';
          else if (m === 'getSSID') wid = 'wifi.ssid';
          else if (m === 'getIpAddress') wid = 'wifi.ip';
          else if (m === 'getNetworkId') wid = 'wifi.network_id';
          else if (m === 'getApMldMacAddress') wid = 'wifi.ap_mld_mac';
          else if (m === 'getPasspointFqdn') wid = 'wifi.passpoint';
          else if (m === 'getRandomizedMacAddress') wid = 'wifi.randomized_mac';
          else if (m === 'getWifiStandard' || m === 'getFrequency') wid = 'wifi.standard';
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
          writeEvent(m === 'getName' ? 'bt.local_name' : 'bt.local_mac', 'BluetoothAdapter.' + m, '', safeStr(result), 'BLUETOOTH_CONNECT');
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
          writeEvent(m === 'getName' ? 'bt.remote_name' : 'bt.remote_mac', 'BluetoothDevice.' + m, '', safeStr(result), 'BLUETOOTH_CONNECT');
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
      writeEvent(id, 'MediaDrm.getPropertyByteArray', safeStr(key), bytesToHex(result), null);
      return result;
    };
    MD.getPropertyString.implementation = function (key) {
      var result = this.getPropertyString(key);
      var k = safeStr(key);
      var id = 'drm.version';
      if (k === 'vendor') id = 'drm.vendor';
      else if (/securityLevel|securitylevel/i.test(k)) id = 'drm.security_level';
      else if (k === 'version') id = 'drm.version';
      writeEvent(id, 'MediaDrm.getPropertyString', k, safeStr(result), null);
      return result;
    };
  } catch (e) {}
}

function hookAdvertisingId() {
  try {
    var AIC = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient');
    AIC.getAdvertisingIdInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        try {
          var id = result.getId();
          var limited = result.isLimitAdTrackingEnabled();
          writeEvent('ad.gaid', 'AdvertisingIdClient.getAdvertisingIdInfo', '', safeStr(id) + ' limited=' + limited, 'AD_ID');
        } catch (e) {}
        return result;
      };
    });
  } catch (e) {}
  try {
    var Info = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info');
    Info.getId.implementation = function () {
      var r = this.getId();
      writeEvent('ad.gaid', 'AdvertisingIdClient.Info.getId', '', safeStr(r), 'AD_ID');
      return r;
    };
    try {
      Info.isLimitAdTrackingEnabled.implementation = function () {
        var r = this.isLimitAdTrackingEnabled();
        writeEvent('ad.limit_tracking', 'AdvertisingIdClient.Info.isLimitAdTrackingEnabled', '', safeStr(r), 'AD_ID');
        return r;
      };
    } catch (e) {}
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
  try {
    var ASI = Java.use('com.google.android.gms.appset.AppSetIdInfo');
    ASI.getId.implementation = function () {
      var r = this.getId();
      writeEvent('ad.app_set_id', 'AppSetIdInfo.getId', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
}

function hookAccounts() {
  try {
    var AM = Java.use('android.accounts.AccountManager');
    ['getAccounts', 'getAccountsByType', 'getAccountsAsUser', 'getAccountsByTypeForPackage'].forEach(function (m) {
      try {
        AM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            var names = [];
            try {
              if (result) {
                for (var i = 0; i < result.length; i++) names.push(safeStr(result[i].name));
              }
            } catch (e) {}
            writeEvent(
              m.indexOf('ByType') >= 0 ? 'account.by_type' : 'account.list',
              'AccountManager.' + m,
              safeStr(arguments[0]),
              names.length ? names.join(', ') : ('count=' + (result ? result.length : 0)),
              'GET_ACCOUNTS'
            );
            return result;
          };
        });
      } catch (e) {}
    });
    ['getAuthToken', 'peekAuthToken', 'blockingGetAuthToken', 'getAuthTokenByFeatures'].forEach(function (m) {
      try {
        AM[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            var acc = '';
            try { acc = arguments[0] ? safeStr(arguments[0].name) : ''; } catch (e) {}
            writeEvent('account.auth_token', 'AccountManager.' + m, acc || safeStr(arguments[0]), 'token-requested', 'GET_ACCOUNTS');
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
              if (isRootPkg(pkg)) {
                writeRoot('root.packages', name + '.' + m, pkg, 'found');
                writeRoot(classifyClass(pkg), name + '.' + m, pkg, 'found');
              }
              else {
                var fraudId = classifyFraudPkg(pkg);
                if (fraudId) writeReq(fraudId, name + '.' + m, pkg, 'present', null);
                else writeReq(m === 'getPackageInfo' ? 'install.package_info' : 'install.application_info', name + '.' + m, pkg + ' flags=' + flags, 'ok', null);
                if (m === 'getPackageInfo' && result && (pkg === TARGET_PKG || /SIGNING|signatures/i.test(flags))) {
                  try { writeOnce('install.first_install', name + '.PackageInfo.firstInstallTime', pkg, safeStr(result.firstInstallTime), null); } catch (e2) {}
                  try { writeOnce('install.last_update', name + '.PackageInfo.lastUpdateTime', pkg, safeStr(result.lastUpdateTime), null); } catch (e2) {}
                  try {
                    var sigs = result.signingInfo || result.signatures;
                    if (sigs) writeOnce('install.signing_cert', name + '.PackageInfo.signatures', pkg, 'present', null);
                  } catch (e2) {}
                }
              }
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
      try {
        PM.getInstallSourceInfo.overloads.forEach(function (overload) {
          overload.implementation = function () {
            var pkg = safeStr(arguments[0]);
            var result = overload.apply(this, arguments);
            var src = '';
            try {
              src = 'installing=' + result.getInstallingPackageName() +
                ' initiating=' + result.getInitiatingPackageName() +
                ' originating=' + result.getOriginatingPackageName();
            } catch (e) { src = safeStr(result); }
            writeReq('install.source', name + '.getInstallSourceInfo', pkg, src, null);
            return result;
          };
        });
      } catch (e) {}
      ['hasSystemFeature', 'getSystemAvailableFeatures'].forEach(function (m) {
        try {
          PM[m].overloads.forEach(function (overload) {
            overload.implementation = function () {
              var result = overload.apply(this, arguments);
              writeOnce('hw.features', name + '.' + m, safeStr(arguments[0]), safeStr(result), null);
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
      'sendExtraCommand', 'getGnssYearOfHardware', 'getGnssCapabilities',
      'getGnssHardwareModelName', 'registerAntennaInfoListener',
      'addTestProvider', 'setTestProviderLocation', 'setTestProviderEnabled',
      'addProximityAlert', 'getProviderProperties'
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
            var locId = 'location.gps';
            var argBlob = args.join(' ').toLowerCase();
            if (m === 'getCurrentLocation') locId = 'location.current';
            else if (m.indexOf('GnssMeasurement') >= 0 || m.indexOf('GnssNavigation') >= 0) locId = 'location.gnss_clock';
            else if (m.indexOf('Antenna') >= 0) locId = 'location.gnss_antenna';
            else if (m.indexOf('Gnss') === 0 || m.indexOf('getGnss') === 0) locId = 'location.gnss_caps';
            else if (m.indexOf('TestProvider') >= 0) locId = 'location.mock_test';
            else if (m === 'addProximityAlert') locId = 'location.proximity';
            else if (m === 'sendExtraCommand') locId = 'location.cmd';
            else if (m.indexOf('Nmea') >= 0) locId = 'location.gnss_nmea';
            else if (argBlob.indexOf('network') >= 0) locId = 'location.network';
            else if (argBlob.indexOf('passive') >= 0) locId = 'location.passive';
            else if (argBlob.indexOf('fused') >= 0) locId = 'location.fused';
            else if (m.indexOf('Provider') >= 0) locId = 'location.providers';
            writeEvent(locId, 'LocationManager.' + m, args.join(', '), response, 'ACCESS_FINE_LOCATION');
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
        inNativeHook++;
        try {
          this.key = Memory.readUtf8String(args[0]);
          this.valueBuf = args[1];
        } catch (e) {
          this.key = '';
        }
      },
      onLeave: function (retval) {
        try {
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
          writeEvent(mapPropertyToId(this.key), '__system_property_get', this.key, response, null, { async: true });
        } finally {
          inNativeHook--;
        }
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
    try {
      SM.getSensorList.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var r = overload.apply(this, arguments);
          writeOnce('hw.sensor_list', 'SensorManager.getSensorList', safeStr(arguments[0]), 'count=' + (r ? r.size() : 0), null);
          return r;
        };
      });
    } catch (e) {}
    try {
      SM.getDefaultSensor.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var r = overload.apply(this, arguments);
          writeOnce('hw.sensor_list', 'SensorManager.getDefaultSensor', safeStr(arguments[0]), safeStr(r), null);
          return r;
        };
      });
    } catch (e) {}
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
      WV.evaluateJavascript.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var script = safeStr(arguments[0]);
          var id = classifyBrowserJs(script) || 'net.webview';
          writeReq(id, 'WebView.evaluateJavascript', script.substring(0, 180), '', null);
          return overload.apply(this, arguments);
        };
      });
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
          inNativeHook++;
          try { this.host = Memory.readUtf8String(args[0]); } catch (e) { this.host = ''; }
        },
        onLeave: function () {
          try {
            if (this.host && looksSensitive(this.host)) {
              writeEvent('net.dns', 'getaddrinfo', this.host, '', null, { async: true });
            }
          } finally { inNativeHook--; }
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
          inNativeHook++;
          try {
            var name = Memory.readUtf8String(retval);
            if (name) writeEvent('net.sni', 'SSL_get_servername', name, '', null, { async: true });
          } catch (e) {}
          inNativeHook--;
        }
      });
    }
  } catch (e) {}
  try {
    var dlopen = Module.findExportByName(null, 'android_dlopen_ext') ||
      Module.findExportByName('libdl.so', 'dlopen');
    if (dlopen) {
      Interceptor.attach(dlopen, {
        onEnter: function (args) {
          inNativeHook++;
          try { this.path = Memory.readUtf8String(args[0]); } catch (e) { this.path = ''; }
        },
        onLeave: function () {
          try {
            if (this.path && /loc|gps|gnss|map|cronet|okhttp|mqtt/i.test(this.path)) {
              writeEvent('location.hal', 'dlopen', this.path, 'loaded', null, { async: true });
            }
            if (this.path && /magisk|zygisk|xposed|lsposed|frida|gadget|riru|substrate/i.test(this.path)) {
              writeRoot('root.maps', 'dlopen', this.path, 'loaded');
            }
          } finally { inNativeHook--; }
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
  writeEvent(id, action, req, resp, null, { async: true });
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
  if (/\/ksu|apatch/.test(s)) return 'root.ksu';
  return 'root.su';
}

function classifyFsPath(path) {
  var s = String(path || '').toLowerCase();
  if (!s) return '';
  if (s.indexOf('/sys/class/net/') >= 0 && s.indexOf('/address') >= 0) return 'wifi.sysfs_mac';
  if (s.indexOf('/sys/class/bluetooth') >= 0) return 'bt.sysfs_mac';
  if (s.indexOf('/sys/class/android_usb') >= 0 && s.indexOf('iserial') >= 0) return 'sys.usb_serial';
  if (s.indexOf('/sys/class/thermal') >= 0) return 'sys.thermal';
  if (s.indexOf('/sys/class/power_supply') >= 0) return 'hw.battery_capacity';
  if (s.indexOf('/sys/devices/system/cpu') >= 0 && s.indexOf('cpufreq') >= 0) return 'sys.cpu_freq';
  if (s.indexOf('/sys/devices/system/cpu') >= 0) return 'sys.cpu';
  if (s.indexOf('/sys/block') >= 0) return 'sys.block_cid';
  if (s.indexOf('/proc/cpuinfo') >= 0) return 'proc.cpuinfo';
  if (s.indexOf('/proc/meminfo') >= 0) return 'proc.meminfo';
  if (s.indexOf('/proc/version') >= 0) return 'proc.version';
  if (s.indexOf('boot_id') >= 0) return 'proc.boot_id';
  if (s.indexOf('/proc/self/auxv') >= 0) return 'proc.auxv';
  if (s.indexOf('/proc/uptime') >= 0) return 'proc.uptime';
  if (s.indexOf('/proc/stat') >= 0) return 'proc.stat';
  if (s.indexOf('/proc/self/mountinfo') >= 0) return 'proc.mountinfo';
  if (s.indexOf('/proc/mounts') >= 0 || s.indexOf('/proc/self/mounts') >= 0) return 'root.mounts';
  if (s.indexOf('/proc/net/arp') >= 0) return 'proc.net_arp';
  if (s.indexOf('/proc/net/route') >= 0) return 'net.route';
  if (s.indexOf('/dev/__properties') >= 0) return 'proc.properties';
  if (s.indexOf('/dev/gnss') >= 0 || s.indexOf('/dev/gps') >= 0) return 'location.hal';
  if (isRootPath(s) || isProcInjectPath(s)) return classifyPath(s);
  if (s.indexOf('/proc/') === 0 || s.indexOf('/sys/') === 0) return 'proc.properties';
  return '';
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

function classifyFraudPkg(pkg) {
  var n = String(pkg || '');
  if (/parallel|dualspace|dualaid|multiapp|da\.daagent|island|shelter|virtual\.app/i.test(n)) return 'fraud.dual_app';
  if (/fakegps|fake.?gps|gpsjoystick|lexa.fakegps|mocklocations/i.test(n)) return 'fraud.mock_apps';
  if (/torproject|wireguard|org\.outline|openvpn/i.test(n)) return 'fraud.vpn_apps';
  if (/autoclick|auto.?click|clicker/i.test(n)) return 'fraud.auto_click';
  return '';
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
          var id = classifyFsPath(path);
          if (id) writeRoot(id, 'File.' + m, path, safeStr(result));
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
        var id = classifyFsPath(path);
        if (id) writeRoot(id, 'FileInputStream', path, '');
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
        var id = classifyFsPath(path);
        if (id) writeRoot(id, 'RandomAccessFile', path, '');
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
        var id = classifyFsPath(path);
        if (id) writeRoot(id, 'Os.open', path, 'fd');
        return fd;
      };
    });
  } catch (e) {}
  try {
    var Os2 = Java.use('android.system.Os');
    ['access', 'stat', 'lstat', 'readlink'].forEach(function (m) {
      try {
        Os2[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var path = safeStr(arguments[0]);
            var result = overload.apply(this, arguments);
            var id = classifyFsPath(path);
            if (id) writeRoot(id, 'Os.' + m, path, safeStr(result));
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Files = Java.use('java.nio.file.Files');
    ['readAllBytes', 'readAllLines', 'newBufferedReader', 'newInputStream'].forEach(function (m) {
      try {
        Files[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var path = safeStr(arguments[0]);
            var id = classifyFsPath(path);
            if (id) writeRoot(id, 'Files.' + m, path, '');
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

var nativeFsHooked = false;

function hasZygiskFsHook() {
  try {
    var io = initNativeIo();
    if (!io) return false;
    var mode = Memory.allocUtf8String('r');
    var paths = [
      '/data/user/0/' + TARGET_PKG + '/cache/access_monitor_native_fs',
      '/data/data/' + TARGET_PKG + '/cache/access_monitor_native_fs'
    ];
    for (var i = 0; i < paths.length; i++) {
      var fp = io.fopen(Memory.allocUtf8String(paths[i]), mode);
      if (fp && !fp.isNull()) {
        io.fclose(fp);
        return true;
      }
    }
  } catch (e) {}
  return false;
}

function hookNativeRootAccess() {
  if (nativeFsHooked) return;
  nativeFsHooked = true;
  if (hasZygiskFsHook()) {
    hookNativeDlsymAndConnect();
    return;
  }
  hookAccessJsFallback();
  hookOpenatCFilter();
  hookNativeDlsymAndConnect();
}

function hookOpenatCFilter() {
  var reportPath = new NativeCallback(function (pathPtr) {
    inNativeHook++;
    try {
      var path = pathPtr.isNull() ? '' : pathPtr.readUtf8String();
      var id = classifyFsPath(path);
      if (id) writeRoot(id, 'native.openat', path, '');
    } catch (e) {
    } finally {
      inNativeHook--;
    }
  }, 'void', ['pointer']);

  try {
    var cm = new CModule([
      '#include <gum/guminterceptor.h>',
      'extern void report_path(const char *p);',
      'static int starts(const char *p, const char *pre) {',
      '  if (!p || !pre) return 0;',
      '  while (*pre) { if (*p++ != *pre++) return 0; }',
      '  return 1;',
      '}',
      'static int interesting(const char *p) {',
      '  int n;',
      '  const char *s;',
      '  if (!p || p[0] == 0) return 0;',
      '  if (p[0] == \'/\' && (',
      '      starts(p, "/proc/") || starts(p, "/sys/") ||',
      '      starts(p, "/dev/__properties") || starts(p, "/dev/qemu") ||',
      '      starts(p, "/dev/goldfish") || starts(p, "/dev/gnss") ||',
      '      starts(p, "/dev/gps") || starts(p, "/system/bin/su") ||',
      '      starts(p, "/system/xbin/su") || starts(p, "/sbin/su") ||',
      '      starts(p, "/su/bin/su") || starts(p, "/data/adb") ||',
      '      starts(p, "/sbin/.magisk") || starts(p, "/debug_ramdisk"))) return 1;',
      '  if (p[0] == \'s\' && p[1] == \'u\' && p[2] == 0) return 1;',
      '  n = 0; s = p; while (*s) { n++; s++; }',
      '  if (n >= 3 && p[n-3] == \'/\' && p[n-2] == \'s\' && p[n-1] == \'u\') return 1;',
      '  return 0;',
      '}',
      'void on_openat(GumInvocationContext *ic) {',
      '  const char *p = (const char *) gum_invocation_context_get_nth_argument(ic, 1);',
      '  if (interesting(p)) report_path(p);',
      '}'
    ].join('\n'), { report_path: reportPath });
    var addr = Module.findExportByName('libc.so', 'openat');
    if (addr) Interceptor.attach(addr, { onEnter: cm.on_openat });
  } catch (e) {}
}

function hookAccessJsFallback() {
  ['access', 'faccessat'].forEach(function (fn) {
    try {
      var addr = Module.findExportByName('libc.so', fn);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          inNativeHook++;
          var idx = fn === 'faccessat' ? 1 : 0;
          try { this.path = Memory.readUtf8String(args[idx]); } catch (e2) { this.path = ''; }
        },
        onLeave: function (retval) {
          try {
            var id = classifyFsPath(this.path);
            if (id) writeRoot(id, 'native.' + fn, this.path, 'rc=' + retval.toInt32());
          } finally { inNativeHook--; }
        }
      });
    } catch (e) {}
  });
}

function hookNativeDlsymAndConnect() {
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
  return;
  /* syscall interceptor on the hot path freezes some processes. */
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
        if (/READ_MEDIA_VISUAL_USER_SELECTED/i.test(perm)) {
          writeReq('hw.partial_media', 'checkSelfPermission', perm, safeStr(result), perm);
        } else if (/PHONE|SMS|CONTACTS|LOCATION|CAMERA|RECORD|STORAGE|AD_ID|ACCOUNTS|CALENDAR|CALL_LOG|BODY_SENSORS|NEARBY|BLUETOOTH|PACKAGE|READ_MEDIA/i.test(perm)) {
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
            var out = overload.apply(this, arguments);
            var w = 0, h = 0, dpi = 0;
            try {
              var arg0 = arguments[0];
              if (arg0) {
                w = arg0.widthPixels || arg0.x || 0;
                h = arg0.heightPixels || arg0.y || 0;
                dpi = arg0.densityDpi || 0;
              }
            } catch (e2) {}
            writeOnce(
              'display.metrics',
              'Display.' + m,
              'android.view.Display.' + m,
              'w=' + w + ' h=' + h + (dpi ? ' dpi=' + dpi : ''),
              null
            );
            return out;
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
      writeOnce(name === 0x1F02 ? 'hw.gles_version' : 'gpu.gl', 'GLES20.glGetString', '' + name, safeStr(r), null);
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
            var id = 'wifi.mac';
            if (m === 'getScanResults') id = 'wifi.scan_results';
            else if (m === 'getDhcpInfo') id = 'wifi.dhcp';
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

function summarizeResult(result) {
  if (result === null || result === undefined) return '(null)';
  try {
    if (result === true || result === false) return String(result);
    if (typeof result === 'number') return String(result);
    var s = safeStr(result);
    if (s && s !== 'undefined' && s.indexOf('@') < 0 && s !== '[object Object]') {
      return s.length > 200 ? s.substring(0, 200) + '…' : s;
    }
    try { if (result.size) return 'count=' + result.size(); } catch (e) {}
    try { if (result.length !== undefined && typeof result.length === 'number') return 'len=' + result.length; } catch (e) {}
    return s && s !== 'undefined' ? s.substring(0, 120) : '(объект)';
  } catch (e) {
    return '(ошибка чтения ответа)';
  }
}

function summarizeArgs(args) {
  var parts = [];
  var n = Math.min(args.length, 4);
  for (var i = 0; i < n; i++) {
    var s = safeStr(args[i]);
    if (s && s !== 'undefined') parts.push(s.substring(0, 80));
  }
  return parts.join(', ');
}

function hookAny(className, id, methods, perm) {
  try {
    var Cls = Java.use(className);
    methods.forEach(function (m) {
      try {
        Cls[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var result = overload.apply(this, arguments);
            writeReq(
              id,
              className.split('.').pop() + '.' + m,
              summarizeArgs(arguments) || (className.split('.').pop() + '.' + m),
              summarizeResult(result),
              perm || null
            );
            return result;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
}

function hookMissedRequestApis() {
  hookAny('android.telephony.euicc.EuiccManager', 'tel.eid', ['getEid', 'getOtaStatus'], 'READ_PRIVILEGED_PHONE_STATE');
  hookAny('android.telephony.CarrierConfigManager', 'tel.carrier_config', ['getConfigForSubId', 'getConfig'], null);
  hookAny('android.telecom.TelecomManager', 'tel.telecom', ['getLine1Number', 'getVoiceMailNumber', 'getCallCapablePhoneAccounts'], 'READ_PHONE_NUMBERS');
  hookAny('android.adservices.adid.AdIdManager', 'ad.adservices', ['getAdId'], 'ACCESS_ADSERVICES_AD_ID');
  hookAny('android.adservices.appsetid.AppSetIdManager', 'ad.app_set_id', ['getAppSetId'], null);
  hookAny('android.adservices.topics.TopicsManager', 'ad.topics', ['getTopics'], null);
  hookAny('android.adservices.measurement.MeasurementManager', 'ad.measurement', ['registerSource', 'registerTrigger', 'getMeasurementApiStatus'], null);
  hookAny('com.google.firebase.installations.FirebaseInstallations', 'ad.firebase_fid', ['getId', 'getToken'], null);
  hookAny('com.google.firebase.iid.FirebaseInstanceId', 'ad.instance_id', ['getId', 'getToken'], null);
  hookAny('com.google.android.gms.iid.InstanceID', 'ad.instance_id', ['getId', 'getToken'], null);
  hookAny('com.android.installreferrer.api.InstallReferrerClient', 'install.referrer', ['startConnection', 'getInstallReferrer'], null);
  hookAny('com.google.android.gms.auth.api.signin.GoogleSignIn', 'account.google', ['getLastSignedInAccount', 'getClient'], null);
  hookAny('com.google.android.gms.auth.api.signin.GoogleSignInAccount', 'account.google', ['getId', 'getIdToken', 'getEmail', 'getServerAuthCode'], null);
  hookAny('com.huawei.hms.ads.identifier.AdvertisingIdClient', 'oem.huawei_oaid', ['getAdvertisingIdInfo'], null);
  hookAny('com.bun.miitmdid.core.MdidSdkHelper', 'oem.oaid_msa', ['InitSdk', 'initSdk'], null);
  hookAny('com.android.id.impl.IdProviderImpl', 'oem.oaid_xiaomi', ['getOAID', 'getVAID', 'getAAID', 'getUDID'], null);
  hookAny('com.heytap.openid.sdk.OpenIDSDK', 'oem.oaid_oppo', ['getOpenId', 'getOAID'], null);
  hookAny('com.vivo.identifier.IdentifierManager', 'oem.oaid_vivo', ['getGuid', 'getOAID', 'getVAID', 'getAAID'], null);
  hookAny('com.samsung.android.telephony.SemTelephonyManager', 'oem.sem_tel', ['getImei', 'getMeid', 'getSubscriberId', 'semGetImei'], null);
  hookAny('com.samsung.android.knox.EnterpriseDeviceManager', 'oem.knox', ['getInstance', 'getVersion'], null);
  hookAny('android.hardware.usb.UsbDevice', 'hw.usb_serial', ['getSerialNumber', 'getDeviceName', 'getVendorId'], null);
  hookAny('android.view.InputDevice', 'hw.input', ['getDescriptor', 'getName', 'getVendorId'], null);
  try {
    var Res = Java.use('android.content.res.Resources');
    Res.getConfiguration.implementation = function () {
      var c = this.getConfiguration();
      try {
        writeOnce('hw.config', 'Resources.getConfiguration', '', 'mcc=' + c.mcc + ' mnc=' + c.mnc + ' locale=' + c.getLocales(), null);
      } catch (e) {}
      return c;
    };
  } catch (e) {}
  hookAny('android.os.storage.StorageManager', 'hw.storage_uuid', ['getStorageVolumes', 'getUuidForPath', 'getPrimaryStorageVolume'], null);
  hookAny('android.os.storage.StorageVolume', 'hw.storage_uuid', ['getUuid', 'getDirectory'], null);
  hookAny('android.app.ActivityManager', 'hw.memory', ['getMemoryInfo', 'getDeviceConfigurationInfo'], null);
  hookAny('android.os.PowerManager', 'hw.power', ['isPowerSaveMode', 'isDeviceIdleMode', 'isInteractive'], null);
  hookAny('android.media.AudioManager', 'hw.audio_dev', ['getDevices', 'getCommunicationDevice'], null);
  hookAny('android.net.ConnectivityManager', 'net.link_props', ['getLinkProperties', 'getActiveNetworkInfo'], null);
  hookAny('android.net.LinkProperties', 'net.link_props', ['getLinkAddresses', 'getDnsServers', 'getDomains'], null);
  hookAny('java.net.InetAddress', 'net.local', ['getLocalHost', 'getHostAddress', 'getCanonicalHostName'], null);
  hookAny('android.webkit.CookieManager', 'net.cookies', ['getCookie', 'setCookie'], null);
  hookAny('android.net.TrafficStats', 'net.traffic', ['getUidRxBytes', 'getUidTxBytes', 'getMobileRxBytes'], null);
  hookAny('android.net.nsd.NsdManager', 'net.nsd', ['discoverServices', 'registerService'], null);
  hookAny('android.net.wifi.p2p.WifiP2pManager', 'net.p2p', ['requestPeers', 'discoverPeers'], null);
  hookAny('android.net.wifi.aware.WifiAwareManager', 'net.aware', ['attach', 'isAvailable'], null);
  hookAny('android.app.usage.NetworkStatsManager', 'net.netstats', ['querySummary', 'queryDetails'], null);
  hookAny('android.bluetooth.BluetoothAdapter', 'bt.bonded', ['getBondedDevices'], 'BLUETOOTH_CONNECT');
  hookAny('com.google.android.gms.fido.Fido', 'fido.fido2', ['getFido2ApiClient', 'getFido2PrivilegedApiClient'], null);
  hookAny('androidx.health.connect.client.HealthConnectClient', 'health.connect', ['getOrCreate', 'insertRecords', 'readRecords'], null);
  hookAny('android.health.connect.HealthConnectManager', 'health.connect', ['getChangeLogs', 'aggregate'], null);
  hookAny('com.google.android.gms.games.PlayersClient', 'games.player', ['getCurrentPlayer', 'getCurrentPlayerId'], null);
  hookAny('com.google.android.recaptcha.Recaptcha', 'play.recaptcha_ent', ['getClient', 'fetchClient'], null);
  hookAny('android.view.autofill.AutofillManager', 'autofill', ['requestAutofill', 'isEnabled'], null);
  hookAny('android.app.role.RoleManager', 'role.sms', ['isRoleHeld', 'isRoleAvailable'], null);
  hookAny('android.telephony.SmsManager', 'role.sms', ['getDefaultSmsSubscriptionId'], null);
  hookAny('android.security.KeyChain', 'keychain', ['getCertificateChain', 'getPrivateKey', 'choosePrivateKeyAlias'], null);
  hookAny('com.google.android.gms.common.GoogleApiAvailability', 'gms.availability', ['isGooglePlayServicesAvailable', 'getApkVersion'], null);
  hookAny('com.google.android.gms.location.SettingsClient', 'location.settings', ['checkLocationSettings'], null);
  hookAny('android.location.Geocoder', 'location.geocoder', ['getFromLocation', 'getFromLocationName'], null);
  hookAny('android.companion.CompanionDeviceManager', 'companion', ['associate', 'getAssociations'], null);
  hookAny('android.content.pm.LauncherApps', 'launcher.apps', ['getActivityList', 'getProfiles'], null);
  hookAny('android.app.NotificationManager', 'notify.enabled', ['areNotificationsEnabled', 'getActiveNotifications'], null);
  hookAny('android.app.DownloadManager', 'download.manager', ['enqueue', 'query'], null);
  hookAny('android.os.UserManager', 'user.serial', ['getSerialNumberForUser', 'getUserName'], null);
  hookAny('android.app.admin.DevicePolicyManager', 'dpm.owner', ['isDeviceOwnerApp', 'isProfileOwnerApp', 'isAdminActive'], null);
  hookAny('android.app.admin.DevicePolicyManager', 'ent.esid', ['getEnrollmentSpecificId'], null);
  hookAny('android.app.admin.DevicePolicyManager', 'ent.org_id', ['setOrganizationId', 'getEnrollmentSpecificId'], null);
  hookAny('android.telephony.CellIdentityLte', 'cell.identity', ['getMccString', 'getMncString', 'getCi', 'getTac', 'getEarfcn'], null);
  hookAny('android.telephony.CellIdentityNr', 'cell.identity', ['getMccString', 'getMncString', 'getNci', 'getTac', 'getNrarfcn'], null);
  hookAny('android.telephony.CellIdentityGsm', 'cell.identity', ['getMccString', 'getMncString', 'getCid', 'getLac'], null);
  try {
    var KS = Java.use('java.security.KeyStore');
    KS.getInstance.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var type = safeStr(arguments[0]);
        var result = overload.apply(this, arguments);
        if (/AndroidKeyStore|BKS|PKCS/i.test(type)) writeReq('keystore.aliases', 'KeyStore.getInstance', type, '', null);
        return result;
      };
    });
  } catch (e) {}
  try {
    var KS = Java.use('java.security.KeyStore');
    KS.aliases.implementation = function () {
      var r = this.aliases();
      writeReq('keystore.aliases', 'KeyStore.aliases', '', 'enum', null);
      return r;
    };
  } catch (e) {}
  try {
    var NI = Java.use('java.net.NetworkInterface');
    var orig = NI.getNetworkInterfaces;
    orig.implementation = function () {
      var r = orig.call(this);
      writeOnce('net.interfaces', 'NetworkInterface.getNetworkInterfaces', '', 'listed', null);
      return r;
    };
  } catch (e) {}
  try {
    var Sms = Java.use('android.provider.Telephony$Sms');
    Sms.getDefaultSmsPackage.implementation = function (ctx) {
      var r = this.getDefaultSmsPackage(ctx);
      writeReq('role.sms', 'Telephony.Sms.getDefaultSmsPackage', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var Os = Java.use('android.system.Os');
    Os.uname.implementation = function () {
      var r = this.uname();
      writeOnce(
        'kernel.version',
        'Os.uname',
        'android.system.Os.uname()',
        safeStr(r.sysname) + ' ' + safeStr(r.machine) + ' ' + safeStr(r.release),
        null
      );
      return r;
    };
  } catch (e) {}
  try {
    var RT = Java.use('java.lang.Runtime');
    RT.availableProcessors.implementation = function () {
      var n = this.availableProcessors();
      writeOnce('hw.cores', 'Runtime.availableProcessors', 'Runtime.availableProcessors()', String(n), null);
      return n;
    };
  } catch (e) {}
}

function hookFraudFingerprint() {
  hookAny('android.app.KeyguardManager', 'hw.pin_lock', ['isDeviceSecure', 'isKeyguardSecure', 'isKeyguardLocked'], null);
  hookAny('android.hardware.biometrics.BiometricManager', 'hw.fp_enrolled', ['canAuthenticate'], null);
  hookAny('android.hardware.fingerprint.FingerprintManager', 'hw.fp_enrolled', ['hasEnrolledFingerprints', 'isHardwareDetected'], null);
  hookAny('android.media.MediaCodecList', 'hw.codec_list', ['getCodecInfos', 'getCodecCount'], null);
  hookAny('android.media.RingtoneManager', 'hw.ringtone', ['getActualDefaultRingtoneUri', 'getDefaultUri'], null);
  hookAny('android.app.UiModeManager', 'hw.dark_mode', ['getNightMode', 'getCurrentModeType'], null);
  hookAny('android.webkit.WebView', 'hw.webview_pkg', ['getCurrentWebViewPackage'], null);
  hookAny('android.net.wifi.WifiManager', 'fraud.wifi_on', ['isWifiEnabled'], null);
  hookAny('android.net.wifi.WifiManager', 'wifi.dhcp', ['getDhcpInfo'], null);
  hookAny('android.bluetooth.BluetoothAdapter', 'fraud.bt_on', ['isEnabled'], null);
  hookAny('android.location.LocationManager', 'fraud.location_on', ['isLocationEnabled', 'isProviderEnabled'], null);
  hookAny('android.hardware.display.DisplayManager', 'fraud.cast', ['getDisplays'], null);
  hookAny('android.media.MediaRouter', 'fraud.cast', ['getSelectedRoute', 'getRouteCount'], null);
  hookAny('android.view.accessibility.AccessibilityManager', 'fraud.talkback', ['isTouchExplorationEnabled', 'getEnabledAccessibilityServiceList', 'isEnabled'], null);
  hookAny('android.os.UserManager', 'fraud.work_profile', ['isManagedProfile', 'getUserProfiles', 'isSystemUser', 'getUserCount'], null);
  hookAny('android.app.admin.DevicePolicyManager', 'hw.encryption', ['getStorageEncryptionStatus'], null);
  hookAny('android.net.ConnectivityManager', 'net.capabilities', ['getNetworkCapabilities', 'getActiveNetwork'], null);
  hookAny('org.webrtc.PeerConnectionFactory', 'net.stun', ['initialize', 'createPeerConnection'], null);
  hookAny('org.webrtc.PeerConnection', 'net.stun', ['createOffer', 'addIceCandidate'], null);
  try {
    var Clock = Java.use('android.os.SystemClock');
    ['elapsedRealtime', 'uptimeMillis', 'elapsedRealtimeNanos'].forEach(function (m) {
      try {
        Clock[m].implementation = function () {
          var r = this[m]();
          writeOnce(m.indexOf('Nano') >= 0 ? 'fraud.elapsed' : 'hw.uptime', 'SystemClock.' + m, '', safeStr(r), null);
          return r;
        };
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var RT = Java.use('java.lang.Runtime');
    RT.availableProcessors.implementation = function () {
      var r = this.availableProcessors();
      writeOnce('hw.cores', 'Runtime.availableProcessors', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var Sec = Java.use('java.security.Security');
    var orig = Sec.getProviders.overload();
    orig.implementation = function () {
      var r = orig.call(this);
      writeOnce('hw.security_providers', 'Security.getProviders', '', 'count=' + (r ? r.length : 0), null);
      return r;
    };
  } catch (e) {}
  try {
    var Loc = Java.use('java.util.Locale');
    Loc.getAvailableLocales.implementation = function () {
      var r = this.getAvailableLocales();
      writeOnce('hw.locales', 'Locale.getAvailableLocales', '', 'count=' + (r ? r.length : 0), null);
      return r;
    };
  } catch (e) {}
  try {
    var AM = Java.use('android.media.AudioManager');
    AM.getRingerMode.implementation = function () {
      var r = this.getRingerMode();
      writeOnce('hw.ringer', 'AudioManager.getRingerMode', '', safeStr(r), null);
      return r;
    };
  } catch (e) {}
  try {
    var Ctx = Java.use('android.app.ContextImpl');
    ['getFilesDir', 'getDataDir', 'getExternalFilesDir'].forEach(function (m) {
      try {
        Ctx[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            var path = safeStr(r);
            if (/\/data\/user\/(999|10|11)\//.test(path) || path.indexOf('parallel') >= 0) {
              writeReq('fraud.clone', 'Context.' + m, path, 'clone-user', null);
            } else {
              writeOnce('fraud.clone', 'Context.' + m, path, '', null);
            }
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var View = Java.use('android.view.View');
    View.dispatchTouchEvent.implementation = function (ev) {
      writeOnce('fraud.touch', 'View.dispatchTouchEvent', '', 'touch', null);
      return this.dispatchTouchEvent(ev);
    };
  } catch (e) {}
  try {
    var AM2 = Java.use('android.app.ActivityManager');
    AM2.getDeviceConfigurationInfo.implementation = function () {
      var r = this.getDeviceConfigurationInfo();
      try { writeOnce('hw.gles_version', 'getDeviceConfigurationInfo', '', 'gles=0x' + r.reqGlEsVersion.toString(16), null); } catch (e) {}
      return r;
    };
  } catch (e) {}
}

function hookFraudSdks() {
  hookAny('com.threatmetrix.TrustDefender.TMXProfiling', 'fraud.tmx', ['profile', 'init', 'getInstance'], null);
  hookAny('com.lexisnexis.tmsdk.TMXProfiling', 'fraud.tmx', ['profile', 'init', 'getInstance'], null);
  hookAny('com.threatmetrix.TrustDefender.TrustDefender', 'fraud.tmx', ['doProfileRequest', 'profile', 'init'], null);
  hookAny('com.trustdecision.android.sdk.TDRisk', 'fraud.trustdecision', ['initWithOptions', 'getBlackBox', 'getDeviceId'], null);
  hookAny('com.trustdecision.mobrisk.TDRisk', 'fraud.trustdecision', ['initWithOptions', 'getBlackBox'], null);
  hookAny('cn.tongdun.android.shell.FMAgent', 'fraud.trustdecision', ['init', 'onEvent', 'getDeviceInfo'], null);
  hookAny('com.fingerprintjs.android.fingerprint.Fingerprinter', 'fraud.fingerprintjs', ['getFingerprint', 'getDeviceId'], null);
  hookAny('com.fingerprint.android.Fingerprint', 'fraud.fingerprintjs', ['getVisitorId', 'request'], null);
  hookAny('io.seon.androidsdk.service.SeonBuilder', 'fraud.seon', ['build', 'withSessionId'], null);
  hookAny('io.seon.androidsdk.Seon', 'fraud.seon', ['getFingerprintBase64', 'start'], null);
  hookAny('siftscience.android.Sift', 'fraud.sift', ['open', 'collect', 'setUserId'], null);
  hookAny('com.forter.mobile.ForterMobile', 'fraud.forter', ['init', 'trackAction', 'getDeviceUID'], null);
  hookAny('com.iovation.mobile.android.FraudForceManager', 'fraud.iovation', ['refresh', 'getBlackbox'], null);
  hookAny('com.kount.api.KountSDK', 'fraud.kount', ['collectDeviceData', 'getSessionID'], null);
  hookAny('com.group_ib.sdk.MobileSdk', 'fraud.groupib', ['init', 'getDeviceId', 'run'], null);
  hookAny('com.ishumei.smantifraud.SmAntiFraud', 'fraud.shumeng', ['create', 'getDeviceId'], null);
  hookAny('com.appsflyer.AppsFlyerLib', 'fraud.appsflyer', ['init', 'start', 'getAppsFlyerUID'], null);
  hookAny('com.adjust.sdk.Adjust', 'fraud.adjust', ['getAdid', 'getGoogleAdId', 'onCreate'], null);
  hookAny('com.incognia.Incognia', 'fraud.incognia', ['init', 'setAccountId'], null);
  hookAny('com.biocatch.client.android.sdk.BioCatch', 'fraud.biocatch', ['start', 'changeContext'], null);
  hookAny('com.sumsub.sns.core.SNSMobileSDK', 'fraud.sumsub', ['init', 'launch'], null);
}

function hookMissedSurface() {
  hookAny('android.location.LocationManager', 'location.gnss_antenna', ['registerAntennaInfoListener', 'unregisterAntennaInfoListener'], 'ACCESS_FINE_LOCATION');
  hookAny('android.location.Location', 'location.altitude', ['getMslAltitudeMeters', 'hasMslAltitude'], null);
  hookAny('android.location.Location', 'location.extras', ['getExtras', 'getElapsedRealtimeNanos'], null);
  hookAny('com.google.android.gms.awareness.Awareness', 'location.awareness', ['getSnapshotClient', 'getFenceClient'], null);
  hookAny('com.google.android.libraries.places.api.Places', 'location.places', ['createClient', 'initialize'], null);
  hookAny('com.google.android.libraries.places.api.net.PlacesClient', 'location.places', ['findCurrentPlace', 'fetchPlace'], null);
  hookAny('com.google.android.gms.location.FusedOrientationProviderClient', 'location.orientation', ['requestOrientationUpdates'], null);
  hookAny('com.google.android.gms.location.ActivityRecognitionClient', 'location.transition', ['requestActivityTransitionUpdates', 'requestSleepSegmentUpdates'], null);
  hookAny('android.hardware.SensorManager', 'sensor.direct', ['createDirectChannel'], null);
  hookAny('android.hardware.SensorManager', 'sensor.trigger', ['requestTriggerSensor', 'cancelTriggerSensor'], null);
  hookAny('android.hardware.SensorManager', 'sensor.dynamic', ['registerDynamicSensorCallback', 'getDynamicSensorList'], null);
  hookAny('android.hardware.SensorPrivacyManager', 'sensor.privacy', ['areAnySensorPrivacyTogglesEnabled', 'isSensorPrivacyEnabled'], null);
  hookAny('android.hardware.SensorEventCallback', 'sensor.additional', ['onSensorAdditionalInfo', 'onFlushCompleted'], null);
  hookAny('android.hardware.GeomagneticField', 'sensor.geomagnetic', ['getDeclination', 'getFieldStrength'], null);
  hookAny('android.telephony.TelephonyManager', 'tel.signal', ['getSignalStrength'], null);
  hookAny('android.telephony.TelephonyManager', 'tel.emergency', ['getEmergencyNumberList'], null);
  hookAny('android.telephony.TelephonyManager', 'tel.uicc', ['getUiccCardsInfo'], null);
  hookAny('android.telephony.TelephonyManager', 'tel.barring', ['getBarringInfo'], null);
  hookAny('android.telephony.satellite.SatelliteManager', 'tel.satellite', ['requestSatelliteEnabled', 'requestIsSatelliteEnabled'], null);
  hookAny('android.se.omapi.SEService', 'tel.omapi', ['getReaders', 'isConnected'], null);
  hookAny('org.simalliance.openmobileapi.SEService', 'tel.omapi', ['getReaders'], null);
  hookAny('com.google.android.gms.nearby.Nearby', 'nearby.connections', ['getConnectionsClient', 'getMessagesClient'], null);
  hookAny('android.bluetooth.le.BluetoothLeAdvertiser', 'bt.advertise', ['startAdvertising', 'startAdvertisingSet'], null);
  hookAny('android.bluetooth.BluetoothDevice', 'bt.gatt', ['connectGatt'], 'BLUETOOTH_CONNECT');
  hookAny('android.net.wifi.WifiManager', 'wifi.softap', ['startLocalOnlyHotspot'], null);
  hookAny('android.net.wifi.WifiManager', 'wifi.suggestion', ['addNetworkSuggestions'], null);
  hookAny('android.net.wifi.WifiInfo', 'wifi.standard', ['getWifiStandard', 'getFrequency'], null);
  hookAny('android.net.wifi.WifiInfo', 'wifi.randomized_mac', ['getRandomizedMacAddress'], null);
  hookAny('android.view.Display', 'hw.refresh', ['getRefreshRate', 'getMode', 'getSupportedModes'], null);
  hookAny('android.view.Display', 'hw.hdr', ['getHdrCapabilities', 'isHdr'], null);
  hookAny('android.os.PowerManager', 'hw.thermal', ['getCurrentThermalStatus'], null);
  hookAny('android.hardware.devicestate.DeviceStateManager', 'hw.fold', ['registerCallback', 'getCurrentState'], null);
  hookAny('android.app.WallpaperManager', 'hw.wallpaper', ['getWallpaperColors', 'getDrawable'], null);
  hookAny('android.hardware.camera2.CameraManager', 'hw.camera_chars', ['getCameraCharacteristics'], null);
  hookAny('android.media.midi.MidiManager', 'hw.midi', ['getDevices'], null);
  hookAny('android.hardware.ConsumerIrManager', 'hw.ir', ['hasIrEmitter', 'transmit'], null);
  hookAny('android.os.Vibrator', 'hw.vibrator', ['getId', 'getQFactor', 'getResonantFrequency'], null);
  hookAny('android.speech.tts.TextToSpeech', 'hw.tts', ['getEngines', 'getVoices'], null);
  hookAny('android.speech.SpeechRecognizer', 'hw.speech_rec', ['startListening', 'createSpeechRecognizer'], null);
  hookAny('android.media.ExifInterface', 'hw.exif', ['getLatLong', 'getAttribute'], null);
  hookAny('androidx.exifinterface.media.ExifInterface', 'hw.exif', ['getLatLong', 'getAttribute'], null);
  hookAny('android.security.identity.IdentityCredentialStore', 'identity.mdoc', ['getInstance', 'createPresentationSession'], null);
  hookAny('com.google.firebase.appcheck.FirebaseAppCheck', 'play.app_check', ['getAppCheckToken', 'getToken'], null);
  hookAny('android.app.role.RoleManager', 'role.browser', ['isRoleHeld'], null);
  hookAny('com.google.firebase.analytics.FirebaseAnalytics', 'ad.app_instance', ['getAppInstanceId'], null);
  hookAny('io.appmetrica.analytics.AppMetrica', 'ad.metrica', ['getDeviceId', 'activate'], null);
  try {
    var SM = Java.use('android.hardware.SensorManager');
    SM.getDefaultSensor.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var r = overload.apply(this, arguments);
        var t = safeStr(arguments[0]);
        var id = 'hw.sensor_list';
        if (t === '19' || t === '18') id = 'sensor.step';
        else if (t === '21' || t === '31') id = 'sensor.heart';
        else if (t === '6') id = 'sensor.pressure';
        else if (t === '5') id = 'sensor.light';
        else if (t === '8') id = 'sensor.proximity';
        else if (t === '36') id = 'sensor.hinge';
        else if (t === '37') id = 'sensor.head_tracker';
        else if (t === '17') id = 'sensor.significant';
        else if (t === '34') id = 'sensor.offbody';
        else if (t === '42') id = 'sensor.heading';
        else if (t === '14' || t === '16' || t === '35' || t === '40' || t === '41') id = 'sensor.uncalibrated';
        writeOnce(id, 'SensorManager.getDefaultSensor', t, safeStr(r), null);
        return r;
      };
    });
  } catch (e) {}
}

function hookBrowserApis() {
  hookAny('android.webkit.WebView', 'browser.js_interface', ['addJavascriptInterface', 'removeJavascriptInterface'], null);
  hookAny('android.webkit.WebView', 'browser.debug', ['setWebContentsDebuggingEnabled'], null);
  hookAny('android.webkit.WebView', 'browser.safe_browsing', ['startSafeBrowsing', 'setSafeBrowsingWhitelist'], null);
  hookAny('android.webkit.WebView', 'browser.multiprocess', ['isMultiProcessEnabled', 'getWebViewClassLoader'], null);
  hookAny('android.webkit.WebView', 'hw.webview_pkg', ['getCurrentWebViewPackage'], null);
  hookAny('android.webkit.WebView', 'browser.web_message', ['postWebMessage', 'createWebMessageChannel'], null);
  hookAny('android.webkit.WebSettings', 'browser.default_ua', ['getDefaultUserAgent', 'setUserAgentString'], null);
  hookAny('android.webkit.WebSettings', 'browser.dom_storage', ['setDomStorageEnabled', 'getDomStorageEnabled', 'setDatabaseEnabled'], null);
  hookAny('android.webkit.WebSettings', 'browser.geolocation_js', ['setGeolocationEnabled', 'getGeolocationEnabled'], null);
  hookAny('android.webkit.WebSettings', 'browser.fonts_css', ['getStandardFontFamily', 'getFixedFontFamily', 'getSansSerifFontFamily', 'getSerifFontFamily', 'getCursiveFontFamily'], null);
  hookAny('android.webkit.CookieManager', 'browser.cookie_3p', ['setAcceptThirdPartyCookies', 'acceptThirdPartyCookies', 'setAcceptCookie'], null);
  hookAny('android.webkit.WebStorage', 'browser.web_storage', ['getOrigins', 'deleteAllData', 'deleteOrigin'], null);
  hookAny('android.webkit.WebViewDatabase', 'browser.web_db', ['getInstance', 'clearHttpAuthUsernamePassword', 'clearFormData'], null);
  hookAny('android.webkit.ServiceWorkerController', 'browser.service_worker', ['getInstance', 'setServiceWorkerClient'], null);
  hookAny('android.webkit.PermissionRequest', 'browser.permission_req', ['grant', 'deny', 'getResources'], null);
  hookAny('android.webkit.WebChromeClient', 'browser.permission_req', ['onPermissionRequest', 'onGeolocationPermissionsShowPrompt', 'onShowFileChooser'], null);
  hookAny('android.webkit.WebViewClient', 'browser.intercept', ['shouldInterceptRequest', 'onReceivedSslError', 'onReceivedClientCertRequest', 'onReceivedHttpAuthRequest'], null);
  hookAny('androidx.webkit.WebSettingsCompat', 'browser.ua_meta', ['setUserAgentMetadata', 'getUserAgentMetadata'], null);
  hookAny('androidx.webkit.WebSettingsCompat', 'browser.safe_browsing', ['setSafeBrowsingEnabled', 'getSafeBrowsingEnabled'], null);
  hookAny('androidx.webkit.WebSettingsCompat', 'browser.dark', ['setForceDark', 'setAlgorithmicDarkeningAllowed'], null);
  hookAny('androidx.webkit.WebViewCompat', 'browser.web_message', ['addWebMessageListener', 'postWebMessage', 'createWebMessageChannel'], null);
  hookAny('androidx.webkit.WebViewCompat', 'browser.variations', ['getVariationsHeader'], null);
  hookAny('androidx.webkit.WebViewCompat', 'browser.safe_browsing', ['startSafeBrowsing', 'getSafeBrowsingPrivacyPolicyUrl', 'setSafeBrowsingAllowlist'], null);
  hookAny('androidx.webkit.WebViewFeature', 'browser.feature', ['isFeatureSupported'], null);
  hookAny('androidx.webkit.ProxyController', 'browser.proxy', ['setProxyOverride', 'clearProxyOverride'], null);
  hookAny('androidx.webkit.ProfileStore', 'browser.profile', ['getOrCreateProfile', 'getProfile'], null);
  hookAny('androidx.browser.customtabs.CustomTabsClient', 'browser.custom_tabs', ['bindCustomTabsService', 'newSession', 'connectAndInitialize'], null);
  hookAny('androidx.browser.customtabs.CustomTabsIntent$Builder', 'browser.custom_tabs', ['build', 'setSession'], null);
  hookAny('androidx.browser.trusted.TrustedWebUtils', 'browser.twa', ['launchAsTrustedWebActivity'], null);
  hookAny('androidx.browser.trusted.TwaLauncher', 'browser.twa', ['launch'], null);
  hookAny('org.mozilla.geckoview.GeckoRuntime', 'browser.geckoview', ['create', 'getDefault'], null);
  hookAny('org.mozilla.geckoview.GeckoSession', 'browser.geckoview', ['loadUri', 'open'], null);
  hookAny('org.chromium.android_webview.AwSettings', 'browser.chromium_aw', ['setUserAgentString', 'getUserAgentMetadata', 'setSafeBrowsingEnabled'], null);
  try {
    var PR = Java.use('android.webkit.PermissionRequest');
    PR.grant.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var res = safeStr(arguments[0]);
        var id = /PROTECTED_MEDIA|MEDIA_ID/i.test(res) ? 'browser.eme' : 'browser.permission_req';
        writeReq(id, 'PermissionRequest.grant', res, 'granted', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Ctx = Java.use('android.app.ContextImpl');
    Ctx.startActivity.overloads.forEach(function (overload) {
      overload.implementation = function () {
        try {
          var intent = arguments[0];
          var action = intent.getAction();
          var data = '';
          try { data = safeStr(intent.getDataString()); } catch (e2) {}
          if (action === 'android.intent.action.VIEW' && /^https?:/i.test(data)) {
            writeReq('browser.intent', 'Context.startActivity(VIEW)', data.substring(0, 180), '', null);
          }
          if ('' + intent.getComponent() && /customtabs|trustedweb/i.test('' + intent.getComponent())) {
            writeReq('browser.custom_tabs', 'startActivity', safeStr(intent.getComponent()), data.substring(0, 120), null);
          }
          if (action === 'android.intent.action.OPEN_DOCUMENT' ||
              action === 'android.intent.action.OPEN_DOCUMENT_TREE' ||
              action === 'android.intent.action.GET_CONTENT') {
            writeReq('hw.saf', 'Context.startActivity', safeStr(action), safeStr(intent.getType()), null);
          }
          if (action === 'android.provider.action.PICK_IMAGES' ||
              /PickVisualMedia|PICK_IMAGES/i.test(safeStr(intent.getComponent()))) {
            writeReq('photo.picker', 'Context.startActivity', safeStr(action), '', null);
          }
        } catch (e) {}
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var Headers = Java.use('okhttp3.Headers');
    var origGet = Headers.get;
    origGet.implementation = function (name) {
      var r = origGet.call(this, name);
      var n = safeStr(name);
      if (/^sec-ch-ua/i.test(n)) writeOnce('browser.ch_ua', 'OkHttp Headers.get', n, safeStr(r), null);
      if (/^x-requested-with$/i.test(n)) writeOnce('browser.xrw', 'OkHttp Headers.get', n, safeStr(r), null);
      if (/^x-client-data$/i.test(n)) writeOnce('browser.variations', 'OkHttp Headers.get', n, safeStr(r), null);
      return r;
    };
  } catch (e) {}
}

function classifyRoleName(role) {
  var s = String(role || '');
  if (/SMS/i.test(s)) return 'role.sms';
  if (/BROWSER/i.test(s)) return 'role.browser';
  if (/DIALER/i.test(s)) return 'role.dialer';
  if (/HOME/i.test(s)) return 'role.home';
  return 'role.sms';
}

function hookCatalogCompleteness() {
  hookAny('android.drm.DrmManagerClient', 'drm.legacy', ['getUniqueId', 'acquireDrmInfo'], null);
  hookAny('android.security.keystore.KeyInfo', 'attest.strongbox', ['isInsideSecureHardware', 'isUserAuthenticationRequired'], null);
  hookAny('android.security.keystore.KeyGenParameterSpec$Builder', 'attest.device_id', ['setDevicePropertiesAttestationIncluded', 'setAttestationChallenge'], null);
  hookAny('android.view.Display', 'hw.cutout', ['getCutout'], null);
  hookAny('android.view.WindowInsets', 'hw.cutout', ['getDisplayCutout'], null);
  hookAny('android.view.accessibility.CaptioningManager', 'hw.captioning', ['getLocale', 'getFontScale', 'isEnabled'], null);
  hookAny('android.app.GameManager', 'hw.game_mode', ['getGameMode'], null);
  hookAny('android.os.PerformanceHintManager', 'hw.adpf', ['createHintSession'], null);
  hookAny('android.view.translation.TranslationManager', 'hw.translation', ['createOnDeviceTranslator', 'getOnDeviceTranslationCapabilities'], null);
  hookAny('android.view.textclassifier.TextClassificationManager', 'hw.textclass', ['getTextClassifier'], null);
  hookAny('android.media.AudioManager', 'hw.spatializer', ['getSpatializer'], null);
  hookAny('android.app.ActivityManager', 'hw.start_info', ['getHistoricalProcessStartReasons'], null);
  hookAny('android.os.UserManager', 'hw.private_space', ['isPrivateProfile', 'getUserProfiles'], null);
  hookAny('android.provider.DocumentsContract', 'hw.saf', ['buildDocumentUri', 'isDocumentUri'], null);
  hookAny('androidx.activity.result.contract.ActivityResultContracts$PickVisualMedia', 'photo.picker', ['createIntent'], null);
  hookAny('android.media.AudioDeviceInfo', 'bt.audio_device_mac', ['getAddress', 'getProductName', 'getType'], null);
  hookAny('org.altbeacon.beacon.BeaconParser', 'bt.beacon', ['setBeaconLayout', 'addExtraDataParser'], null);
  hookAny('org.altbeacon.beacon.BeaconManager', 'bt.beacon', ['startRangingBeacons', 'startMonitoring'], null);
  hookAny('android.telephony.TelephonyManager', 'tel.physical_channel', ['getPhysicalChannelConfigList'], null);
  hookAny('android.telephony.TelephonyManager', 'tel.display_info', ['getTelephonyDisplayInfo'], null);
  hookAny('android.telephony.ims.ImsMmTelManager', 'tel.ims', ['isAvailable', 'isVoNrAvailable', 'isWifiCallingAvailable', 'isTtySupported'], null);
  hookAny('android.telecom.TelecomManager', 'tel.phone_account', ['getCallCapablePhoneAccounts', 'getDefaultOutgoingPhoneAccount', 'getPhoneAccountsSupportingScheme'], 'READ_PHONE_NUMBERS');
  hookAny('android.telecom.CallScreeningService', 'call.screening', ['onScreenCall', 'respondToCall'], null);
  hookAny('android.uwb.UwbManager', 'location.uwb', ['openRangingSession', 'getTimestampInformation'], null);
  hookAny('com.google.android.gms.nearby.Nearby', 'nearby.messages', ['getMessagesClient'], null);
  hookAny('com.google.android.gms.nearby.sharing.Sharing', 'nearby.share', ['getClient'], null);
  hookAny('com.google.android.gms.nearby.fastpair.FastPair', 'nearby.fastpair', ['getClient'], null);
  hookAny('okhttp3.OkHttpClient', 'net.websocket', ['newWebSocket'], null);
  hookAny('okhttp3.internal.ws.RealWebSocket', 'net.websocket', ['connect', 'send'], null);
  hookAny('org.chromium.net.CronetEngine$Builder', 'net.quic', ['enableQuic', 'addQuicHint'], null);
  hookAny('com.amplitude.api.Amplitude', 'ad.amplitude', ['getDeviceId', 'setDeviceId', 'getInstance'], null);
  hookAny('com.amplitude.android.Amplitude', 'ad.amplitude', ['getDeviceId'], null);
  hookAny('com.mixpanel.android.mpmetrics.MixpanelAPI', 'ad.amplitude', ['getDistinctId', 'getDeviceId'], null);
  hookAny('com.google.ccc.abuse.droidguard.DroidGuard', 'droidguard', ['init', 'ss', 'close'], null);
  hookAny('com.kaspersky.kfp.KFPSdk', 'fraud.kfp', ['init', 'getDeviceId'], null);
  hookAny('com.google.android.gms.wallet.Pay', 'identity.wallet', ['getClient'], null);
  hookAny('com.google.android.gms.wallet.Wallet', 'identity.wallet', ['getPaymentsClient', 'getWalletObjectsClient'], null);
  hookAny('com.google.android.gms.safetynet.SafetyNetClient', 'play.protect', ['enableVerifyApps', 'isVerifyAppsEnabled', 'listHarmfulApps'], null);
  hookAny('android.net.ConnectivityManager', 'net.captive', ['getCaptivePortalServerUrl'], null);
  hookAny('android.net.wifi.WifiManager', 'oem.vivo_wifi', ['getExtWifiScanResults'], null);
  try {
    var Role = Java.use('android.app.role.RoleManager');
    ['isRoleHeld', 'isRoleAvailable'].forEach(function (m) {
      try {
        Role[m].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var role = safeStr(arguments[0]);
            var r = overload.apply(this, arguments);
            writeReq(classifyRoleName(role), 'RoleManager.' + m, role, safeStr(r), null);
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Xiaomi = Java.use('com.android.id.impl.IdProviderImpl');
    [['getOAID', 'ad.oaid'], ['getVAID', 'ad.vaid'], ['getAAID', 'ad.aaid'], ['getUDID', 'ad.udid']].forEach(function (pair) {
      try {
        Xiaomi[pair[0]].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            writeReq(pair[1], 'IdProviderImpl.' + pair[0], '', safeStr(r), null);
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var Vivo = Java.use('com.vivo.identifier.IdentifierManager');
    [['getOAID', 'ad.oaid'], ['getVAID', 'ad.vaid'], ['getAAID', 'ad.aaid'], ['getGuid', 'ad.guid']].forEach(function (pair) {
      try {
        Vivo[pair[0]].overloads.forEach(function (overload) {
          overload.implementation = function () {
            var r = overload.apply(this, arguments);
            writeReq(pair[1], 'IdentifierManager.' + pair[0], '', safeStr(r), null);
            return r;
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    [['onReceivedSslError', 'browser.ssl_error'],
      ['onReceivedClientCertRequest', 'browser.client_cert'],
      ['onReceivedHttpAuthRequest', 'browser.http_auth']].forEach(function (pair) {
      try {
        WVC[pair[0]].overloads.forEach(function (overload) {
          overload.implementation = function () {
            writeReq(pair[1], 'WebViewClient.' + pair[0], safeStr(arguments[2]), '', null);
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) {}
  try {
    var WCC = Java.use('android.webkit.WebChromeClient');
    WCC.onShowFileChooser.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('browser.file_chooser', 'WebChromeClient.onShowFileChooser', '', 'chooser', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var FI = Java.use('com.google.firebase.installations.FirebaseInstallations');
    FI.getToken.overloads.forEach(function (overload) {
      overload.implementation = function () {
        writeReq('ad.firebase_token', 'FirebaseInstallations.getToken', '', 'requested', null);
        return overload.apply(this, arguments);
      };
    });
  } catch (e) {}
}

function hookGsfAndSettingsQuery() {
  try {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var uri = safeStr(arguments[0]);
        var result = overload.apply(this, arguments);
        if (/gservices|settings\/secure|settings\/global|settings\/system/i.test(uri)) {
          writeEvent(
            /gservices/i.test(uri) ? 'ad.gsf_id' : 'settings.secure',
            'ContentResolver.query',
            uri.substring(0, 180),
            result ? 'cursor' : 'null',
            null
          );
        }
        return result;
      };
    });
  } catch (e) {}
}

function hookVpnAndProxy() {
  try {
    var CM = Java.use('android.net.ConnectivityManager');
    CM.getNetworkCapabilities.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var r = overload.apply(this, arguments);
        var vpn = false;
        try { vpn = !!(r && r.hasTransport(4)); } catch (e) {}
        writeOnce('net.vpn', 'ConnectivityManager.getNetworkCapabilities', '', 'vpn=' + vpn, null);
        return r;
      };
    });
  } catch (e) {}
}

var identifierHooksInstalled = false;
function installIdentifierHooks() {
  if (identifierHooksInstalled) return;
  identifierHooksInstalled = true;
  writeEvent('frida.init', 'Frida: хуки идентификаторов включены', TARGET_PKG, 'перехват вызовов цели', null);
  hookBuild();
  hookSystemProperties();
  hookSettings();
  hookGsfAndSettingsQuery();
  hookTelephonyManager();
  hookSubscriptionManager();
  hookLocation();
  hookWifiAndBluetooth();
  hookNetworkInterface();
  hookMediaDrm();
  hookAdvertisingId();
  hookAccounts();
  hookVpnAndProxy();
}

var remainingHooksInstalled = false;
function installJavaHooks() {
  if (remainingHooksInstalled) return;
  remainingHooksInstalled = true;
  installIdentifierHooks();
  hookPackageManager();
  hookContentResolver();
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
  hookWorkAndGeofence();
  hookCronetVolleyRetrofit();
  hookHmsAndFlutter();
  hookSniAndIntent();
  hookRequestSurface();
  hookMissedRequestApis();
  hookFraudFingerprint();
  hookFraudSdks();
  hookBrowserApis();
  hookMissedSurface();
  hookCatalogCompleteness();
  hookRootDetection();
  hookNativeRootAccess();
}

try { writeEvent('frida.boot', 'Frida: скрипт загружен', TARGET_PKG, EVENT_FILES[0], null); } catch (e) {}

function tryInstallIdentifierHooks() {
  if (identifierHooksInstalled) return true;
  if (!Java.available) return false;
  Java.perform(function () {
    try { installIdentifierHooks(); } catch (e) {}
  });
  return identifierHooksInstalled;
}

var nativePropsHooked = false;
var nativeNetHooked = false;
var installTries = 0;
var installTimer = null;

function installNativeEarly() {
  if (!nativePropsHooked) {
    try { hookNativeProperties(); nativePropsHooked = true; } catch (e) {}
  }
  if (!nativeNetHooked) {
    try { hookNativeNetMeta(); nativeNetHooked = true; } catch (e) {}
  }
}

installNativeEarly();
try { tryInstallIdentifierHooks(); } catch (e) {}

installTimer = setInterval(function () {
  installTries++;
  try { tryInstallIdentifierHooks(); } catch (e) {}
  if (identifierHooksInstalled || installTries > 40) {
    if (installTimer) clearInterval(installTimer);
  }
}, 80);

setTimeout(function () {
  if (Java.available) {
    Java.perform(function () {
      try { installJavaHooks(); } catch (e) {}
    });
  }
  installNativeEarly();
  if (MITM_ENABLED) {
    try { installMitmHooks(); } catch (e) {}
  }
}, 400);

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
            writeEvent('net.https', this.fn, TARGET_PKG, truncateHttp(text), null, { async: true });
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
