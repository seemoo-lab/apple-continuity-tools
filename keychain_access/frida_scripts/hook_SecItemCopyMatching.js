/**
 * Convert NSData to a hex formatted string
 * @param {NSData} data NSData from Objective-c
 */
function nsDataToHex(data) {
  var arrayBuffer = new NativePointer(data.bytes()).readByteArray(
    data.length()
  );
  var bytes = new Uint8Array(arrayBuffer);
  if (!bytes) {
    return "";
  }

  var dataLength = data.length();
  var hexString = "0x";

  for (var i = 0; i < dataLength; i++) {
    var byte = bytes[i];
    var hx = byte.toString(16);
    hexString += hx;
  }

  return hexString;
}

/**
 * Decode OPACK encoded NSData
 * @param {NSData} data
 */
function decodeOPACKFromNSData(data) {
  try {
    var OPACKDecodeData = new NativeFunction(
      Module.findExportByName("CoreUtils", "OPACKDecodeData"),
      "pointer",
      ["pointer", "int", "pointer"]
    );
    console.log("Decoding OPACK\n", OPACKDecodeData);
    var errorPtr = ptr(0x00);

    var opackDictionary = OPACKDecodeData(data, 0, errorPtr);
    if (opackDictionary) {
      return new ObjC.Object(opackDictionary);
    } else {
      console.error("OPACK decoding failed");
    }
  } finally {
    return null;
  }
}

/**
 * Convert an NSDictionary to a JS Object
 * @param {NSDictionary} dict
 */
function dictionaryToJSObject(dict) {
  var obj = {};
  var allKeys = dict.allKeys();
  var keysCount = allKeys.count();

  for (var i = 0; i < keysCount; i++) {
    var key = allKeys.objectAtIndex_(i);
    var keyString = key.valueOf();
    var value = dict.objectForKey_(key);

    if (value.$className.includes("Data")) {
      obj[keyString] = nsDataToHex(value);
    } else {
      obj[keyString] = value.valueOf();
    }
  }
  return obj;
}

/**
 * Convert a NSDictionary with a keychain item to a JS Object
 * @param {NSDictionary} entry
 */
function keychainItemToJson(entry) {
  var keychainJSON = {};

  var default_keys = ["v_Data", "agrp", "cdat", "mdat", "pdmn", "acct", "svce"];

  if (entry.objectForKey_("v_Data") != null) {
    var data = entry.objectForKey_("v_Data");
    var hexString = nsDataToHex(data);
    keychainJSON.Data = hexString;
    // Try Decode OPACK
    var opackDictionary = decodeOPACKFromNSData(data);
    if (opackDictionary) {
      keychainJSON.KeyData = dictionaryToJSObject(opackDictionary);
    }
  }

  if (entry.containsKey_("agrp")) {
    keychainJSON.KeychainAccessGroup = entry.objectForKey_("agrp").valueOf();
  }

  if (entry.containsKey_("cdat")) {
    var date = entry.objectForKey_("cdat");
    keychainJSON.CreationTime = date.valueOf();
  }

  if (entry.containsKey_("pdmn")) {
    keychainJSON.Protection = constants[entry.objectForKey_("pdmn").valueOf()]
      ? constants[entry.objectForKey_("pdmn").valueOf()]
      : "null";
  }

  if (entry.containsKey_("acct")) {
    keychainJSON.Account = entry.objectForKey_("acct").valueOf();
  }

  if (entry.containsKey_("svce")) {
    keychainJSON.Service = entry.objectForKey_("svce").valueOf();
  }

  if (entry.containsKey_("mdat")) {
    var date = entry.objectForKey_("mdat");
    keychainJSON.ModifiedTime = date.valueOf();
  }

  var allKeys = entry.allKeys();
  var keysCount = allKeys.count();

  for (var i = 0; i < keysCount; i++) {
    var key = allKeys.objectAtIndex_(i);
    var keyString = key.valueOf();
    if (default_keys.indexOf(keyString) >= 0) {
      continue;
    }

    var value = entry.objectForKey_(key);

    if (value.$className.includes("Data")) {
      keychainJSON[keyString] = nsDataToHex(value);
    } else {
      keychainJSON[keyString] = value.valueOf();
    }
  }

  return keychainJSON;
}

var constants = {
  ck: "kSecAttrAccessibleAfterFirstUnlock",
  ak: "kSecAttrAccessibleWhenUnlocked",
  cku: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
  dk: "kSecAttrAccessibleAlways",
  dku: "kSecAttrAccessibleAlwaysThisDeviceOnly",
  akpu: "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
  aku: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
  cert: "kSecClassCertificate",
  class: "kSecClass",
  genp: "kSecClassGenericPassword",
  idnt: "kSecClassIdentity",
  inet: "kSecClassInternetPassword",
  keys: "kSecClassKey",
};

// Find location of SecItemCopyMatching
var SecItemCopyMatching = Module.findExportByName(
  "Security",
  "SecItemCopyMatching"
);
var returnPtr = null;
var keychainQuery = null;

// Hook into the SecItemCopyMatching function
Interceptor.attach(SecItemCopyMatching, {
  onEnter: function (args) {
    var query = new ObjC.Object(args[0]); // NSDictionary
    keychainQuery = query;
    returnPtr = args[1];
  },
  onLeave: function () {
    try {
      // Copied from Needle https://github.com/FSecureLABS/needle/blob/master/needle/modules/storage/data/keychain_dump_frida.py
      var result = new ObjC.Object(Memory.readPointer(returnPtr));

      var returned = null;

      if (result.$className.includes("Dictionary")) {
        returned = keychainItemToJson(result);
      } else if (result.$className.includes("Array")) {
        var keychainEntries = [];
        for (var i = 0; i < result.count(); i++) {
          var entry = result.objectAtIndex_(i);
          keychainEntries.push(keychainItemToJson(entry));
        }
        returned = keychainEntries;
      } else if (result.$className.includes("Data")) {
        returned = nsDataToHex(result);
      } else {
        console.log(
          "Returned unknown Keychain item of class ",
          result.$className
        );
      }

      send({
        query: keychainItemToJson(keychainQuery),
        result: returned,
      });
    } catch (error) {
      console.log(error);
    }
  },
});
