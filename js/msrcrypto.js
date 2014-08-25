//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/* jshint -W016 */ /* repress binary operator errors */
/* jshint -W052 */ /* repress complaint about binary NOT operator*/
var msrCryptoVersion = "1.01";
var msrCrypto = msrCrypto || (function () {

    "use strict";
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

var operations = {};

operations.register = function (operationType, algorithmName, functionToCall) {

    if (!operations[operationType]) {
        operations[operationType] = {};
    }

    var op = operations[operationType];

    if (!op[algorithmName]) {
        op[algorithmName] = functionToCall;
    }

};

operations.exists = function (operationType, algorithmName) {
    if (!operations[operationType]) {
        return false;
    }

    return (operations[operationType][algorithmName]) ? true : false;
};
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global self */
/* jshint -W098 */
/* W098 is 'defined but not used'. These properties are used in other scripts. */

/// <reference path="jsCopDefs.js" />

// Sets the url to for this script.
// We need this to pass to webWorkers later to instantiate them.

/// <dictionary>fprng</dictionary>

/// #endregion JSCop/JsHint

var scriptUrl = (function () {

    /* jshint -W117 */

    if (typeof document !== "undefined") {
        var scripts = document.getElementsByTagName("script");
        // Since this script is currently being evaluated
        //  it will be the last one in the list.
        return scripts[scripts.length - 1].src;
        
    } else if (typeof self !== "undefined") {
        // If this script is being run in a WebWorker, 'document' will not exist
        //  but we can use self.        
        return self.location.href;        
    }

    // Must be running in an environment without document or self.
    return null;

    /* jshint +W117 */

})();

// Indication if the user provided entropy into the entropy pool.
var fprngEntropyProvided = false;

// Support for webWorkers IE10+.
var webWorkerSupport = (typeof Worker !== "undefined");

// Is this script running in an instance of a webWorker?
var runningInWorkerInstance = (typeof importScripts !== "undefined");

// Typed Arrays support?
var typedArraySupport = (typeof Uint8Array !== "undefined");

// Property setter/getter support IE9+.
var setterSupport = (function () {
    try {
        Object.defineProperty({}, "oncomplete", {});
        return true;
    } catch (ex) {
        return false;
    }
}());

// Run in async mode (requires web workers) and user can override to sync mode
//  by setting the .forceSync property to true on the subtle interface
//  this can be changes 'on the fly'.
var asyncMode = webWorkerSupport;

// Gets the type of a native object.
var type = function (item) {
    return Object.prototype.toString.call(item).replace("[object ", "").replace("]", "");
};

var createProperty = function (parentObject, propertyName, /*@dynamic*/initialValue, getterFunction, setterFunction) {
    /// <param name="parentObject" type="Object"/>
    /// <param name="propertyName" type="String"/>
    /// <param name="initialValue" type="Object"/>
    /// <param name="getterFunction" type="Function"/>
    /// <param name="setterFunction" type="Function" optional="true"/>

    if (!setterSupport) {
        parentObject[propertyName] = initialValue;
        return;
    }

    var setGet = {};

    getterFunction && (setGet.get = getterFunction);
    setterFunction && (setGet.set = setterFunction);

    Object.defineProperty(
        parentObject,
        propertyName, setGet);
};

// Collection of hash functions for global availability.
// Each hashfunction will add itself to the collection as it is evaluated.
var msrcryptoHashFunctions = {};
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* jshint -W016 */

/// <reference path="global.js" />
/// <reference path="jsCopDefs.js" />

/// <dictionary>
///    msrcrypto, Btoa, uint, hexval, res, xor
/// </dictionary>

/// #endregion JSCop/JsHint

var msrcryptoUtilities = (function () {

    var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    var btoaSupport = (typeof btoa !== "undefined");

    function toBase64(/*@dynamic*/data, /*@optional*/ base64Url) {
        /// <returns type="String"/>

        var output = "";

        if (!base64Url) {
            base64Url = false;
        }

        // If the input is an array type, convert it to a string.
        // The built-in btoa takes strings.
        if (data.pop || data.subarray) {
            data = String.fromCharCode.apply(null, data);
        }

        if (btoaSupport) {
            output = btoa(data);
        } else {

            var char1, char2, char3, enc1, enc2, enc3, enc4;
            var i;

            for (i = 0; i < data.length; i += 3) {

                // Get the next three chars.
                char1 = data.charCodeAt(i);
                char2 = data.charCodeAt(i + 1);
                char3 = data.charCodeAt(i + 2);

                // Encode three bytes over four 6-bit values.
                // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].
                // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].

                // 'enc1' = high 6-bits from char1
                enc1 = char1 >> 2;
                // 'enc2' = 2 low-bits of char1 + 4 high-bits of char2
                enc2 = ((char1 & 0x3) << 4) | (char2 >> 4);
                // 'enc3' = 4 low-bits of char2 + 2 high-bits of char3
                enc3 = ((char2 & 0xF) << 2) | (char3 >> 6);
                // 'enc4' = 6 low-bits of char3
                enc4 = char3 & 0x3F;

                // 'char2' could be 'nothing' if there is only one char left to encode
                //   if so, set enc3 & enc4 to 64 as padding.
                if (isNaN(char2)) {
                    enc3 = enc4 = 64;

                    // If there was only two chars to encode char3 will be 'nothing'
                    //   set enc4 to 64 as padding.
                } else if (isNaN(char3)) {
                    enc4 = 64;
                }

                // Lookup the base-64 value for each encoding.
                output = output +
                encodingChars.charAt(enc1) +
                encodingChars.charAt(enc2) +
                encodingChars.charAt(enc3) +
                encodingChars.charAt(enc4);
            }
        }

        if (base64Url) {
            return output.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        }

        return output;
    }

    function base64ToString(encodedString) {
        /// <param name="encodedString" type="String"/>
        /// <returns type="String"/>

        if (btoaSupport) {

            // This could be encoded as base64url (different from base64)
            encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

            // In case the padding is missing, add some.
            while (encodedString.length % 4 !== 0) {
                encodedString += "=";
            }

            return atob(encodedString);
        }

        return String.fromCharCode.apply(null, base64ToBytes(encodedString));

    }

    function base64ToBytes(encodedString) {
        /// <param name="encodedString" type="String"/>
        /// <returns type="Array"/>

        // This could be encoded as base64url (different from base64)
        encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

        // In case the padding is missing, add some.
        while (encodedString.length % 4 !== 0) {
            encodedString += "=";
        }

        var output = [];
        var char1, char2, char3;
        var enc1, enc2, enc3, enc4;
        var i;

        // Remove any chars not in the base-64 space.
        encodedString = encodedString.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for (i = 0; i < encodedString.length; i += 4) {

            // Get 4 characters from the encoded string.
            enc1 = encodingChars.indexOf(encodedString.charAt(i));
            enc2 = encodingChars.indexOf(encodedString.charAt(i + 1));
            enc3 = encodingChars.indexOf(encodedString.charAt(i + 2));
            enc4 = encodingChars.indexOf(encodedString.charAt(i + 3));

            // Convert four 6-bit values to three characters.
            // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].
            // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].

            // 'char1' = all 6 bits of enc1 + 2 high-bits of enc2.
            char1 = (enc1 << 2) | (enc2 >> 4);
            // 'char2' = 4 low-bits of enc2 + 4 high-bits of enc3.
            char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            // 'char3' = 2 low-bits of enc3 + all 6 bits of enc4.
            char3 = ((enc3 & 3) << 6) | enc4;

            // Convert char1 to string character and append to output
            output.push(char1);

            // 'enc3' could be padding
            //   if so, 'char2' is ignored.
            if (enc3 !== 64) {
                output.push(char2);
            }

            // 'enc4' could be padding
            //   if so, 'char3' is ignored.
            if (enc4 !== 64) {
                output.push(char3);
            }

        }

        return output;

    }

    function getObjectType(object) {
        /// <param name="encodedString" type="Object"/>
        /// <returns type="String"/>
        return Object.prototype.toString.call(object).slice(8, -1);
    }

    function bytesToHexString(bytes, separate) {
        /// <param name="bytes" type="Array"/>
        /// <param name="separate" type="Boolean" optional="true"/>
        /// <returns type="String"/>

        var result = "";
        if (typeof separate === "undefined") {
            separate = false;
        }

        for (var i = 0; i < bytes.length; i++) {

            if (separate && (i % 4 === 0) && i !== 0) {
                result += "-";
            }

            var /*@type(String)*/ hexval = bytes[i].toString(16).toUpperCase();
            // Add a leading zero if needed.
            if (hexval.length === 1) {
                result += "0";
            }

            result += hexval;
        }

        return result;
    }

    function stringToBytes(messageString) {
        /// <param name="messageString" type="String"/>
        /// <returns type="Array"/>

        var bytes = new Array(messageString.length);

        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = messageString.charCodeAt(i);
        }

        return bytes;
    }

    function hexToBytesArray(hexString) {

        hexString = hexString.replace(/\-/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return result;
    }

    function clone(/*@type(Object)*/object) {
        var newObject = {};
        for (var propertyName in object) {
            if (object.hasOwnProperty(propertyName)) {
                newObject[propertyName] = object[propertyName];
            }
        }
        return newObject;
    }

    function unpackData(base64String, arraySize, toUint32s) {

        var bytes = base64ToBytes(base64String),
            data = [],
            i;

        if (isNaN(arraySize)) {
            return bytes;
        } else {
            for (i = 0; i < bytes.length; i += arraySize) {
                data.push(bytes.slice(i, i + arraySize));
            }
        }

        if (toUint32s) {
            for (i = 0; i < data.length; i++) {
                data[i] = (data[i][0] << 24) + (data[i][1] << 16) + (data[i][2] << 8) + data[i][3];
            }
        }

        return data;
    }

    function int32ToBytes(int32) {
        return [(int32 >>> 24) & 255, (int32 >>> 16) & 255, (int32 >>> 8) & 255, int32 & 255];
    }

    function int32ArrayToBytes(int32Array) {
        var result = [];
        for (var i = 0; i < int32Array.length; i++) {
            result = result.concat(int32ToBytes(int32Array[i]));
        }
        return result;
    }

    function xorVectors(a, b) {
        /// <summary>Exclusive OR (XOR) two arrays.</summary>
        /// <param name="a" type="Array">Input array.</param>
        /// <param name="b" type="Array">Input array.</param>
        /// <returns type="Array">XOR of the two arrays. The length is minimum of the two input array lengths.</returns>
        var length = Math.min(a.length, b.length),
            res = new Array(length);
        for (var i = 0 ; i < length ; i += 1) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }

    function getVector(length, /*@optional*/ fillValue) {
        /// <summary>Get an array filled with zeroes.</summary>
        /// <param name="length" type="Number">Requested array length.</param>
        /// <returns type="Array">Array of length filled with zeroes.</returns>

        // Use a default value of zero
        fillValue || (fillValue = 0);

        var res = new Array(length);
        for (var i = 0; i < length; i += 1) {
            res[i] = fillValue;
        }
        return res;
    }

    function /*@type(Array)*/ toArray(/*@type(Array)*/ typedArray) {

        if (typedArray.pop) {
            return typedArray;
        }

        // A single element array will cause a new Array to be created with the length
        // equal to the value of the single element. Not what we want.
        // We'll return a new single element array with the single value.
        return (typedArray.length === 1) ? [typedArray[0]] : Array.apply(null, typedArray);
    }

    function indexOf(array, value, /*@optional*/ start) {

        // If 'array' is a regular array
        if (array.indexOf) {
            return array.indexOf(value, start);
        }

        // If 'array' is a typed array (or regular array on IE8)
        for (var i = start || 0; i < array.length; i += 1) {
            if (array[i] === value) {
                return i;
            }
        }

        return -1;
    }

    function padEnd(array, value, finalLength) {

        while (array.length < finalLength) {
            array.push(value);
        }

        return array;
    }

    function padFront(array, value, finalLength) {

        while (array.length < finalLength) {
            array.unshift(value);
        }

        return array;
    }

    function arraysEqual(/*@type(Array)*/ array1, /*@type(Array)*/ array2) {
        if (array1.length !== array2.length) {
            return false;
        }

        for (var i = 0; i < array1.length; i++) {
            if (array1[i] !== array2[i]) {
                return false;
            }
        }

        return true;
    }

    return {
        toBase64: toBase64,
        base64ToString: base64ToString,
        base64ToBytes: base64ToBytes,
        getObjectType: getObjectType,
        bytesToHexString: bytesToHexString,
        stringToBytes: stringToBytes,
        unpackData: unpackData,
        hexToBytesArray: hexToBytesArray,
        int32ToBytes: int32ToBytes,
        int32ArrayToBytes: int32ArrayToBytes,
        indexOf: indexOf,
        toArray: toArray,
        arraysEqual: arraysEqual,
        clone: clone,
        xorVectors: xorVectors,
        padEnd: padEnd,
        padFront: padFront,
        getVector: getVector
    };

})();
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global fprngEntropyProvided: true */
/* global runningInWorkerInstance */
/* global self */
/* global operations */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="random.js" />

/// <dictionary>
///    msrcrypto, webworker, func, onmessage, prng
/// </dictionary>

/// #endregion JSCop/JsHint

var msrcryptoWorker = (function () {

    // If we're running in a webworker we need to postMessage to return our result
    //   otherwise just return the value as normal.
    function returnResult(result) {
        if (runningInWorkerInstance) {
            self.postMessage(result);
        }
        return result;
    }

    return {

        jsCryptoRunner: function (/*@type(typeEvent)*/ e) {

            var operation = e.data.operationType;
            var result;

            if (!operations.exists(operation, e.data.algorithm.name)) {
                throw new Error("unregistered algorithm.");
            }

            var func = operations[operation][e.data.algorithm.name];

            var /*@dynamic*/ p = e.data;

            if (p.operationSubType === "process") {
                func(p);
                result = returnResult({ type: "process" });
            } else {
                result = returnResult(func(p));
            }

            return result;
        }
    };

})();

// If this is running in a webworker we need self.onmessage to receive messages from
//   the calling script.
// If we are in 'synchronous mode' (everything running in one script)
//   we don't want to override self.onmessage.
if (runningInWorkerInstance) {

    self.onmessage = function (/*@type(typeEvent)*/e) {

        // When this worker first gets instantiated we will receive seed data
        //   for this workers prng.
        if (e.data.prngSeed) {
            var entropy = e.data.prngSeed;
            msrcryptoPseudoRandom.init(entropy);
            return;
        }

        // Process the crypto operation
        msrcryptoWorker.jsCryptoRunner(e);
    };
}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoUtilities */

/// <reference path="utilities.js" />

/// <dictionary>alg,Jwk,msrcrypto,utils</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoJwk = (function () {

    var utils = msrcryptoUtilities;

    function stringToArray(stringData) {

        var result = [];

        for (var i = 0; i < stringData.length; i++) {
            result[i] = stringData.charCodeAt(i);
        }

        if (result[result.length - 1] === 0) {
            result.pop();
        }

        return result;
    }

    function getKeyType(keyHandle) {

        var algType = keyHandle.algorithm.name.slice(0, 3).toLowerCase();

        if (algType === "rsa") {
            return "RSA";
        }

        if (algType === "ecd") {
            return "EC";
        }

        return "oct";
    }

    function keyToJwk(keyHandle, keyData) {

        var key = {};

        key.kty = getKeyType(keyHandle);
        key.extractable = keyHandle.extractable;
        
        // Using .pop to determine if a property value is an array.
        if (keyData.pop) {
            key.k = utils.toBase64(keyData, true);
        } else {
            // Convert the base64Url properties to byte arrays
            for (var property in keyData) {
                if (keyData[property].pop) {
                    key[property] = utils.toBase64(keyData[property], true);
                }
            }
        }

        if (keyHandle.algorithm.namedCurve) {
            key["crv"] = keyHandle.algorithm.namedCurve;
        }

        var stringData = JSON.stringify(key, null, '\t');

        return stringToArray(stringData);

    }

    // 'jwkKeyData' is an array of bytes. Each byte is a charCode for a json key string
    function jwkToKey(keyData, algorithm, propsToArray) {

        // Convert array of string data to a json string
        var jsonString = String.fromCharCode.apply(null, keyData);

        // Convert the json string to an object
        var jsonKeyObject = JSON.parse(jsonString);

        // Convert the base64url encoded properties to byte arrays
        for (var i = 0; i < propsToArray.length; i += 1) {
            var propValue = jsonKeyObject[propsToArray[i]];
            if (propValue) {
                jsonKeyObject[propsToArray[i]] =
                    utils.base64ToBytes(propValue);
            }
        }

        return jsonKeyObject;
    }

    return {
        keyToJwk: keyToJwk,
        jwkToKey: jwkToKey
    };
})();
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

//depot/incubations/msrcrypto/msrCrypto/scripts/cryptoMath.js#5 - edit change 1781 (text)
/// cryptoMath.js ==================================================================================
/// Implementation of math routines for cryptographic applications.

/// #region JSCop/JsHint
/* jshint -W016 */ /* allows bitwise operators */
/* jshint -W052 */ /* allows not operator */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="random.js" />

/// <dictionary>alg,bitmasks,coord,De-montgomeryized,digitbits,digitmask,divrem,dont,Elt,endian-ness,endian,gcd,goto,gotta,Int,Jacobi,Jacobian,Legendre,mlen,Modm,modpow,montgomerized,montgomeryize,montgomeryized,montmul,mul,param,Pomerance,povar,precompute,Pseudocode,Tolga,typeof,Uint,unrollsentinel,wil,Xout,Xout-t,Yout,Zout</dictionary>
/// <dictionary>aequals,Eshift,idx,Lsbit,Minust,mult,myelement,myresult,naf,Neg,Nist,numcopy,Obj,onemontgomery,Precomputation,Res,swaptmp,Tmp,xbytes,ybytes</dictionary>

/// #endregion JSCop/JsHint

function MsrcryptoMath() {
    // 'number' of bits per digit. Must be even.
    var DIGIT_BITS = 24;
    // 'number' of bytes per digit.
    var DIGIT_NUM_BYTES = Math.floor(DIGIT_BITS / 8);
    // digit mask.
    var DIGIT_MASK = (1 << DIGIT_BITS) - 1;
    // digit base.
    var DIGIT_BASE = (1 << DIGIT_BITS);
    // max digit value, unsigned
    var DIGIT_MAX = DIGIT_MASK;

    // Construct scaler for DIGIT_NUM_BYTES, so I don't have to multiply in the loop
    var DIGIT_SCALER = [1, 256];
    for (var i = 2; i <= DIGIT_NUM_BYTES; ++i) {
        DIGIT_SCALER[i] = DIGIT_SCALER[i - 1] * 256;
    }

    // Number of trailing zero bits in numbers 0..15 (4 bits). [0] is for 0, [15] is for 15.
    var Zero = [0];
    var One = [1];

    // Create an array, mimics the constructors for typed arrays.
    function createArray(/*@dynamic*/parameter) {
        var i, array = null;
        if (!arguments.length || typeof arguments[0] === "number") {
            // A number.
            array = new Array(parameter);
            for (i = 0; i < parameter; i += 1) {
                array[i] = 0;
            }
        } else if (typeof arguments[0] === "object") {
            // An array or other index-able object
            array = new Array(parameter.length);
            for (i = 0; i < parameter.length; i += 1) {
                array[i] = parameter[i];
            }
        }
        return array;
    }

    function swapEndianness(bytes) {
        /// <summary>Swap big endian bytes to little endian bytes.</summary>
        /// <param name="bytes" type="Bytes">UInt8Array - representing a big-integer.</param>
        /// <returns type="Bytes">UInt8Array - the number with endianness swapped.</returns>

        var out = new Array(bytes.length);
        var i = 0;

        while (i < bytes.length) {
            out[i] = bytes[bytes.length - i - 1];
            i += 1;
        }

        return out;
    }

    function stringToDigits(number, radix) {
        /// <summary>Parse a String in a given base into a little endian digit array.</summary>
        /// <param name="number" type="String">Input unsigned integer in a string.</param>
        /// <param name="radix" optional="true" integer="true">Radix of the input. Must be >=2 and <=36. Default = 10.</param>
        /// <returns type="Array">Array of digits in little endian; [0] is LSW.</returns>

        // skip leading and trailing whitespace.
        number = number.replace(/^\s+|\s+$/g, '');
        var num = [0];
        var buffer = [0];
        radix = radix || 10;        // default radix is 10
        for (var i = 0; i < number.length; i += 1) {
            // Extract character
            var char = parseInt(number[i], radix);
            if (isNaN(char)) {
                throw new Error("Failed to convert string to integer in radix " + radix.toString());
            }

            // 'buffer' = 'num' * 'radix'
            multiply(num, radix, buffer);

            // 'num' = 'buffer' + 'char'
            add(buffer, [/*@static_cast(Number)*/char], num);
            normalizeDigitArray(num);
        }

        return num;
    }

    function digitsToString(digits, radix) {
        /// <summary>Convert a big-endian byte array to a number in string in radix.</summary>
        /// <param name="digits" type="Digits">A big integer as a little-endian digit array.</param>
        /// <param name="radix" optional="true" integer="true">Radix from 2 to 26. Default = 10.</param>
        /// <returns type="String">The number in base radix as a string.</returns>

        radix = radix || 10;
        if (DIGIT_BASE <= radix) {
            throw new Error("DIGIT_BASE is smaller than RADIX; cannot convert.");
        }

        var wordLength = digits.length;
        var quotient = [];
        var remainder = [];
        var temp1 = [];
        var temp2 = [];
        var divisor = [];
        var a = [];
        var i;

        // Find the largest divisor that fits in a digit in radix
        //divisor[0] = 10000; // Largest power of ten fitting in a digit
        var sb = "";
        var pad = "0";
        divisor[0] = radix;
        while (Math.floor(DIGIT_BASE / divisor[0]) >= radix) {
            divisor[0] = divisor[0] * radix;
            pad = pad.concat("0");
        }

        for (i = 0; i < wordLength; i += 1) {
            a[i] = digits[i];
        }

        do {
            var allZeros = true;
            for (i = 0; i < a.length; i += 1) {
                if (a[i] !== 0) {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros) {
                break;
            }

            divRem(a, divisor, quotient, remainder, temp1, temp2);
            normalizeDigitArray(quotient, a.length, true);

            var /*@type(String) */ newDigits = remainder[0].toString(radix);
            sb = pad.substring(0, pad.length - newDigits.length) + newDigits + sb;

            var swap = a;
            a = quotient;
            quotient = swap;
        } while (true);

        // Trim leading zeros
        while (sb.length !== 0 && sb[0] === "0") {
            sb = sb.substring(1, sb.length);
        }

        if (sb.length === 0) {
            sb = "0";
        }

        return sb;
    }

    function powerOfTwo(i) {
        /// <summary>Given a positive integer i, return a big integer in big-endian format
        ///   equal to 2^i. This is useful for creating fields of certain size.</summary>
        /// <param name="i" type="Number">A positive integer.</param>
        /// <returns>UInt8Array - 2^i as a big-endian byte array.</returns>
        var requiredBytes = Math.ceil((i + 1) / 8);
        var out = createArray(requiredBytes);
        out[0] = Math.pow(2, i % 8);
        return out;
    }

    function computeBitArray(bytes) {
        /// <summary>Given an array of bytes in big-endian format, compute UInt8Array with
        /// one element for each bit (0 or 1), in little-endian order.</summary>
        /// <param name="bytes" type="Digits">An array of bytes in big-endian format.</param>
        /// <returns type="Digits">An array of 0's and 1's representing the bits in little-endian.</returns>

        var out = createArray(bytes.length * 8);
        var bitLength = 0;
        var i = bytes.length - 1;
        while (i >= 0) {
            var j = 0;
            while (j < 8) {
                var mask = (1 << j);
                var bit = ((bytes[i] & mask) === mask) ? 1 : 0;
                var thisBitIndex = (8 * ((bytes.length - i) - 1)) + j;

                if (bit === 1) {
                    bitLength = thisBitIndex + 1;
                }

                out[thisBitIndex] = bit;
                j += 1;
            }

            i--;
        }

        return out.slice(0, bitLength);
    }

    function bitScanForward(value) {
        /// <summary>Return the 0-based index of the first non-zero bit starting at the most significant bit position.</summary>
        /// <param name="value" type="Number" integer="true">Value to scan.</param>
        /// <returns>Zero-based index of the first non-zero bit.</returns>
        var mask = DIGIT_BASE >>> 1;
        var index = DIGIT_BITS;
        while (index-- > 0) {
            if ((value & mask) === mask) {
                break;
            }
            mask = mask >>> 1;
        }

        return index;
    }

    function highestSetBit(bytes) {
        /// <summary>Returns the (1 indexed) index of the highest set bit.</summary>
        /// <param name="bytes" type="Array">A big-endian big integer byte array.</param>
        /// <returns type="Number">The index of the highest bit.</returns>

        var i = 0;
        var bitLength = 0;

        while (i < bytes.length) {
            if (bitLength === 0) {
                // Look for highest set bit in this byte
                var j = 7;
                while (j >= 0 && bitLength === 0) {
                    var mask = (1 << j);
                    if ((bytes[i] & mask) === mask) {
                        bitLength = j + 1;
                    }

                    j--;
                }
            } else {
                bitLength += 8;
            }

            i += 1;
        }

        return bitLength;
    }

    function computeNAF(k, w, temp, nafDigits) {
        /// <summary>Compute the width-w Non-Adjacent-Form of the given positive integer, from 
        ///   least to most significant digit.</summary>
        /// <param name="k" type="Digits">A little-endian digit array representing the
        ///                             number to be converted into NAF.</param>
        /// <param name="w" type="Number" integer="true">The width of the NAF window.</param>
        /// <param name="temp" type="Digits">An array for temp storage, same size as k.</param>
        /// <param name="nafDigits" type="Array">An array which receives the NAF form of
        ///                             of the given number. Size should be equal to the 
        ///                             width of k (digits * 16) plus one. Not all elements will be 
        ///                             necessarily be used.</param>
        /// <returns type="Number" integer="true">The number of valid digits.</returns>

        // Get the number of bits
        var bitWidth = k.length * DIGIT_BITS;
        var i, j;
        var s = k.length;
        var sMinusOne = s - 1;

        if (nafDigits.length !== bitWidth + 1) {
            throw "nafDigits length must = bitwidth + 1";
        }

        if (w <= 1) {
            throw "w must be greater than 1";
        }

        if (w >= DIGIT_BITS) {
            throw "w must be less than " + DIGIT_BITS.toString();
        }

        // Clone digits because we are going to modify them during the
        // computation.

        for (i = 0; i < s; i += 1) {
            temp[i] = k[i];
        }

        // Set number of NAF digits (out parameter) to begin 
        var numNafDigits = 0;

        // Mask for taking w bits off the digits
        var mask = (0x1 << w) - 1;
        var wMinusOne = w - 1;
        var twoToTheW = (0x1 << w);
        var twoToTheWMinusOneMinusOne = (0x1 << (w - 1)) - 1;

        // Number of pending zeros to write the NAF.
        // They will be written IFF we encounter a non-zero value to write.
        var zeroCount = 0;

        var isTempZero = isZero(temp);

        while (!isTempZero) {
            /* If k is even */
            if ((temp[0] & 0x1) !== 0x1) {
                // 'k' <- k / 2
                shiftRight(temp, temp);
                zeroCount++;
            } else {
                // Grab remainder bits
                var maskedBits = (temp[0] & mask);

                // Bit shift w to the right
                shiftRight(temp, temp, w, sMinusOne + 1);
                if (maskedBits > twoToTheWMinusOneMinusOne) {
                    maskedBits -= twoToTheW;
                }

                if (maskedBits < 0) {
                    // ADD ONE TO K
                    var carry = temp[0] + 1;
                    temp[0] = carry & DIGIT_MASK;
                    carry = (carry >> DIGIT_BITS);

                    // Break early if possible
                    if (carry !== 0) {
                        for (j = 1; j < s; j += 1) {
                            carry += temp[j];
                            temp[j] = carry & DIGIT_MASK;
                            carry = (carry >> DIGIT_BITS);
                            if (carry === 0) {
                                break;
                            }
                        }
                    }
                }

                // Add any pending zeros and reset the zero counter
                for (; zeroCount > 0; zeroCount--) {
                    nafDigits[numNafDigits] = 0;
                    numNafDigits++;
                }

                // 'k_i' = maskedBits
                nafDigits[numNafDigits] = maskedBits;
                numNafDigits++;

                // Add zeros
                for (j = 0; j < wMinusOne; j += 1) {
                    zeroCount++;
                }
            }

            isTempZero = true;
            for (i = 0; i < s; i += 1) {
                if (temp[i] !== 0) {
                    isTempZero = false;
                    break;
                }
            }
        }

        return numNafDigits;
    }

    //// //// //// //// //// //// //// //// //// //// //// //// ///
    /// Other utility functions
    //// //// //// //// //// //// //// //// //// //// //// //// ///

    function copyArray(/*@Array*/source, sourceIndex, /*@Array*/destination, destIndex, length) {
        /// <summary>Copies a range of elements from one array to another array.</summary>
        /// <param name="source" type="Array">Source array to copy from.</param>
        /// <param name="sourceIndex" type="Number">The index in the source array at which copying begins.</param>
        /// <param name="destination" type="Array">The array that receives the data.</param>
        /// <param name="destIndex" type="Number">The index in the destination array at which storing begins.</param>
        /// <param name="length" type="Number">The number of elements to copy.</param>
        while (length-- > 0) {
            destination[destIndex + length] = source[sourceIndex + length];
        }
    }

    function isZero(array) {
        /// <summary>Check if an array is zero. All elements are zero.</summary>
        /// <param name="array" type="Digits">UInt16Array - An array to be checked.</param>
        /// <returns type="Boolean"/>
        var i;
        for (i = 0; i < array.length; i += 1) {
            if (array[i] !== 0) {
                return false;
            }
        }
        return true;
    }

    function isEven(array) {
        /// <summary>Returns true if this number is even.</summary>
        /// <param name="array" type="Digits"/>
        /// <returns type="Boolean"/>
        return (array[0] & 0x1) === 0x0;
    }

    function sequenceEqual(left, right) {
        /// <summary>Compare two indexable collections for sequence equality.</summary>
        /// <param name="left" type="Digits">The left array.</param>
        /// <param name="right" type="Digits">The right array.</param>
        /// <returns type="Boolean">True if both arrays are the same.</returns>
        if (left.length !== right.length) {
            return false;
        }

        for (var i = 0; i < left.length; i += 1) {
            if (left[i] !== right[i]) {
                return false;
            }
        }

        return true;
    }

    function bytesToDigits(bytes) {
        /// <summary>Convert an unsigned number from big-endian bytes to little endian digits.</summary>
        /// <param name="bytes" type="Bytes">The number in unsigned big-endian byte format.</param>
        /// <returns type="Array">The digits in little-endian.</returns>

        // Construct scaler for DIGIT_NUM_BYTES, so I don't have to multiply in the loop
        var arrayLength = Math.floor((bytes.length + DIGIT_NUM_BYTES - 1) / DIGIT_NUM_BYTES);
        var array = new Array(arrayLength);
        array[0] = 0;
        var digit = 0, index = 0, scIndex = 0;
        for (var i = bytes.length - 1; i >= 0; --i) {
            digit = digit + (DIGIT_SCALER[scIndex++] * (bytes[i] & 0x0ff));
            if (DIGIT_SCALER[scIndex] === DIGIT_BASE) {
                scIndex = 0;
                array[index++] = digit;
                digit = 0;
            }
        }

        // Last digit (MSW), if there is a need
        if (digit !== 0) {
            array[index] = digit;
        }

        return array;
    }

    function digitsToBytes(digits, trim, minTrimLength) {
        /// <summary>Construct a big endian array of bytes from a litte-endian array of digits. 
        /// Always returns at least one byte and trims leading zeros.</summary>
        /// <param name="digits" type="Array">The digits in little-endian.</param>
        /// <param name="trim" type="Boolean" optional="true">Remove the leading zeros from the result (default true)</param>
        /// <param name="minTrimLength" type="Number" optional="true">Minimum length to trim down to. Valid only if trim is true. Default=1.</param>
        /// <returns type="Array">Encoded bytes in big-endian format.</returns>

        var i, j, byte1;
        var bytes = [0];

        if (typeof trim === "undefined") {
            trim = true;
        }

        for (i = 0; i < digits.length; i += 1) {
            byte1 = digits[i];
            for (j = 0; j < DIGIT_NUM_BYTES; j += 1) {
                bytes[i * DIGIT_NUM_BYTES + j] = byte1 & 0x0FF;
                byte1 = Math.floor(byte1 / 256);
            }
        }

        bytes = swapEndianness(bytes);

        if (minTrimLength === undefined) {
            minTrimLength = 1;
        }
        if (trim) {
            while (bytes.length > minTrimLength && bytes[0] === 0) {
                bytes.shift();
            }
        }

        return bytes;
    }

    function intToDigits(value, numDigits) {
        /// <summary>Construct an array of digits from a positive integer.</summary>
        /// <param name="value" type="Number" integer="true">A positive integer to be converted to digit form.</param>
        /// <param name="numDigits" type="Number" optional="true" integer="true">The number of digits to use for the digit form.</param>
        /// <returns type="Array">The given integer in digit form.</returns>

        if (typeof numDigits === "undefined") {
            if (value <= 1) {
                numDigits = 1; // Special case <= 1
            } else {
                var numBits = Math.log(value) / Math.LN2;
                numDigits = Math.ceil(numBits / DIGIT_BITS);
            }
        }

        var digitRepresentation = [];
        while (value > 0) {
            digitRepresentation.push(value % DIGIT_BASE);
            value = Math.floor(value / DIGIT_BASE);
        }

        while (digitRepresentation.length < numDigits) {
            digitRepresentation.push(0);
        }

        return digitRepresentation;
    }

    function mswIndex(digits) {
        /// <summary>Return the index of the most significant word of x, 0-indexed.
        /// If x is zero (no significant index), then -1 is returned.</summary>
        /// <param name="digits" type="Array">Digit array.</param>
        /// <returns type="Number">Index of the most significant word, or -1 if digits is zero.</returns>
        for (var i = digits.length - 1; i >= 0; i--) {
            if (digits[i] !== undefined && digits[i] !== 0) {
                return i;
            }
        }

        return (digits[0] === 0) ? -1 : 0;
    }

    function compareDigits(left, right) {
        /// <summary>Compare two digit arrays by value. Returns an integer indicating the comparison result.
        /// Digit arrays are in little endian.</summary>
        /// <param name="left" type="Array">The object on the left side of the comparison.</param>
        /// <param name="right" type="Array">The object on the right side of the comparison.</param>
        /// <returns type="Number">A value that indicates the relative order of the objects 
        ///                           being compared. The value is 0 if the items are equal, 
        ///                           negative if the left object precedes the right object,
        ///                           and positive otherwise.</returns>

        var comparisonResult = 0;
        var nLeft = mswIndex(left) + 1;
        var nRight = mswIndex(right) + 1;
        if (nLeft > nRight) {
            comparisonResult = 1;
        } else if (nRight > nLeft) {
            comparisonResult = -1;
        } else {
            while ((nLeft-- > 0) && (comparisonResult === 0)) {
                comparisonResult = left[nLeft] - right[nLeft];
            }
        }

        return comparisonResult;
    }

    function normalizeDigitArray(digits, length, pad) {
        /// <summary>Normalize a digit array by truncating any leading zeroes and adjusting its length.
        /// Set the length if given, and pad it with zeroes to that length of padding is requested.</summary>
        /// <remarks>Normalization results with a zero-indexed length of the array such that the MSW is not zero.
        /// If the final array length is zero and no non-zero digits are found, assign digits[0]=0 and set length to 1.
        /// Optionally, pad with zeroes to the given length, and set the array length.</remarks>
        /// <param name="digits" type="Array">Digit array.</param>
        /// <param name="length" type="Number" integer="true" optional="true">Output length to pad with zeroes.</param>
        /// <param name="pad" type="Boolean" optional="true">Pad with zeroes to length if true [false].</param>
        /// <returns type="Array">Resized digits array; same input object.</returns>

        // Trim. Find the trimmed length and the position to start padding from (if padding is requested).
        var i = mswIndex(digits);

        // set the length to the given length (if given) or the trimmed length
        digits.length = length || i + 1;

        // Pad to the length
        if (pad) {
            while (++i < digits.length) {
                digits[i] = 0;
            }
        }

        if (digits.length <= 0) {
            // no non-zero digits found.
            digits[0] = 0;
            digits.length = 1;
        }

        return digits;
    }

    function shiftRight(source, destination, bits, length) {
        /// <summary>Shift a big integer to the right by the given number of bits or 1 if bits is not specified,
        /// effectively dividing by two (or 2^bits) and ignoring the remainder.</summary>
        /// <param name="source" type="Array">Source digit array.</param>
        /// <param name="destination" type="Array">Destination digit array. May be the same as source.</param>
        /// <param name="bits" integer="true" optional="true">Number of bits to shift, must be less than DIGIT_BITS and greater or equal to zero. Default is 1.</param>
        /// <param name="length" optional="true" integer="true">Number of items to shift from he source array. Default is source.length.</param>
        /// <remarks>This is a numerical shift. Integers are stored in arrays in little-endian format.
        /// Thus, this function shifts an array from higher order indices into lower indices. [0] is LSW.
        /// </remarks>

        if (bits === undefined) {
            bits = 1;
        } else if (bits >= DIGIT_BITS || bits < 0) {
            throw new Error("Invalid bit count for shiftRight");
        }
        if (length === undefined) {
            length = source.length;
        }

        var n = length - 1;
        var leftShiftBitCount = DIGIT_BITS - bits;
        for (var i = 0; i < n; ++i) {
            destination[i] = ((source[i + 1] << leftShiftBitCount) | (source[i] >>> bits)) & DIGIT_MASK;
            //a[i] = high|low = low bits of a[i+1] | high bits of a[i]
        }

        destination[n] = source[n] >>> bits;
    }

    function shiftLeft(source, destination, bits, length) {
        /// <summary>Shift a number array to the left by given bits, i.e., multiply by 2^bits.</summary>
        /// <param name="source" type="Array">Source digit array.</param>
        /// <param name="destination" type="Array">Destination digit array. May be the same as source.</param>
        /// <param name="bits" integer="true" optional="true">Number of bits to shift, must be less than DIGIT_BITS and greater or equal to zero. Default is 1.</param>
        /// <param name="length" optional="true" integer="true">Number of items to shift from he source array. Default is source.length.</param>
        /// <remarks>An additional MSW digit may be added if the leftshift out from the current MSW produces a non-zero result. [0] is LSW.</remarks>

        if (bits === undefined) {
            bits = 1;
        } else if (bits >= DIGIT_BITS || bits < 0) {
            throw new Error("bit count must be smaller than DIGIT_BITS and positive in shiftLeft");
        }
        if (length === undefined) {
            length = source.length;
        }

        var rightShiftBitCount = DIGIT_BITS - bits;
        // The following line is correct. destination should remain undefined if there are no bits going into it.
        destination[length] = (source[length - 1] >>> (DIGIT_BITS - bits)) || destination[length];
        for (var i = length - 1; i > 0; i--) {
            destination[i] = ((source[i] << bits) | ((source[i - 1] >>> rightShiftBitCount))) & DIGIT_MASK;
            // a[i] = high|low = low bits of a[i] | high bits of a[i-1]
        }

        destination[0] = (source[0] << bits) & DIGIT_MASK;
    }

    //// //// //// //// //// //// //// //// //// //// //// //// //// /
    // Low level math routines
    //// //// //// //// //// //// //// //// //// //// //// //// //// /

    function add(addend1, addend2, sum) {
        /// <summary>Add two arrays of digits into a third array: sum = addend1 + addend2. Carry is recorded in the output if there is one.</summary>
        /// <param name="addend1" type="Array">The first addend.</param>
        /// <param name="addend2" type="Array">The second added.</param>
        /// <param name="sum" type="Array">The output sum buffer addend1 + addend2.</param>
        /// <returns type="Number" integer="true">If carry out then 1, otherwise 0.</returns>

        // Determine which is shorter
        var shortArray = addend1;
        var longArray = addend2;
        if (addend2.length < addend1.length) {
            shortArray = addend2;
            longArray = addend1;
        }

        // Perform the addition
        var s = shortArray.length;
        var carry = 0;
        var i;

        for (i = 0; i < s; i += 1) {
            carry += shortArray[i] + longArray[i];
            sum[i] = carry & DIGIT_MASK;
            carry = (carry >> DIGIT_BITS);
        }

        for (i = s; i < longArray.length; i += 1) {
            carry += longArray[i];
            sum[i] = carry & DIGIT_MASK;
            carry = (carry >> DIGIT_BITS);
        }

        // Set output length
        sum.length = longArray.length;

        // Is there a carry into the next digit?
        if (carry !== 0) {
            sum[i] = carry & DIGIT_MASK;
        }

        return carry;
    }

    function subtract(minuend, subtrahend, difference) {
        /// <summary>Subtraction: difference = minuend - subtrahend. Condition: minuend.length &lt;= subtrahend.length.</summary>
        /// <param name="minuend" type="Array">Minuend.</param>
        /// <param name="subtrahend" type="Array">Subtrahend.</param>
        /// <param name="difference" type="Array">The difference.</param>
        /// <returns type="Number" integer="true">Returns -1 if there is a borrow (minuend &lt; subtrahend), or 0 if there isn't (minuend &gt;= subtrahend).</returns>

        var s = subtrahend.length;
        if (minuend.length < subtrahend.length) {
            s = mswIndex(subtrahend);
            if (minuend.length < s) {
                throw new Error("Subtrahend is longer than minuend, not supported.");
            }
        }
        var i, carry = 0;
        for (i = 0; i < s; i += 1) {
            carry += minuend[i] - subtrahend[i];
            difference[i] = carry & DIGIT_MASK;
            carry = carry >> DIGIT_BITS;
        }

        // Propagate the carry by subtracting from minuend into difference
        while (i < minuend.length) {
            carry += minuend[i];
            difference[i++] = carry & DIGIT_MASK;
            carry = carry >> DIGIT_BITS;
        }

        return carry;
    }

    function multiply(multiplicant, /* @dynamic */multiplier, product) {
        /// <summary>Multiply two arrays of digits into a third array using schoolbook.</summary>
        /// <param name="multiplicant" type="Array">Multiplicand.</param>
        /// <param name="multiplier">Multiplier.</param>
        /// <param name="product" type="Array">Product = multiplicant * multiplier.</param>
        /// <returns type="Array">The result buffer; same as the product argument.</returns>

        // Single number or an array?
        var mplr = (typeof multiplier === "number") ? [multiplier] : multiplier;
        var s = Math.max(multiplicant.length, mplr.length);
        var i, j, u;

        // P <- 0
        // We only have to do this for half of result
        //   since the upper half is over-written on the first i iteration.
        for (i = 0; i < s; i += 1) {
            product[i] = 0;
        }

        // For i from 0 by 1 to s - 1 do
        for (i = 0; i < mplr.length; i += 1) {

            // 'u <- 0'
            u = 0;

            // For j from 0 by 1 to s - 1 do
            for (j = 0; j < multiplicant.length; j += 1) {

                // '(u,v) <- a_j * b_i + p_(i+j) + u'
                u += multiplicant[j] * mplr[i] + product[i + j];

                // 'p_(i+j) <- v'
                product[i + j] = (u & DIGIT_MASK) /* v */;
                u = Math.floor(u / DIGIT_BASE); // 'v <- u, u <- 0'
            }

            product[multiplicant.length + i] = (u & DIGIT_MASK);
        }

        // set product length; there may still be leading zero digits after this
        product.length = multiplicant.length + mplr.length;

        return product;
    }

    function divRem(dividend, divisor, quotient, remainder, temp1, temp2) {
        /// <summary>Computes the quotient q and remainder r when dividend is divided by
        ///   divisor.</summary>
        /// <param name="dividend" type="Array">The dividend.</param>
        /// <param name="divisor" type="Array">The divisor.</param>
        /// <param name="quotient" type="Array">Receives the quotient (n digits).</param>
        /// <param name="remainder" type="Array">Receives the remainder (n digits).</param>
        /// <param name="temp1" type="Array" optional="true">Temporary storage (n digits).</param>
        /// <param name="temp2" type="Array" optional="true">Temporary storage (n digits).</param>
        /// <remarks>This is an implementation of Figure 9-1 is Knuth's Algorithm D [Knu2 sec. 4.3.1].
        /// Throws error on division by zero.
        /// </remarks>
        var m = mswIndex(dividend) + 1;        // zero-based length
        var n = mswIndex(divisor) + 1;        // zero-based length
        var qhat, rhat, carry, p, t, i, j;

        // Check for quick results and clear out conditionals
        if (m < n) {
            // dividend < divisor. q=0, remainder=dividend
            copyArray(dividend, 0, remainder, 0, dividend.length);
            remainder.length = dividend.length;
            normalizeDigitArray(remainder);
            quotient[0] = 0;
            quotient.length = 1;
            return;
        } else if (n === 0 || (n === 1 && divisor[n - 1] === 0)) { // self-explanatory
            throw new Error("Division by zero.");
        } else if (n === 1) {
            // divisor is single digit; do a simpler division
            t = divisor[0];
            rhat = 0;
            for (j = m - 1; j >= 0; --j) {
                p = (rhat * DIGIT_BASE) + dividend[j];
                quotient[j] = (p / t) & DIGIT_MASK;
                rhat = (p - quotient[j] * t) & DIGIT_MASK;
            }
            quotient.length = m;
            normalizeDigitArray(quotient);
            remainder[0] = rhat;
            remainder.length = 1;
            return;
        }

        // Normalization step. Align dividend and divisor so that their
        // most significant digits are at the same index.
        // Shift divisor by so many bits (0..DIGIT_BITS-1) to make MSB non-zero.
        var s = DIGIT_BITS - 1 - bitScanForward(divisor[n - 1]);
        var vn = temp1 || [];
        vn.length = n;
        shiftLeft(divisor, vn, s, n);

        var un = temp2 || [];
        un.length = m;
        shiftLeft(dividend, un, s, m);
        un[m] = un[m] || 0;     // must not be undefined

        // Main division loop with quotient estimate qhat
        quotient.length = m - n + 1;
        remainder.length = n;
        for (j = m - n; j >= 0; --j) {
            // Estimate quotient qhat using two-digit by one-digit division
            // because 3-digit by 2-digit division is more complex. Then, correct qhat after this.
            qhat = Math.floor((un[j + n] * DIGIT_BASE + un[j + n - 1]) / vn[n - 1]);
            rhat = (un[j + n] * DIGIT_BASE + un[j + n - 1]) - qhat * vn[n - 1];

            // If the quotient estimate is large, reduce the quotient estimate till the following is satisfied:
            //      qhat = {un[j+n, j+n-1, j+n-2]} div {uv[n-1,n-2]}
            while (true) {
                if (qhat >= DIGIT_BASE || (qhat * vn[n - 2]) > ((rhat * DIGIT_BASE) + un[j + n - 2])) {
                    qhat = qhat - 1;
                    rhat = rhat + vn[n - 1];
                    if (rhat < DIGIT_BASE) {
                        continue;
                    }
                }

                break;
            }

            // Multiply the [shifted] divisor by the quotient estimate and subtract the product from the dividend
            // un = un - qhat*vn
            carry = 0;
            for (i = 0; i < n; i++) {
                p = qhat * vn[i];
                t = un[i + j] - carry - (p & DIGIT_MASK);
                un[i + j] = t & DIGIT_MASK;
                //carry = (p >>> DIGIT_BITS) - (t >> DIGIT_BITS);
                // Don't shift: integer shifts are defined over 32-bit numbers in JS.
                carry = Math.floor(p / DIGIT_BASE) - Math.floor(t / DIGIT_BASE);
            }

            t = un[j + n] - carry;
            un[j + n] = t & DIGIT_MASK;

            // Store the estimated quotient digit (may need correction)
            quotient[j] = qhat & DIGIT_MASK;

            // Correction needed?
            if (t < 0) {
                // quotient too big (at most by 1 divisor)
                // decrement the quotient, and add [shifted] divisor back to the running dividend (remainder)
                quotient[j] = quotient[j] - 1;

                // un = un + vn
                carry = 0;
                for (i = 0; i < n; i++) {
                    t = un[i + j] + vn[i] + carry;
                    un[i + j] = t & DIGIT_MASK;
                    carry = t >> DIGIT_BITS;
                }
                un[j + n] = (un[j + n] + carry) & DIGIT_MASK;
            }
        }

        // Denormalize the remainder (shift right by s bits).
        for (i = 0; i < n; i++) {
            remainder[i] = ((un[i] >>> s) | (un[i + 1] << (DIGIT_BITS - s))) & DIGIT_MASK;
        }

        // Compute correct lengths for the quotient and remainder
        normalizeDigitArray(quotient);
        normalizeDigitArray(remainder);
    }

    function reduce(number, modulus, remainder, temp1, temp2) {
        /// <summary>Integer reduction by a modulus to compute number mod modulus. This function uses division,
        /// and should not be used for repetitive operations.</summary>
        /// <param name="number" type="Array">Input number to reduce.</param>
        /// <param name="modulus" type="Array">Modulus to reduce the input by.</param>
        /// <param name="remainder" type="Array">Output remainder = number mod modulus.</param>
        /// <param name="temp1" type="Array" optional="true">Temporary space, optional.<param>
        /// <param name="temp2" type="Array" optional="true">Temporary space, optional.<param>
        /// <returns type="Array">The resulting remainder is in 0..modulus-1; same as "remainder".</returns>

        // TODO: More efficient reduction implementation
        var quotient = [];
        divRem(number, modulus, quotient, remainder, temp1, temp2);

        return remainder;
    }

    function modMul(multiplicant, /*@dynamic*/multiplier, modulus, product, temp1, temp2) {
        /// <summary>Moduler multiplication of two numbers for a modulus. This function uses multiply and divide method,
        /// and should not be used for repetitive operations.
        /// product can be same as multiplicant and multiplier.</summary>
        /// <param name="multiplicant" type="Array">Multiplicand.</param>
        /// <param name="multiplier">Multiplier.</param>
        /// <param name="modulus" type="Array">Modulus to reduce the product.</param>
        /// <param name="product" type="Array">Output product = multiplicant * multiplier mod modulus.</param>
        /// <param name="temp1" type="Array" optional="true">Scratch space (optional).</param>
        /// <param name="temp2" type="Array" optional="true">Scratch space (optional).</param>
        /// <returns type="Array">The resulting product in in 0..modulus-1; same as product.</returns>

        var quotient = [];
        multiply(multiplicant, multiplier, quotient);
        divRem(quotient, modulus, quotient, product, temp1, temp2);

        return product;
    }

    function eea(a, b, upp, vpp, rpp) {
        /// <summary>Extended Euclidean Algorithm, Berlekamp's version. On return
        /// b*upp - a*vpp = (-1)(k-1)*rpp.</summary>
        /// <param name="a" type="Array">The first number a.</param>
        /// <param name="b" type="Array">The second number b.</param>
        /// <param name="upp" type="Array" optional="true">a^-1 mod b if gcd=1. Optional.</param>
        /// <param name="vpp" type="Array" optional="true">b^-1 mod a if gcd=1. Optional./</param>
        /// <param name="rpp" type="Array">gcd(a,b).</param>
        /// <returns type="Number">k value.</returns>
        /// <remarks>Algebraic Coding Theory, Pages 24-30.<code>
        ///     if k is odd
        ///         a*a^-1 = 1 mod b    ---> a^-1 = b - vpp
        ///         b*b^-1 = 1 mod a    ---> b^-1 = vpp
        ///     if k is even
        ///         a*a^-1 = 1 mod b    ---> a^-1 = upp
        ///         b*b^-1 = 1 mod a    ---> b^-1 = a - upp
        /// </code></remarks>
        // Initialize rpp and rp from two inputs a and b s.t. rpp >= rp
        var rp;     // initialized from a or b
        if (isZero(a)) {    // gcd = (0,b) = b
            copyArray(b, 0, rpp, 0, b.length);
            rpp.length = b.length;
            return 0;
        } else if (isZero(b)) {     // gcd = (a,0) = a
            copyArray(a, 0, rpp, 0, a.length);
            rpp.length = a.length;
            return 0;
        } else if (compareDigits(a, b) < 0) {
            rp = a.slice(0);
            copyArray(b, 0, rpp, 0, b.length); rpp.length = b.length;
        } else {
            rp = b.slice(0);
            copyArray(a, 0, rpp, 0, a.length); rpp.length = a.length;
        }

        normalizeDigitArray(rpp);
        normalizeDigitArray(rp);
        var q = new Array(rpp.length);
        var r = new Array(rpp.length);

        var v = new Array(rpp.length);
        var vppPresent = vpp !== undefined;
        var vp;
        if (vppPresent) {
            vp = new Array(rpp.length);
            vp[0] = 1; vp.length = 1;
            vpp[0] = 0; vpp.length = 1;
        }

        var up;
        var u = new Array(rpp.length);
        var uppPresent = upp !== undefined;
        if (uppPresent) {
            up = new Array(rpp.length);
            up[0] = 0; up.length = 1;
            upp[0] = 1; upp.length = 1;
        }

        // k starts at -1 so that on return, it is >=0.
        // In the follwing discussion, assume a<b and this is computing a^-1 mod b where (a,b)=1, a<b.
        // Initialize rp=a, rpp=b.
        // The integer k keeps track of the sign of a^-1 (0 = positive) in b = q*a + r with 0 = q*a + r mod b
        // such that for q=a^-1 and r=1 (which is gcd=1 for inverse to exist), we have q*a = (-1)^k mod b.
        // Thus, for odd k, q*a = -1 mod b, and a^-1 = b-q as in the description.
        var k = -1;

        // At the end, gcd = rp = (a,b)
        var upp_out = upp;
        var vpp_out = vpp;
        var rpp_out = rpp;
        var save;

        // Recycle u and v as temp variables in division (divRem).
        while (!isZero(rp)) {
            // rpp = q*rp + r: compute q, r
            divRem(rpp, rp, q, r, u, v);

            if (uppPresent) {
                // u = q*up + upp
                // upp=up, up=u, u=upp
                multiply(q, up, u);
                add(u, upp, u);
                normalizeDigitArray(u);
                save = upp;
                upp = up;
                up = u;
                u = save;
            }

            if (vppPresent) {
                // v = q*vp + vpp
                // vpp=vp, vp=v, v=vpp
                multiply(q, vp, v);
                add(v, vpp, v);
                normalizeDigitArray(v);
                save = vpp;
                vpp = vp;
                vp = v;
                v = save;
            }

            // rpp=rp, rp=r, r=rpp
            save = rpp;
            rpp = rp;
            rp = r;
            r = save;

            ++k;
        }

        // copy to output upp, vpp, rpp
        if (uppPresent) {
            copyArray(upp, 0, upp_out, 0, upp.length); upp_out.length = upp.length;
        }
        if (vppPresent) {
            copyArray(vpp, 0, vpp_out, 0, vpp.length); vpp_out.length = vpp.length;
        }
        copyArray(rpp, 0, rpp_out, 0, rpp.length); rpp_out.length = rpp.length;

        return k;
    }

    function gcd(a, b, output) {
        /// <summary>Compute greatest common divisor or a and b.</summary>
        /// <param name="a" type="Array">First integer input.</param>
        /// <param name="b" type="Array">Second integer input.</param>
        /// <param name="output" type="Array" optional="true">GCD output (optional).</param>
        /// <returns type="Array">GCD(a,b), the same object as the output parameter if given or a new object otherwise.</returns>
        var aa = a;
        var bb = b;
        if (compareDigits(a, b) > 0) {
            aa = b;
            bb = a;
        }

        eea(aa, bb, undefined, undefined, output);
        return normalizeDigitArray(output);
    }

    function modInv(a, n, aInv) {
        /// <summary>Modular multiplicative inverse a^-1 mod n.</summary>
        /// <param name="a" type="Array">The number to invert. Condition: a &lt; n, or the result would be n^-1 mod a.</param>
        /// <param name="n" type="Array">The modulus.</param>
        /// <param name="aInv" type="Array" optional="true">a^-1 mod n (optional).</param>
        /// <returns type="Array">a^-1 mod n. Same as the aInv parameter if the parameter is specified.</returns>
        //var gcd = eea(a, n, inv);
        var upp = new Array(n.length);
        var vpp = new Array(n.length);
        var rpp = new Array(n.length);
        var k = eea(a, n, vpp, upp, rpp);

        aInv = aInv || [];
        if (compareDigits(rpp, One) !== 0) {
            aInv[0] = NaN;
            aInv.length = 1;
        } else {
            // gcd = 1, there is an inverse.
            // Compute inverse from Berlekamp's EEA outputs.
            if ((k & 1) === 1) {
                subtract(n, upp, aInv);
            } else {
                copyArray(upp, 0, aInv, 0, upp.length); aInv.length = upp.length;
            }
            normalizeDigitArray(aInv);
        }

        return aInv;
    }

    function modExp(base, exponent, modulus, result) {
        /// <summary>Modular exponentiation in an integer group.</summary>
        /// <param name="base" type="Array">The base of the exponentiation.</param>
        /// <param name="exponent" type="Array">The exponent.</param>
        /// <param name="modulus" type="Array">Modulus to reduce the result.</param>
        /// <param name="result" type="Array" optional="true">Output element that takes the modular exponentiation result (optional).</param>
        /// <returns type="Array">Modular exponentiation result, same as <paramref name="result"/> if not null, or a new object.</returns>

        result = result || [];

        // If exponent is 0 return 1
        if (compareDigits(exponent, Zero) === 0) {
            result[0] = 1;
        } else if (compareDigits(exponent, One) === 0) {
            // If exponent is 1 return valueElement
            copyArray(base, 0, result, 0, base.length);
            result.length = base.length;
        } else {
            var montmul = new MontgomeryMultiplier(modulus);
            normalizeDigitArray(base, montmul.s, true);
            montmul.modExp(
                base,
                exponent,
                result);
            result.length = modulus.length;
        }

        return result;
    }

    function MontgomeryMultiplier(modulus) {
        /// <summary>Construct a new montgomeryMultiplier object with the given modulus.</summary>
        /// <param name="modulus" type="Array">A prime modulus in little-endian digit form</param>
        /// <remarks>Montgomery Multiplier class
        /// This class implements high performance montgomery multiplication using 
        /// CIOS, as well as modular exponentiation.</remarks>

        function computeM0Prime(m0) {
            /// <summary>Compute m' = -(m^-1) mod b, 16 bit digits. Based on Tolga Acar's code.</summary>
            /// <param name="m0" type="Number" integer="true">Digit m.</param>
            /// <returns type="Number">Digit m'.</returns>
            var m0Pr = 1;
            var a = 2;
            var b = 3;
            var c = b & m0;

            for (var i = 2; i <= DIGIT_BITS; i += 1) {
                if (a < c) {
                    m0Pr += a;
                }

                a = a << 1;
                b = (b << 1) | 1;
                c = m0 * m0Pr & b;
            }

            var result = (~m0Pr & DIGIT_MASK) + 1;
            return result;
        }

        function montgomeryMultiply(multiplicant, multiplier, result, ctx) {
            /// <summary>Montgomery multiplication with the CIOS method.</summary>
            /// <param name="multiplicant" type="Array">Multiplicant.</param>
            /// <param name="multiplier" type="Array">Multiplier.</param>
            /// <param name="result" type="Array">Computed result multiplicant * multiplier * r^-1 mod n.</param>
            /// <param name="ctx" type="MontgomeryMultiplier" optional="true">Context (optional = this).</param>

            ctx = ctx || this;

            // Upper digits of result
            var resultHigh = 0;

            // Precompute offsets
            var s = ctx.m.length;
            var sMinus1 = s - 1;

            // Local cache of m0, m', digitmask, digitbits
            var mPrime = ctx.mPrime;
            var m0 = ctx.m0;
            var left0 = multiplicant[0];

            var uv = 0, rightI, q, i, j, k;

            // Clear the result array
            for (i = 0; i < s; i += 1) {
                result[i] = 0;
            }

            for (i = 0; i < s; i += 1) {

                rightI = multiplier[i]; // Cache array value

                // 'u <- 0'

                // ---- UNROLL FIRST ITERATION (j == 0) ----
                uv = left0 * rightI + result[0];
                result[0] = uv & DIGIT_MASK;
                uv = Math.floor(uv / DIGIT_BASE);

                // ---- REMAINING ITERATIONS ----
                for (j = 1; j < s; j += 1) {

                    // '(u,v) <- a_j * b_i + z_j + u'
                    // uv = uv >>> DIGIT_BITS;
                    // Don't shift: JS supports shifts over 32-bit integers, only.
                    uv = multiplicant[j] * rightI + result[j] + uv;
                    result[j] = uv & DIGIT_MASK;
                    uv = Math.floor(uv / DIGIT_BASE);
                }
                // -------------------------------

                // '(u,v) <- z_s + u'.
                // 'z_s <- v'.
                // 'z_s+1 <- u'.
                resultHigh = resultHigh + uv;

                // 'q <- z_0 * m'  mod  digitBase
                q = (result[0] * mPrime) & DIGIT_MASK;

                // '(u,v) <- z_0 + m_0 * q'
                uv = Math.floor((result[0] + (m0 * q)) / DIGIT_BASE);

                // For j from 1 by 1 to s-1 
                for (j = 1, k = 0; j < s; j += 1, k++) {
                    // '(u,v) <- m_j * q + z_j + u'
                    uv = ctx.m[j] * q + result[j] + uv;

                    // 'z_j-1 <- v'
                    result[k] = uv & DIGIT_MASK;
                    uv = Math.floor(uv / DIGIT_BASE);
                }

                // '(u,v) <- z_s + u'.
                // 'z_s-1 <- v'.
                // 'z_s <- z_s+1 + u'.
                resultHigh += uv;
                result[sMinus1] = resultHigh & DIGIT_MASK;
                resultHigh = Math.floor(resultHigh / DIGIT_BASE);
            }

            // Quick check to see if Z < M
            if (!(resultHigh === 0 && result[sMinus1] < ctx.m[sMinus1])) {
                // Subtract modulus
                var resultMinusM = ctx.temp1;
                var carry = 0;
                for (i = 0; i < s; i += 1) {
                    carry = result[i] - ctx.m[i] + (carry >> DIGIT_BITS);
                    resultMinusM[i] = carry & DIGIT_MASK;
                }

                carry = (resultHigh & DIGIT_MASK) + (carry >> DIGIT_BITS);
                carry = (resultHigh >>> DIGIT_BITS) + (carry >> DIGIT_BITS);

                if ((carry >> DIGIT_BITS) !== -1) {
                    // Return resultMinusM
                    for (i = 0; i < s; i += 1) {
                        result[i] = resultMinusM[i];
                    }

                    return;
                }
            }
        }

        function convertToMontgomeryForm(/*@type(Digits)*/digits) {
            /// <summary>Convert the digits in standard form to Montgomery residue representation.</summary>
            /// <param name="digits" type="Array">Input digits to convert, and also the output converted digits.</param>
            var result = createArray(digits.length);

            this.montgomeryMultiply(digits, this.rSquaredModm, result);
            for (var i = 0; i < this.s; i += 1) {
                digits[i] = result[i];
            }
        }

        function convertToStandardForm(digits) {
            /// <summary>Convert from Montgomery residue representation to the standard form.</summary>
            /// <param name="digits" type="Array">Input digits to convert, and also the output converted digits.</param>
            this.montgomeryMultiply(digits, this.one, this.temp1);
            for (var i = 0; i < this.s; i += 1) {
                digits[i] = this.temp1[i];
            }
        }

        function modExp(base, exponent, result) {
            /// <summary>Compute base to exponent mod m into result.</summary>
            /// <param name="base" type="Array">Base of length s in the context.</param>
            /// <param name="exponent" type="Array">Exponent.</param>
            /// <param name="result" type="Array">Output as base raised to exponent, and reduced to the modulus in the context.</param>
            /// <returns type="Array">result base^exponent mod m; the same result object.</returns>

            // Skip leading zero bits in the exponent
            // The total number of bits to scan in the exponent must be an integral multiple of
            // the number of bits to use in the exponent.
            var i;
            var expBitsToScan = 2;  // scan 2 bits at a time
            var expMask = DIGIT_MASK >>> (DIGIT_BITS - expBitsToScan);
            for (i = exponent.length - 1; i > 0 && exponent[i] === 0; --i) { }
            var bitsToScan = i * DIGIT_BITS + bitScanForward(exponent[i]) + 1;
            bitsToScan = bitsToScan + (expBitsToScan - (bitsToScan % expBitsToScan));
            var shiftAmt = (bitsToScan % DIGIT_BITS) - expBitsToScan;
            if (shiftAmt < 0) {
                shiftAmt += DIGIT_BITS;
            }
            var mask = expMask << shiftAmt;

            // Prepare the precomputation table of base for k bits
            // base[0..3] = [r, r*base, r*base^2, r*base^3] mod m
            for (i = 1; i < baseTable.length; ++i) {
                modMul(baseTable[i - 1], base, this.m, baseTable[i], temp1, temp2);
                normalizeDigitArray(baseTable[i], this.s, true);
            }

            // a is the running result: a = 1*r mod m
            // TODO: Skip the first loop iteration below to avoid 1*1 mod m (minor optimization)
            var fourthPower = new Array(this.s);
            var squared = result;
            var partialResult = temp2;
            copyArray(this.rModM, 0, partialResult, 0, this.s);

            // Scan the exponent expBitsToScan bits at a time
            var tableIndex;
            while (bitsToScan > 0) {
                // result <- Mont(a, a);
                // result <- Mont(result, a);
                this.montgomeryMultiply(partialResult, partialResult, squared);
                this.montgomeryMultiply(squared, squared, fourthPower);

                // tableIndex <- the current bits of the scanned exponent
                tableIndex = (exponent[Math.floor((bitsToScan - 1) / DIGIT_BITS)] & mask) >>> shiftAmt;

                // aDigits = result * table[tableIndex]
                this.montgomeryMultiply(fourthPower, baseTable[tableIndex], partialResult);

                bitsToScan = bitsToScan - expBitsToScan;
                shiftAmt = shiftAmt - expBitsToScan;
                mask = mask >>> expBitsToScan;
                if (mask === 0) {
                    mask = expMask << (DIGIT_BITS - expBitsToScan);
                    shiftAmt = DIGIT_BITS - expBitsToScan;
                }
            }

            // result = Mont(a, 1)
            this.montgomeryMultiply(partialResult, this.one, result);
            return result;
        }

        // Modulus
        var m = modulus;

        // First digit of modulus
        var m0 = m[0];

        // Operand size (number of digits)
        var s = m.length;

        // The number one - used by modpow
        var one = createArray(s);
        one[0] = 1;

        // Compute m' = -(m^-1) mod b used by CIOS
        var mPrime = computeM0Prime(m0);

        // Create r and compute r mod m
        // Since we are base b integers of length s, we want
        // 'r = b^n = b^s'.
        var quotient = createArray(2 * s + 1);
        var rRemainder = createArray(s + 1);        // becomes rModM
        var temp1 = createArray(2 * s + 1);
        var temp2 = createArray(2 * s + 1);
        var rDigits = rRemainder;
        rDigits[s] = 1;
        divRem(
            rDigits,
            m,
            quotient,
            rRemainder,
            temp1,
            temp2);
        var rModM = normalizeDigitArray(rRemainder, s, true);

        // Compute R^2 mod m
        var rSquaredModm = createArray(2 * s + 1);
        var rSquaredDigits = rSquaredModm;
        rSquaredDigits[s * 2] = 1;
        divRem(
            rSquaredDigits,
            m,
            quotient,
            rSquaredModm,
            temp1,
            temp2);
        normalizeDigitArray(rSquaredModm, s, true);

        // Ready to do MontMul now - compute R^3
        var rCubedModm = createArray(s);
        var ctx = { m: m, mPrime: mPrime, m0: m0, temp1: temp1 };
        montgomeryMultiply(
            rSquaredModm,
            rSquaredModm,
            rCubedModm,
            ctx);

        // Allocate space for multi-bit modular exponentiation
        var baseTable = new Array(4);
        baseTable[0] = rModM;
        baseTable[1] = new Array(s);
        baseTable[2] = new Array(s);
        baseTable[3] = new Array(s);

        // Return a per-instance context for Montgomery multiplier.
        // There is no need to use the "new" keyword when using this function.
        return {
            // Modulus
            m: modulus,

            // First digit of modulus
            m0: m0,

            // Compute m' = -(m^-1) mod b used by CIOS
            mPrime: mPrime,

            rSquaredModm: rSquaredModm,
            s: s,
            rModM: rModM,
            rCubedModm: rCubedModm,
            one: one,
            temp1: temp1,

            // Functions
            convertToMontgomeryForm: convertToMontgomeryForm,
            convertToStandardForm: convertToStandardForm,
            montgomeryMultiply: montgomeryMultiply,
            modExp: modExp
        };
    }

    function IntegerGroup (modulusBytes) {
        /// <summary>Construct a new IntegerGroup object with the given modulus.</summary>
        /// <param name="modulusBytes" type="Array">A big-endian number to represent the modulus in a byte array.</param>
        /// <remarks>This class represents the set of integers mod n. It is meant to be used in
        /// a variety of situations, for example to perform operations in the additive
        /// or multiplicative groups mod n. The modulus can be an arbitrary integer and
        /// in the case that it is a prime p then the integer group is the field Fp. The 
        /// user should be aware of what type of object the given modulus produces, and
        /// thus which operations are valid.</remarks>

        // Modulus
        var m_modulus = bytesToDigits(modulusBytes);

        // Length of an element in digits
        var m_digitWidth = m_modulus.length;

        // Setup numeric constants
        var m_zero = intToDigits(0, m_digitWidth);
        var m_one = intToDigits(1, m_digitWidth);

        // Temp storage.
        // Allocation in js is very slow, we use these temp arrays to avoid it.
        var temp0 = createArray(m_digitWidth);
        var temp1 = createArray(m_digitWidth);

        // Create montgomery multiplier object
        var montmul = new MontgomeryMultiplier(m_modulus);

        function createElementFromBytes(bytes) {
            /// <summary>Create a new element object from a byte value.</summary>
            /// <param name="bytes" type="Array">Desired element in big-endian format in an array of bytes.</param>
            /// <returns type="IntegerGroupElement">An element object representing the given element.</returns>            
            var digits = bytesToDigits(bytes);

            // Check size of the new element
            if (cryptoMath.compareDigits(digits, this.m_modulus) >= 0) {
                // Too many digits
                throw new Error("The number provided is not an element of this group");
            }

            // expand to the group modulus length
            normalizeDigitArray(digits, this.m_digitWidth, true);
            return IntegerGroupElement(digits, this);
        }

        function createElementFromInteger(integer) {
            /// <summary>Create a new element object from an integer value.</summary>
            /// <param name="integer" type="Number" integer="true">Desired element as an integer.</param>
            /// <returns type="IntegerGroupElement">An element object representing the given element.</returns>
            var digits = intToDigits(integer, this.m_digitWidth);
            return IntegerGroupElement(digits, this);
        }

        function createElementFromDigits(digits) {
            /// <summary>Create a new element object from a digit array.</summary>
            /// <param name="digits" type="Array">Desired element as a digit array.</param>
            /// <returns type="IntegerGroupElement">Object initialized with the given value.</returns>
            cryptoMath.normalizeDigitArray(digits, this.m_digitWidth, true);
            return IntegerGroupElement(digits, this);
        }

        function equals(otherGroup) {
            /// <summary>Return true if the given object is equivalent to this one.</summary>
            /// <param name="otherGroup" type="IntegerGroup"/>)
            /// <returns type="Boolean">True if the given objects are equivalent.</returns>

            return compareDigits(this.m_modulus, otherGroup.m_modulus) === 0;
        }

        function add(addend1, addend2, sum) {
            /// <summary>Add this element to another element.</summary>
            /// <param name="addend1" type="IntegerGroupElement"/>
            /// <param name="addend2" type="IntegerGroupElement"/>
            /// <param name="sum" type="IntegerGroupElement"/>

            var i;
            var s = this.m_digitWidth;
            var result = sum.m_digits;
            cryptoMath.add(addend1.m_digits, addend2.m_digits, result);
            var mask = compareDigits(result, this.m_modulus) >= 0 ? DIGIT_MASK : 0;

            // Conditional reduction by the modulus (one subtraction, only) only if the sum>modulus in almost constant time.
            // The result is unmodified if the computed sum < modulus already.
            var carry = 0;
            for (i = 0; i < s; i += 1) {
                carry = result[i] - (this.m_modulus[i] & mask) + carry;
                result[i] = carry & DIGIT_MASK;
                carry = (carry >> DIGIT_BITS);
            }

            result.length = s;
        }

        function subtract(leftElement, rightElement, outputElement) {
            /// <summary>Subtract an element from another element.</summary>
            /// <param name="leftElement" type="IntegerGroupElement"/>
            /// <param name="rightElement" type="IntegerGroupElement"/>
            /// <param name="outputElement" type="IntegerGroupElement"/>

            var i, s = this.m_digitWidth;
            var result = outputElement.m_digits;
            var carry = cryptoMath.subtract(leftElement.m_digits, rightElement.m_digits, outputElement.m_digits);

            // Final borrow?
            if (carry === -1) {
                carry = 0;
                for (i = 0; i < s; i += 1) {
                    carry += result[i] + this.m_modulus[i];
                    result[i] = carry & DIGIT_MASK;
                    carry = carry >> DIGIT_BITS;
                }
            }
        }

        function inverse(element, outputElement) {
            /// <summary>Compute the modular inverse of the given element.</summary>
            /// <param name="element" type="IntegerGroupElement">The element to be inverted.</param>
            /// <param name="outputElement" type="IntegerGroupElement">Receives the inverse element.</param>
            cryptoMath.modInv(element.m_digits, this.m_modulus, outputElement.m_digits);
        }

        function multiply(multiplicant, multiplier, product) {
            /// <summary>Multiply an element by another element in the integer group.</summary>
            /// <param name="multiplicant" type="IntegerGroupElement">Multiplicand.</param>
            /// <param name="multiplier" type="IntegerGroupElement">Multiplier.</param>
            /// <param name="product" type="IntegerGroupElement">Product reduced by the group modulus.</param>
            /// <returns type="Array">Same as <paramref name="product"/>.</returns>

            return cryptoMath.modMul(multiplicant.m_digits, multiplier.m_digits, this.m_modulus, product.m_digits, temp0, temp1);
        }

        function modexp(valueElement, exponent, outputElement) {
            /// <summary>Modular exponentiation in an integer group.</summary>
            /// <param name="valueElement" type="IntegerGroupElement">The base input to the exponentiation.</param>
            /// <param name="exponent" type="Array">The exponentas an unsigned integer.</param>
            /// <param name="outputElement" type="IntegerGroupElement" optional="true">Output element that takes the modular exponentiation result.</param>
            /// <returns type="IntegerGroupElement">Computed result. Same as <paramref name="outputElement"/> if not null, a new object otherwise.</returns>

            outputElement = outputElement || IntegerGroupElement([], this);

            // If exponent is 0 return 1
            if (compareDigits(exponent, m_zero) === 0) {
                outputElement.m_digits = intToDigits(1, this.m_digitWidth);
            } else if (compareDigits(exponent, m_one) === 0) {
                // If exponent is 1 return valueElement
                for (var i = 0; i < valueElement.m_digits.length; i++) {
                    outputElement.m_digits[i] = valueElement.m_digits[i];
                }
                outputElement.m_digits.length = valueElement.m_digits.length;
            } else {
                this.montmul.modExp(
                    valueElement.m_digits,
                    exponent,
                    outputElement.m_digits);
                outputElement.m_digits.length = this.montmul.s;
            }

            return outputElement;
        }

        function IntegerGroupElement(digits, group) {
            /// <summary>IntegerGroupElement inner class.
            /// Create a new integer element mod n.</summary>
            /// <param name="digits" type="Array">An array of digits representing the element.</param>
            /// <param name="group" type="IntegerGroup">The parent group to which this element belongs.</param>
            /// <remarks>The value given in digits 
            /// must be &gt;= 0 and &;lt; modulus. Note that the constructor should not be 
            /// visible to the user, user should use group.createElementFromDigits(). This way we 
            /// can use any digit size and endian-ness we wish internally, operating in
            /// our chosen representation until such time as the user wishes to produce
            /// a byte array as output, which will be done by calling 
            /// toByteArrayUnsigned(). Note that other properties and methods are meant
            /// to be "public" of course and thus callable by the user.</remarks>

            return {
                // Variables
                m_digits: digits,
                m_group: group,

                // Functions
                equals: function (element) {
                    /// <summary>Compare an elements to this for equality.</summary>
                    /// <param name="element" type="IntegerGroupElement">Element to compare.</param>
                    /// <returns>True if elements are equal, false otherwise.</returns>
                    return (compareDigits(this.m_digits, element.m_digits) === 0) &&
                        this.m_group.equals(this.m_group, element.m_group);
                }
            };
        }

        return {
            // Variables
            m_modulus: m_modulus,
            m_digitWidth: m_digitWidth,
            montmul: montmul,

            // Functions
            createElementFromInteger: createElementFromInteger,
            createElementFromBytes: createElementFromBytes,
            createElementFromDigits: createElementFromDigits,
            equals: equals,
            add: add,
            subtract: subtract,
            multiply: multiply,
            inverse: inverse,
            modexp: modexp
        };
    }

    return {
        DIGIT_BITS: DIGIT_BITS,
        DIGIT_NUM_BYTES: DIGIT_NUM_BYTES,
        DIGIT_MASK: DIGIT_MASK,
        DIGIT_BASE: DIGIT_BASE,
        DIGIT_MAX: DIGIT_MAX,
        Zero: Zero,
        One: One,

        normalizeDigitArray: normalizeDigitArray,
        swapEndianness: swapEndianness,
        bytesToDigits: bytesToDigits,
        stringToDigits: stringToDigits,
        digitsToString: digitsToString,
        intToDigits: intToDigits,
        digitsToBytes: digitsToBytes,
        sequenceEqual: sequenceEqual,
        isZero: isZero,
        isEven: isEven,

        powerOfTwo: powerOfTwo,
        shiftRight: shiftRight,
        shiftLeft : shiftLeft,
        compareDigits: compareDigits,
        computeBitArray: computeBitArray,
        bitLength: highestSetBit,
        computeNAF: computeNAF,
        IntegerGroup: IntegerGroup,

        add: add,
        subtract: subtract,
        multiply: multiply,
        divRem: divRem,
        reduce: reduce,
        modInv: modInv,
        modExp: modExp,
        modMul: modMul,
        MontgomeryMultiplier: MontgomeryMultiplier,
        gcd: gcd
    };
}

var cryptoMath = cryptoMath || MsrcryptoMath();

//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// cryptoECC.js ==================================================================================
/// Implementation of Elliptic Curve math routines for cryptographic applications.

/// #region JSCop/JsHint
/* global createProperty */
/* global cryptoMath */
/* jshint -W016 */ /* allows bitwise operators */
/* jshint -W052 */ /* allows not operator */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="random.js" />

/// <dictionary>alg,bitmasks,coord,De-montgomeryized,digitbits,digitmask,divrem,dont,Elt,endian-ness,endian,gcd,goto,gotta,Int,Jacobi,Jacobian,Legendre,mlen,Modm,modpow,montgomerized,montgomeryize,montgomeryized,montmul,mul,param,Pomerance,povar,precompute,Pseudocode,Tolga,typeof,Uint,unrollsentinel,wil,Xout,Xout-t,Yout,Zout</dictionary>
/// <dictionary>aequals,Eshift,idx,Lsbit,Minust,mult,myelement,myresult,naf,Neg,Nist,numcopy,Obj,onemontgomery,Precomputation,Res,swaptmp,Tmp,xbytes,ybytes</dictionary>

/// #endregion JSCop/JsHint

function MsrcryptoECC() {
    /// <summary>Elliptic Curve Cryptography (ECC) funcions.</summary>

    // Create an array, mimics the constructors for typed arrays.
    function createArray(/*@dynamic*/parameter) {
        var i, array = null;
        if (!arguments.length || typeof arguments[0] === "number") {
            // A number.
            array = [];
            for (i = 0; i < parameter; i += 1) {
                array[i] = 0;
            }
        } else if (typeof arguments[0] === "object") {
            // An array or other index-able object
            array = [];
            for (i = 0; i < parameter.length; i += 1) {
                array[i] = parameter[i];
            }
        }
        return array;
    }

    var btd = cryptoMath.bytesToDigits;
    var utils = msrcryptoUtilities;

    var EllipticCurveFp = function (p1, a1, b1, order, gx, gy) {
        /// <param name="p1" type="Digits"/>
        /// <param name="a1" type="Digits"/>
        /// <param name="b1" type="Digits"/>
        /// <param name="order" type="Digits"/>
        /// <param name="gx" type="Digits"/>
        /// <param name="gy" type="Digits"/>
        /// <returns type="EllipticCurveFp"/>

        var fieldStorageBitLength = p1.length;

        var generator = EllipticCurvePointFp(this, false, gx, gy, null, false);

        return {
            p: p1,                  // field prime
            a: a1,                  // Weierstrass coefficient a
            b: b1,                  // Weierstrass coefficient b
            order: order,           // EC group order
            generator: generator,   // EC group generator
            allocatePointStorage: function () {
                return EllipticCurvePointFp(
                    this,
                    false,
                    cryptoMath.intToDigits(0, fieldStorageBitLength),
                    cryptoMath.intToDigits(0, fieldStorageBitLength)
                    );
            },
            createPointAtInfinity: function () {
                return EllipticCurvePointFp(
                    this,
                    true,
                    cryptoMath.intToDigits(0, fieldStorageBitLength),
                    cryptoMath.intToDigits(0, fieldStorageBitLength)
                    );
            }
        };
    };
    var createANeg3Curve = function (p, b, order, gx, gy) {
        /// <param name="p" type="Digits"/>
        /// <param name="b" type="Digits"/>
        /// <param name="order" type="Digits"/>
        /// <param name="gx" type="Digits"/>
        /// <param name="gy" type="Digits"/>

        var a = cryptoMath.intToDigits(3, p.length);
        cryptoMath.subtract(p, a, a);
        var curve = EllipticCurveFp(p, a, b, order, gx, gy);
        curve.generator.curve = curve;
        return curve;
    };

    var curvesData = {
        "256": { size: 32, data: "/////wAAAAEAAAAAAAAAAAAAAAD///////////////9axjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgS/////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="},
        "384": { size: 48, data: "//////////////////////////////////////////7/////AAAAAAAAAAD/////szEvp+I+5+SYjgVr4/gtGRgdnG7+gUESAxQIj1ATh1rGVjmNii7RnSqFyO3T7Crv////////////////////////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlzqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f"},
        "521": { size: 32, data: "Af//////////////////////////////////////////////////////////////////////////////////////UZU+uWGOHJofkpohoLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz34g9LDTx70Uf1GtQPwAB///////////////////////////////////////////6UYaHg78vlmt/zAFI9wml0Du1ybiJnEeuu2+3HpE4ZAnGhY4GtwQE6c2ePstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUA==" }
    };

    var createP256 = function () {
        return createPCurve("256");
    };

    var createP384 = function () {
        return createPCurve("384");
    };

    var createP521 = function () {
        return createPCurve("521");
    };

    var createPCurve = function (curveSize) {

        var cd = utils.unpackData(curvesData[curveSize].data, curvesData[curveSize].size);

        var newCurve = createANeg3Curve(
            btd(cd[0]), // P
            btd(cd[1]), // B
            btd(cd[2]), // Order
            btd(cd[3]), // gX
            btd(cd[4])  // gy
        );

        newCurve.name = "P-" + curveSize;

        return newCurve;

    };

    var createBN254 = function () {

        return EllipticCurveFp(
            cryptoMath.stringToDigits("16798108731015832284940804142231733909889187121439069848933715426072753864723", 10), // 'p'
            cryptoMath.intToDigits(0, 16), // 'a'
            cryptoMath.intToDigits(2, 16), // 'b'
            cryptoMath.stringToDigits("16798108731015832284940804142231733909759579603404752749028378864165570215949", 10), // 'order'
            cryptoMath.stringToDigits("16798108731015832284940804142231733909889187121439069848933715426072753864722", 10), // 'gx = -1'
            cryptoMath.intToDigits(1, 16) // 'gy = 1'
            );
    };
    var EllipticCurvePointFp = function (curve, isInfinity, x, y, z, isInMontgomeryForm) {
        /// <param name="curve" type="EllipticCurveFp"/>
        /// <param name="isInfinity" type="Boolean"/>
        /// <param name="x" type="Digits"/>
        /// <param name="y" type="Digits"/>
        /// <param name="z" type="Digits" optional="true"/>
        /// <param name="isInMontgomeryForm" type="Boolean" optional="true"/>
        /// <returns type="EllipticCurvePointFp"/>

        var returnObj;

        // 'optional' parameters
        if (typeof z === "undefined") {
            z = null;
        }

        if (typeof isInMontgomeryForm === "undefined") {
            isInMontgomeryForm = false;
        }

        function equals(/*@type(EllipticCurvePointFp)*/ellipticCurvePointFp) {
            /// <param name="ellipticCurvePointFp" type="EllipticCurvePointFp"/>

            // If null
            if (!ellipticCurvePointFp) {
                return false;
            }

            // Infinity == infinity
            if (returnObj.isInfinity && ellipticCurvePointFp.isInfinity) {
                return true;
            }

            // Otherwise its member-wise comparison

            if (returnObj.z === null && ellipticCurvePointFp.z !== null) {
                return false;
            }

            if (returnObj.z !== null && ellipticCurvePointFp.z === null) {
                return false;
            }

            if (returnObj.z === null) {
                return (cryptoMath.sequenceEqual(returnObj.x, ellipticCurvePointFp.x) &&
                         cryptoMath.sequenceEqual(returnObj.y, ellipticCurvePointFp.y) &&
                         returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm);
            }

            return (cryptoMath.sequenceEqual(returnObj.x, ellipticCurvePointFp.x) &&
                    cryptoMath.sequenceEqual(returnObj.y, ellipticCurvePointFp.y) &&
                    cryptoMath.sequenceEqual(returnObj.z, ellipticCurvePointFp.z) &&
                    returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm);
        }

        function copyTo(/*@type(EllipticCurvePointFp)*/ source, /*@type(EllipticCurvePointFp)*/ destination) {
            /// <param name="source" type="EllipticCurvePointFp"/>
            /// <param name="destination" type="EllipticCurvePointFp"/>

            destination.curve = source.curve;
            destination.x = source.x.slice();
            destination.y = source.y.slice();

            if (source.z !== null) {
                destination.z = source.z.slice();
            } else {
                destination.z = null;
            }

            setterSupport || (destination.isAffine = source.isAffine);
            destination.isInMontgomeryForm = source.isInMontgomeryForm;
            destination.isInfinity = source.isInfinity;

            if (!destination.equals(source)) {
                throw new Error("Instances should be equal.");
            }

        }

        function clone() {
            if (returnObj.z === null) {  // isAffine

                return EllipticCurvePointFp(
                    returnObj.curve,
                    returnObj.isInfinity,
                    createArray(returnObj.x),
                    createArray(returnObj.y),
                    null,
                    returnObj.isInMontgomeryForm);
            } else {

                return EllipticCurvePointFp(
                    returnObj.curve,
                    returnObj.isInfinity,
                    createArray(returnObj.x),
                    createArray(returnObj.y),
                    createArray(returnObj.z),
                    returnObj.isInMontgomeryForm);
            }
        }

        returnObj = /*@static_cast(EllipticCurvePointFp)*/ {
            equals: function (ellipticCurvePointFp) {
                return equals(ellipticCurvePointFp);
            },
            copy: function (destination) {
                copyTo(this, destination);
                return;
            },
            clone: function () {
                return clone();
            }
        };

        createProperty(returnObj, "curve", curve, function () { return curve; }, function (val) { curve = val; });

        createProperty(returnObj, "x", x, function () { return x; }, function (val) { x = val; });
        createProperty(returnObj, "y", y, function () { return y; }, function (val) { y = val; });
        createProperty(returnObj, "z", z, function () { return z; }, function (val) { z = val; });

        createProperty(returnObj, "isInMontgomeryForm", isInMontgomeryForm, function () { return isInMontgomeryForm; }, function (val) { isInMontgomeryForm = val; });
        createProperty(returnObj, "isInfinity", isInfinity, function () { return isInfinity; }, function (val) { isInfinity = val; });
        createProperty(returnObj, "isAffine", (z === null), function () { return (z === null); });

        return returnObj;
    };
    var EllipticCurveOperatorFp = function (/*@type(EllipticCurveFp)*/curve) {
        /// <param name="curve" type="EllipticCurveFp"/>

        // Store a reference to the curve.
        var m_curve = curve;

        var fieldElementWidth = curve.p.length;

        var montgomeryMultiplier = cryptoMath.MontgomeryMultiplier(curve.p);

        // Pre-compute and store the montgomeryized form of A, and set our
        // zero flag to determine whether or not we should use implementations
        // optimized for A = 0.
        var montgomerizedA = curve.a.slice();
        montgomeryMultiplier.convertToMontgomeryForm(montgomerizedA);

        var aequalsZero = cryptoMath.isZero(curve.a);

        var one = cryptoMath.One;

        var onemontgomery = createArray(fieldElementWidth);
        onemontgomery[0] = 1;
        montgomeryMultiplier.convertToMontgomeryForm(onemontgomery);

        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(montgomeryMultiplier.m), true);

        // Setup temp storage.
        var temp0 = createArray(fieldElementWidth);
        var temp1 = createArray(fieldElementWidth);
        var temp2 = createArray(fieldElementWidth);
        var temp3 = createArray(fieldElementWidth);
        var temp4 = createArray(fieldElementWidth);
        var temp5 = createArray(fieldElementWidth);
        var temp6 = createArray(fieldElementWidth);
        var temp7 = createArray(fieldElementWidth);
        var swap0 = createArray(fieldElementWidth);

        // Some additional temp storage used in point conversion routines.
        var conversionTemp0 = createArray(fieldElementWidth);
        var conversionTemp1 = createArray(fieldElementWidth);
        var conversionTemp2 = createArray(fieldElementWidth);

        function modSub(left, right, result) {
            var resultElement = group.createElementFromInteger(0);
            resultElement.m_digits = result;
            group.subtract(
                group.createElementFromDigits(left),
                group.createElementFromDigits(right),
                resultElement);
        }

        function modAdd(left, right, result) {
            var resultElement = group.createElementFromInteger(0);
            resultElement.m_digits = result;
            group.add(
                group.createElementFromDigits(left),
                group.createElementFromDigits(right),
                resultElement);
        }

        function modInv(number, result) {
            cryptoMath.modInv(number, m_curve.p, result);
        }

        function modDivByTwo( /*@type(Digits)*/ dividend,  /*@type(Digits)*/ result) {

            var s = dividend.length;

            var modulus = curve.p;

            // If dividend is odd, add modulus
            if ((dividend[0] & 0x1) === 0x1) {
                var carry = 0;

                for (var i = 0; i < s; i += 1) {
                    carry += dividend[i] + modulus[i];
                    result[i] = carry & cryptoMath.DIGIT_MASK;
                    carry = (carry >>> cryptoMath.DIGIT_BITS);
                }

                // Put carry bit into position for masking in
                carry = carry << (cryptoMath.DIGIT_BITS - 1);

                // Bit shift
                cryptoMath.shiftRight(result, result);

                // Mask in the carry bit
                result[s - 1] |= carry;
            } else {
                // Shift directly into result
                cryptoMath.shiftRight(dividend, result);
            }

        }

        function montgomeryMultiply(left, right, result) {
            montgomeryMultiplier.montgomeryMultiply(
                left,
                right,
                result);
        }

        function montgomerySquare(left, result) {
            montgomeryMultiplier.montgomeryMultiply(
                left,
                left,
                result);
        }

        function correctInversion(digits) {
            /// <param name="digits" type="Digits"/>
            var results = createArray(digits.length);
            montgomeryMultiply(digits, montgomeryMultiplier.rCubedModm, results);
            for (var i = 0; i < results.length; i += 1) {
                digits[i] = results[i];
            }
        }

        function doubleAequalsNeg3(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // If point = infinity then outputPoint := infinity.
            if (point.isInfinity) {
                outputPoint.isInfinity = true;
                return;
            }

            // 't4:=Z1^2;'
            montgomerySquare(point.z, temp4);

            // 't3:=Y1^2;'
            montgomerySquare(point.y, temp3);

            // 't1:=X1+t4;'
            modAdd(point.x, temp4, temp1);

            // 't4:=X1-t4;'
            modSub(point.x, temp4, temp4);

            // 't0:=3*t4;'
            modAdd(temp4, temp4, temp0);
            modAdd(temp0, temp4, temp0);

            // 't5:=X1*t3;'
            montgomeryMultiply(point.x, temp3, temp5);

            // 't4:=t1*t0;'
            montgomeryMultiply(temp1, temp0, temp4);

            // 't0:=t3^2;'
            montgomerySquare(temp3, temp0);

            // 't1:=t4/2'
            modDivByTwo(temp4, temp1);

            // 't3:=t1^2;'
            montgomerySquare(temp1, temp3);

            // 'Z_out:=Y1*Z1;'
            montgomeryMultiply(point.y, point.z, swap0);
            for (var i = 0; i < swap0.length; i += 1) {
                outputPoint.z[i] = swap0[i];
            }

            // 'X_out:=t3-2*t5;'
            modSub(temp3, temp5, outputPoint.x);
            modSub(outputPoint.x, temp5, outputPoint.x);

            // 't3:=t5-X_out;'
            modSub(temp5, outputPoint.x, temp3);

            // 't5:=t1*t3'
            montgomeryMultiply(temp1, temp3, temp5);

            // 'Y_out:=t5-t0;'
            modSub(temp5, temp0, outputPoint.y);

            // Finalize the flags on the output point.
            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;
        }

        function doubleAequals0(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // If point = infinity then outputPoint := infinity.
            if (point.isInfinity) {
                outputPoint.isInfinity = true;
                return;
            }

            // 't3:=Y1^2;'
            montgomerySquare(point.y, temp3);

            // 't4:=X1^2;'
            montgomerySquare(point.x, temp4);

            // 't4:=3*t4;'
            modAdd(temp4, temp4, temp0);
            modAdd(temp0, temp4, temp4);

            // 't5:=X1*t3;'
            montgomeryMultiply(point.x, temp3, temp5);

            // 't0:=t3^2;'
            montgomerySquare(temp3, temp0);

            // 't1:=t4/2;'
            modDivByTwo(temp4, temp1);

            // 't3:=t1^2;'
            montgomerySquare(temp1, temp3);

            // 'Z_out:=Y1*Z1;'
            montgomeryMultiply(point.y, point.z, swap0);
            for (var i = 0; i < swap0.length; i += 1) {
                outputPoint.z[i] = swap0[i];
            }

            // 'X_out:=t3-2*t5;'
            modSub(temp3, temp5, outputPoint.x);
            modSub(outputPoint.x, temp5, outputPoint.x);

            // 't4:=t5-X_out;'
            modSub(temp5, outputPoint.x, temp4);

            // 't2:=t1*t4;'
            montgomeryMultiply(temp1, temp4, temp2);

            // 'Y_out:=t2-t0;'
            modSub(temp2, temp0, outputPoint.y);

            // Finalize the flags on the output point.
            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;
        }

        function generatePrecomputationTable(w, generatorPoint) {

            if (w < 4) {
                throw new Error("This pre-computation algorithm assumes w >= 4");
            }

            if (!generatorPoint.isInMontgomeryForm) {
                throw new Error("Generator point must be in montgomery form");
            }

            if (!generatorPoint.isAffine) {
                throw new Error("Generator point must be in affine form");
            }

            // Currently we support only two curve types, those with A=-3, and
            // those with A=0. In the future we will implement general support.
            // For now we switch here, assuming that the curve was validated in
            // the constructor.
            if (aequalsZero) {
                return generatePrecomputationTableAequals0(w, generatorPoint);
            } else {
                return generatePrecomputationTableAequalsNeg3(w, generatorPoint);
            }
        }

        // Given a point P on an elliptic curve, return a table of 
        // size 2^(w-2) filled with pre-computed values for 
        // P, 3P, 5P, ... Etc.

        function generatePrecomputationTableAequalsNeg3(w, generatorPoint) {
            /// <param name="w" type="Number">The "width" of the table to use. The should match the width used to generate the NAF.</param>
            /// <param name="generatorPoint">The point P in affine, montgomery form.</param>
            /// <returns>A table of size 2^(w-2) filled with pre-computed values for P, 3P, 5P, ... Etc in De-montgomeryized Affine Form.</returns>

            // Width of our field elements.
            var s = curve.p.length;

            // Initialize table
            // The first element is set to our generator povar initially.
            // The rest are dummy points to be filled in by the pre-computation
            // algorithm.
            var tableSize = (1 << (w - 2)); // 2^(w-2)
            var t = []; // Of EllipticCurvePointFp
            var i;
            t[0] = generatorPoint.clone();

            for (i = 1; i < tableSize; i += 1) {
                var newPoint = EllipticCurvePointFp(
                    curve,
                    false,
                    createArray(s),
                    createArray(s),
                    createArray(s),
                    true
                );
                t[i] = newPoint;
            }

            // Initialize temp tables for povar recovery.
            var d = [];
            var e = [];

            for (i = 0; i < tableSize - 2; i += 1) {
                d[i] = createArray(s);
                e[i] = createArray(s);
            }

            // Alias temp7 to Z for readability.
            var z = temp7;

            // Pseudocode Note:
            // Arrays of points use element 1 for X, element 2 for Y
            // so e.g. T[0][1] === T[0].x.

            // SETUP -----------------------------------------------------------

            // Compute T[0] = 2*P and T[1] = P such that both are in Jacobian 
            // form with the same Z. These values are then used to compute 
            // T[0] = 3P, T[1] = 5P, ..., T[n] = (3 + 2*n) * P.

            // 't1 := T[0].x^2;  '
            montgomerySquare(t[0].x, temp1);

            // 't3 := T[0].y^2;'
            montgomerySquare(t[0].y, temp3);

            // 't1 := (3*t1 + A)/2;'
            modAdd(temp1, temp1, temp2);
            modAdd(temp2, temp1, temp1);
            modAdd(temp1, montgomerizedA, temp1);
            modDivByTwo(temp1, temp1);

            // 'T[2].x := t3 * T[0].x;'
            montgomeryMultiply(temp3, t[0].x, t[2].x);

            // 'T[2].y := t3^2;'
            montgomerySquare(temp3, t[2].y);

            // 'Z := T[0].y;'
            for (i = 0; i < s; i += 1) {
                z[i] = t[0].y[i];
            }

            // 'T[1].x := t1^2;'
            montgomerySquare(temp1, t[1].x);

            // 'T[1].x := T[1].x - 2 * T[2].x;'
            // PERF: Implementing DBLSUB here (and everywhere where we compute A - 2*B) 
            // may possibly result in some performance gain.
            modSub(t[1].x, t[2].x, t[1].x);
            modSub(t[1].x, t[2].x, t[1].x);

            // 't2 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp2);

            // 't1 := t1 * t2;'
            // NOTE: Using temp0 as target since montmul is destructive.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[1].y := t1 - T[2].y;'
            modSub(temp0, t[2].y, t[1].y);

            // First iteration ------------------------------------------------

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't2 := T[2].y - T[1].y;'
            modSub(t[2].y, t[1].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);
            var idx;
            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[0] := t1^2;'
            montgomerySquare(temp1, d[0]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'T[2].x := d[0] * T[1].x;'
            montgomeryMultiply(d[0], t[1].x, t[2].x);

            // 't3 := t3 - 2 * T[2].x;'
            modSub(temp3, t[2].x, temp3);
            modSub(temp3, t[2].x, temp3);

            // 'd[0] := d[0] * t1;'
            montgomeryMultiply(d[0], temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                d[0][idx] = temp0[idx];
            }

            // 'T[1].x := t3 - d[0];'
            modSub(temp3, d[0], t[1].x);

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't1 := t1 * t2;'
            // NOTE: Using t0 as target due to destructive multiply.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[2].y := T[1].y*d[0];'
            montgomeryMultiply(t[1].y, d[0], t[2].y);

            // 'T[1].y := t1 - T[2].y;'
            // NOTE: Reusing t0 result from above.
            modSub(temp0, t[2].y, t[1].y);

            // INNER ITERATIONS ------------------------------------------------
            var j, k, l;

            for (i = 0; i < tableSize - 3; i += 1) {
                j = i + 1;
                k = i + 2;
                l = i + 3;

                // 't1 := T[j].x - T[k].x;'
                modSub(t[j].x, t[k].x, temp1);

                // 't2 := T[j].y - T[k].y;'
                modSub(t[j].y, t[k].y, temp2);

                // 'Z := Z * t1;'
                // NOTE: Using temp0 as target since multiply is destructive.
                montgomeryMultiply(z, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    z[idx] = temp0[idx];
                }

                // 'd[i] := t1^2;'
                montgomerySquare(temp1, d[i]);

                // 't3 := t2^2;'
                montgomerySquare(temp2, temp3);

                // 'T[l].x := d[i] * T[k].x;'
                montgomeryMultiply(d[i], t[k].x, t[l].x);

                // 't3 := t3 - 2 * T[l].x;'
                modSub(temp3, t[l].x, temp3);
                modSub(temp3, t[l].x, temp3);

                // 'e[i] := d[i] * t1;'
                montgomeryMultiply(d[i], temp1, e[i]);

                // 'T[k].x := t3 - e[i];'
                modSub(temp3, e[i], t[k].x);

                // 't1 := T[l].x - T[k].x;'
                // NOTE: Using temp0 as target so we can multiply into temp1 below.
                modSub(t[l].x, t[k].x, temp0);

                // 't1 := t1 * t2;'
                // NOTE: Using temp0 result from above.
                montgomeryMultiply(temp0, temp2, temp1);

                // 'T[l].y := T[k].y*e[i];'
                montgomeryMultiply(t[k].y, e[i], t[l].y);

                // 'T[k].y := t1 - T[l].y;'
                modSub(temp1, t[l].y, t[k].y);
            }

            // FINAL ITERATION -------------------------------------------------
            // {
            i = tableSize - 3;
            j = i + 1;
            k = i + 2; // 't1 := T[j].x - T[k].x;'
            modSub(t[j].x, t[k].x, temp1);

            // 't2 := T[j].y - T[k].y;'
            modSub(t[j].y, t[k].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[i] := t1^2;'
            montgomerySquare(temp1, d[i]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'e[i] := d[i] * t1;'
            montgomeryMultiply(d[i], temp1, e[i]);

            // 't1 := d[i] * T[k].x;'
            montgomeryMultiply(d[i], t[k].x, temp1);

            // 't3 := t3 - 2 * t1;'
            modSub(temp3, temp1, temp3);
            modSub(temp3, temp1, temp3);

            // 'T[k].x := t3 - e[i];'
            modSub(temp3, e[i], t[k].x);

            // 't1 := t1 - T[k].x;'
            // NOTE: Using temp0 as target so we can multiply into temp1 below.
            modSub(temp1, t[k].x, temp0);

            // 't1 := t1 * t2;'
            // NOTE: Reusing temp0 to multiply into temp1.
            montgomeryMultiply(temp0, temp2, temp1);

            // 'T[k].y := T[k].y * e[i];'
            // NOTE: Using temp3 as target due to destructive multiply.
            montgomeryMultiply(t[k].y, e[i], temp3);

            // 'T[k].y := t1 - T[k].y;'
            // NOTE: Using temp3 instead of T[k].y.
            modSub(temp1, temp3, t[k].y);

            // POST ITERATIONS - INVERT Z AND PREPARE TO RECOVER TABLE ENTRIES ---------------

            // 'Z := 1/Z;'
            // NOTE: Z is in montgomery form at this point, i.e. Z*R. After 
            // inversion we will have 1/(Z*R) but we want (1/Z)*R (the 
            // montgomery form of Z inverse) so we use the inversion 
            // correction, which does a montgomery multiplication by R^3
            // yielding the correct result.
            modInv(z, z);
            correctInversion(z);

            // 't1 := Z^2;'
            montgomerySquare(z, temp1);

            // 't2 := t1 * Z;'
            montgomeryMultiply(temp1, z, temp2);

            // 'T[k].x := T[k].x * t1;'
            montgomeryMultiply(t[k].x, temp1, temp0);

            // Copy temp0 to T[k].x.
            for (idx = 0; idx < s; idx++) {
                t[k].x[idx] = temp0[idx];
            }

            // 'T[k].y := T[k].y * t2;'
            montgomeryMultiply(t[k].y, temp2, temp0);

            for (idx = 0; idx < s; idx++) {
                t[k].y[idx] = temp0[idx];
            }
            // } FINAL ITERATION

            // RECOVER POINTS FROM TABLE ---------------------------------------

            // For i in [(2^(w-2)-2)..1 by -1] do
            for (i = tableSize - 3; i >= 0; i--) {
                // 'j := i + 1;'
                j = i + 1; // 't1 := t1 * d[i];'
                montgomeryMultiply(temp1, d[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp1[idx] = temp0[idx];
                }

                // 't2 := t2 * e[i];'
                montgomeryMultiply(temp2, e[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp2[idx] = temp0[idx];
                }

                // 'T[j].x := T[j].x * t1;'
                montgomeryMultiply(t[j].x, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].x[idx] = temp0[idx];
                }

                // 'T[j].y := T[j].y * t2;'
                montgomeryMultiply(t[j].y, temp2, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].y[idx] = temp0[idx];
                }

                // End for;
            }

            // Points are now in affine form, set Z coord to null (== 1).
            for (i = 0; i < t.length; i += 1) {
                t[i].z = null;
                setterSupport || (t[i].isAffine = true);
            }

            for (i = 0; i < t.length; i += 1) {

                if (!t[i].isAffine) {
                    throw new Error("Non-affine povar found in precomputation table");
                }
                if (!t[i].isInMontgomeryForm) {
                    convertToMontgomeryForm(t[i]);
                }
            }

            return t;
        }

        // Given a povar P on an elliptic curve, return a table of 
        // size 2^(w-2) filled with pre-computed values for 
        // P, 3P, 5P, ... Etc.

        function generatePrecomputationTableAequals0(w, generatorPoint) {
            /// <param name="w" type="Number">The "width" of the table to use. The should match
            /// the width used to generate the NAF.</param>
            /// <param name="generatorPoint" type="EllipticCurvePointFp">The povar P in affine, montgomery form.</param>
            /// <returns>A table of 
            /// size 2^(w-2) filled with pre-computed values for 
            /// P, 3P, 5P, ... Etc in De-montgomeryized Affine Form.</returns>

            // Width of our field elements.
            var s = curve.p.length;

            // Initialize table
            // The first element is set to our generator povar initially.
            // The rest are dummy points to be filled in by the pre-computation
            // algorithm.
            var tableSize = (1 << (w - 2)); // '2^(w-2)'
            var t = []; // Of EllipticCurvePointFp
            t[0] = generatorPoint.clone();
            var i;
            for (i = 1; i < tableSize; i += 1) {
                var newPoint = EllipticCurvePointFp(
                    curve,
                    false,
                    createArray(s),
                    createArray(s),
                    createArray(s),
                    true
                );
                t[i] = newPoint;
            }

            // Initialize temp tables for povar recovery.
            var d = [];
            var e = [];

            for (i = 0; i < tableSize - 2; i += 1) {
                d[i] = createArray(s);
                e[i] = createArray(s);
            }

            // Alias temp7 to Z for readability.
            var z = temp7;

            // Pseudocode Note:
            // Arrays of points use element 1 for X, element 2 for Y
            // so e.g. T[0][1] === T[0].x.

            // SETUP -----------------------------------------------------------

            // Compute T[0] = 2*P and T[1] = P such that both are in Jacobian 
            // form with the same Z. These values are then used to compute 
            // T[0] = 3P, T[1] = 5P, ..., T[n] = (3 + 2*n) * P.

            // 't1 := T[0].x^2;  '
            montgomerySquare(t[0].x, temp1);

            // 't3 := T[0].y^2;'
            montgomerySquare(t[0].y, temp3);

            // 't1 := (3*t1)/2;'
            modAdd(temp1, temp1, temp2);
            modAdd(temp2, temp1, temp1);
            modDivByTwo(temp1, temp1);

            // 'T[2].x := t3 * T[0].x;'
            montgomeryMultiply(temp3, t[0].x, t[2].x);

            // 'T[2].y := t3^2;'
            montgomerySquare(temp3, t[2].y);

            // 'Z := T[0].y;'
            for (i = 0; i < s; i += 1) {
                z[i] = t[0].y[i];
            }

            // 'T[1].x := t1^2;'
            montgomerySquare(temp1, t[1].x);

            // 'T[1].x := T[1].x - 2 * T[2].x;'
            // PERF: Implementing DBLSUB here (and everywhere where we compute A - 2*B) 
            // may possibly result in some performance gain.
            modSub(t[1].x, t[2].x, t[1].x);
            modSub(t[1].x, t[2].x, t[1].x);

            // 't2 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp2);

            // 't1 := t1 * t2;'
            // NOTE: Using temp0 as target since montmul is destructive.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[1].y := t1 - T[2].y;'
            modSub(temp0, t[2].y, t[1].y);

            // First iteration ------------------------------------------------

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't2 := T[2].y - T[1].y;'
            modSub(t[2].y, t[1].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);
            var idx;
            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[0] := t1^2;'
            montgomerySquare(temp1, d[0]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'T[2].x := d[0] * T[1].x;'
            montgomeryMultiply(d[0], t[1].x, t[2].x);

            // 't3 := t3 - 2 * T[2].x;'
            modSub(temp3, t[2].x, temp3);
            modSub(temp3, t[2].x, temp3);

            // 'd[0] := d[0] * t1;'
            montgomeryMultiply(d[0], temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                d[0][idx] = temp0[idx];
            }

            // 'T[1].x := t3 - d[0];'
            modSub(temp3, d[0], t[1].x);

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't1 := t1 * t2;'
            // NOTE: Using t0 as target due to destructive multiply.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[2].y := T[1].y*d[0];'
            montgomeryMultiply(t[1].y, d[0], t[2].y);

            // 'T[1].y := t1 - T[2].y;'
            // NOTE: Reusing t0 result from above.
            modSub(temp0, t[2].y, t[1].y);

            var j, k, l;
            // INNER ITERATIONS ------------------------------------------------
            for (i = 0; i < tableSize - 3; i += 1) {
                j = i + 1;
                k = i + 2;
                l = i + 3;

                // 't1 := T[j].x - T[k].x;'
                modSub(t[j].x, t[k].x, temp1);

                // 't2 := T[j].y - T[k].y;'
                modSub(t[j].y, t[k].y, temp2);

                // 'Z := Z * t1;'
                // NOTE: Using temp0 as target since multiply is destructive.
                montgomeryMultiply(z, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    z[idx] = temp0[idx];
                }

                // 'd[i] := t1^2;'
                montgomerySquare(temp1, d[i]);

                // 't3 := t2^2;'
                montgomerySquare(temp2, temp3);

                // 'T[l].x := d[i] * T[k].x;'
                montgomeryMultiply(d[i], t[k].x, t[l].x);

                // 't3 := t3 - 2 * T[l].x;'
                modSub(temp3, t[l].x, temp3);
                modSub(temp3, t[l].x, temp3);

                // 'e[i] := d[i] * t1;'
                montgomeryMultiply(d[i], temp1, e[i]);

                // 'T[k].x := t3 - e[i];'
                modSub(temp3, e[i], t[k].x);

                // 't1 := T[l].x - T[k].x;'
                // NOTE: Using temp0 as target so we can multiply into temp1 below.
                modSub(t[l].x, t[k].x, temp0);

                // 't1 := t1 * t2;'
                // NOTE: Using temp0 result from above.
                montgomeryMultiply(temp0, temp2, temp1);

                // 'T[l].y := T[k].y*e[i];'
                montgomeryMultiply(t[k].y, e[i], t[l].y);

                // 'T[k].y := t1 - T[l].y;'
                modSub(temp1, t[l].y, t[k].y);
            }

            // FINAL ITERATION -------------------------------------------------
            // {
            i = tableSize - 3;
            j = i + 1;
            k = i + 2;

            // 't1 := T[j].x - T[k].x;'
            modSub(t[j].x, t[k].x, temp1);

            // 't2 := T[j].y - T[k].y;'
            modSub(t[j].y, t[k].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[i] := t1^2;'
            montgomerySquare(temp1, d[i]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'e[i] := d[i] * t1;'
            montgomeryMultiply(d[i], temp1, e[i]);

            // 't1 := d[i] * T[k].x;'
            montgomeryMultiply(d[i], t[k].x, temp1);

            // 't3 := t3 - 2 * t1;'
            modSub(temp3, temp1, temp3);
            modSub(temp3, temp1, temp3);

            // 'T[k].x := t3 - e[i];'
            modSub(temp3, e[i], t[k].x);

            // 't1 := t1 - T[k].x;'
            // NOTE: Using temp0 as target so we can multiply into temp1 below.
            modSub(temp1, t[k].x, temp0);

            // 't1 := t1 * t2;'
            // NOTE: Reusing temp0 to multiply into temp1.
            montgomeryMultiply(temp0, temp2, temp1);

            // 'T[k].y := T[k].y*e[i];'
            // NOTE: Using temp3 as target due to destructive multiply.
            montgomeryMultiply(t[k].y, e[i], temp3);

            // 'T[k].y := t1 - T[k].y;'
            // NOTE: Using temp3 instead of T[k].y.
            modSub(temp1, temp3, t[k].y);

            // POST ITERATIONS - INVERT Z AND PREPARE TO RECOVER TABLE ENTRIES ---------------

            // 'Z := 1/Z;'
            // NOTE: Z is in montgomery form at this point, i.e. Z*R. After 
            // inversion we will have 1/(Z*R) but we want (1/Z)*R (the 
            // montgomery form of Z inverse) so we use the inversion 
            // correction, which does a montgomery multiplication by R^3
            // yielding the correct result.
            modInv(z, z);
            correctInversion(z);

            // 't1 := Z^2;'
            montgomerySquare(z, temp1);

            // 't2 := t1 * Z;'
            montgomeryMultiply(temp1, z, temp2);

            // 'T[k].x := T[k].x * t1;'
            montgomeryMultiply(t[k].x, temp1, temp0);

            // Copy temp0 to T[k].x.
            for (idx = 0; idx < s; idx++) {
                t[k].x[idx] = temp0[idx];
            }

            // 'T[k].y := T[k].y * t2;'
            montgomeryMultiply(t[k].y, temp2, temp0);

            for (idx = 0; idx < s; idx++) {
                t[k].y[idx] = temp0[idx];
            }
            // }

            // RECOVER POINTS FROM TABLE ---------------------------------------

            // For i in [(2^(w-2)-2)..1 by -1] do
            for (i = tableSize - 3; i >= 0; i--) {
                // 'j := i + 1;'
                j = i + 1;

                // 't1 := t1 * d[i];'
                montgomeryMultiply(temp1, d[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp1[idx] = temp0[idx];
                }

                // 't2 := t2 * e[i];'
                montgomeryMultiply(temp2, e[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp2[idx] = temp0[idx];
                }

                // 'T[j].x := T[j].x * t1;'
                montgomeryMultiply(t[j].x, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].x[idx] = temp0[idx];
                }

                // 'T[j].y := T[j].y * t2;'
                montgomeryMultiply(t[j].y, temp2, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].y[idx] = temp0[idx];
                }

                // End for;
            }

            // Points are now in affine form, set Z coord to null (== 1).
            for (i = 0; i < t.length; i += 1) {
                t[i].z = null;
                setterSupport || (t[i].isAffine = true);
            }

            for (i = 0; i < t.length; i += 1) {

                if (!t[i].isAffine) {
                    throw new Error("Non-affine povar found in precomputation table");
                }
                if (!t[i].isInMontgomeryForm) {
                    convertToMontgomeryForm(t[i]);
                }
            }

            return t;
        }

        function convertToMontgomeryForm(point) {
            /// <param name="point" type="EllipticCurvePointFp"/>

            if (point.isInMontgomeryForm) {
                throw new Error("The given point is already in montgomery form.");
            }

            if (!point.isInfinity) {
                montgomeryMultiplier.convertToMontgomeryForm(point.x);
                montgomeryMultiplier.convertToMontgomeryForm(point.y);

                if (point.z !== null) {
                    montgomeryMultiplier.convertToMontgomeryForm(point.z);
                }
            }

            point.isInMontgomeryForm = true;
        }

        return {

            double: function (point, outputPoint) {
                /// <param name="point" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                if (typeof point === "undefined") {
                    throw new Error("point undefined");
                }
                if (typeof outputPoint === "undefined") {
                    throw new Error("outputPoint undefined");
                }

                //// if (!point.curve.equals(outputPoint.curve)) {
                ////    throw new Error("point and outputPoint must be from the same curve object.");
                //// }

                if (point.isAffine) {
                    throw new Error("Given point was in Affine form. Use convertToJacobian() first.");
                }

                if (!point.isInMontgomeryForm) {
                    throw new Error("Given point must be in montgomery form. Use montgomeryize() first.");
                }

                if (outputPoint.isAffine) {
                    throw new Error("Given output point was in Affine form. Use convertToJacobian() first.");
                }

                // Currently we support only two curve types, those with A=-3, and
                // those with A=0. In the future we will implement general support.
                // For now we switch here, assuming that the curve was validated in
                // the constructor.
                if (aequalsZero) {
                    doubleAequals0(point, outputPoint);
                } else {
                    doubleAequalsNeg3(point, outputPoint);
                }

            },

            mixedDoubleAdd: function (jacobianPoint, affinePoint, outputPoint) {
                /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
                /// <param name="affinePoint" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                if (jacobianPoint.isInfinity) {
                    affinePoint.copy(outputPoint);
                    this.convertToJacobianForm(outputPoint);
                    return;
                }

                if (affinePoint.isInfinity) {
                    jacobianPoint.copy(outputPoint);
                    return;
                }

                // Ok then we do the full double and add.

                // Note: in pseudo-code the capital X,Y,Z is Jacobian point, lower 
                // case x, y, z is Affine point.

                // 't5:=Z1^ 2;'
                montgomerySquare(jacobianPoint.z, temp5);

                // 't6:=Z1*t5;'
                montgomeryMultiply(jacobianPoint.z, temp5, temp6);

                // 't4:=x2*t5;'
                montgomeryMultiply(affinePoint.x, temp5, temp4);

                // 't5:=y2*t6;'
                montgomeryMultiply(affinePoint.y, temp6, temp5);

                // 't1:=t4-X1;'
                modSub(temp4, jacobianPoint.x, temp1);

                // 't2:=t5-Y1;'
                modSub(temp5, jacobianPoint.y, temp2);

                // 't4:=t2^2;'
                montgomerySquare(temp2, temp4);

                // 't6:=t1^2;'
                montgomerySquare(temp1, temp6);

                // 't5:=t6*X1;'
                montgomeryMultiply(temp6, jacobianPoint.x, temp5);

                // 't0:=t1*t6;'
                montgomeryMultiply(temp1, temp6, temp0);

                // 't3:=t4-2*t5;'
                modSub(temp4, temp5, temp3);
                modSub(temp3, temp5, temp3);

                // 't4:=Z1*t1;'
                montgomeryMultiply(jacobianPoint.z, temp1, temp4);

                // 't3:=t3-t5;'
                modSub(temp3, temp5, temp3);

                // 't6:=t0*Y1;'
                montgomeryMultiply(temp0, jacobianPoint.y, temp6);

                // 't3:=t3-t0;'
                modSub(temp3, temp0, temp3);

                // 't1:=2*t6;'
                modAdd(temp6, temp6, temp1);

                // 'Zout:=t4*t3;'
                montgomeryMultiply(temp4, temp3, outputPoint.z);

                // 't4:=t2*t3;'
                montgomeryMultiply(temp2, temp3, temp4);

                // 't0:=t3^2;'
                montgomerySquare(temp3, temp0);

                // 't1:=t1+t4;'
                modAdd(temp1, temp4, temp1);

                // 't4:=t0*t5;'
                montgomeryMultiply(temp0, temp5, temp4);

                // 't7:=t1^2;'
                montgomerySquare(temp1, temp7);

                // 't4:=t0*t5;'
                montgomeryMultiply(temp0, temp3, temp5);

                // 'Xout:=t7-2*t4;'
                modSub(temp7, temp4, outputPoint.x);
                modSub(outputPoint.x, temp4, outputPoint.x);

                // 'Xout:=Xout-t5;'
                modSub(outputPoint.x, temp5, outputPoint.x);

                // 't3:=Xout-t4;'
                modSub(outputPoint.x, temp4, temp3);

                // 't0:=t5*t6;'
                montgomeryMultiply(temp5, temp6, temp0);

                // 't4:=t1*t3;'
                montgomeryMultiply(temp1, temp3, temp4);

                // 'Yout:=t4-t0;'
                modSub(temp4, temp0, outputPoint.y);

                outputPoint.isInfinity = false;
                outputPoint.isInMontgomeryForm = true;

            },

            mixedAdd: function (jacobianPoint, affinePoint, outputPoint) {
                /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
                /// <param name="affinePoint" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                if (jacobianPoint === null) {
                    throw new Error("jacobianPoint");
                }

                if (affinePoint === null) {
                    throw new Error("affinePoint");
                }

                if (outputPoint === null) {
                    throw new Error("outputPoint");
                }

                if (jacobianPoint.curve !== affinePoint.curve ||
                    jacobianPoint.curve !== outputPoint.curve) {
                    throw new Error("All points must be from the same curve object.");
                }

                if (jacobianPoint.isAffine) {
                    throw new Error(
                        "Given jacobianPoint was in Affine form. Use ConvertToJacobian() before calling DoubleJacobianAddAffinePoints().");
                }

                if (!affinePoint.isAffine) {
                    throw new Error(
                        "Given affinePoint was in Jacobian form. Use ConvertToAffine() before calling DoubleJacobianAddAffinePoints().");
                }

                if (outputPoint.isAffine) {
                    throw new Error(
                        "Given jacobianPoint was in Jacobian form. Use ConvertToJacobian() before calling DoubleJacobianAddAffinePoints().");
                }

                if (!jacobianPoint.isInMontgomeryForm) {
                    throw new Error("Jacobian point must be in Montgomery form");
                }

                if (!affinePoint.isInMontgomeryForm) {
                    throw new Error("Affine point must be in Montgomery form");
                }

                if (jacobianPoint.isInfinity) {
                    affinePoint.copy(outputPoint);
                    this.convertToJacobianForm(outputPoint);
                    return;
                }

                if (affinePoint.isInfinity) {
                    jacobianPoint.copy(outputPoint);
                    return;
                }

                // Ok then we do the full double and add.

                // Note: in pseudo-code the capital X1,Y1,Z1 is Jacobian point, 
                // lower case x2, y2, z2 is Affine point.
                // 't1 := Z1^2;'.
                montgomerySquare(jacobianPoint.z, temp1);

                // 't2 := t1 * Z1;'
                montgomeryMultiply(temp1, jacobianPoint.z, temp2);

                // 't3 := t1 * x2;'
                montgomeryMultiply(temp1, affinePoint.x, temp3);

                // 't4 := t2 * y2;'
                montgomeryMultiply(temp2, affinePoint.y, temp4);

                // 't1 := t3 - X1;'
                modSub(temp3, jacobianPoint.x, temp1);

                // 't2 := t4 - Y1;'
                modSub(temp4, jacobianPoint.y, temp2);

                // If t1 != 0 then
                var i;
                for (i = 0; i < temp1.length; i += 1) {
                    if (temp1[i] !== 0) {

                        // 'Zout := Z1 * t1;'
                        montgomeryMultiply(jacobianPoint.z, temp1, temp0);
                        for (var j = 0; j < fieldElementWidth; j += 1) {
                            outputPoint.z[j] = temp0[j];
                        }

                        // 't3 := t1^2;'
                        montgomerySquare(temp1, temp3);

                        // 't4 := t3 * t1;'
                        montgomeryMultiply(temp3, temp1, temp4);

                        // 't5 := t3 * X1;'
                        montgomeryMultiply(temp3, jacobianPoint.x, temp5);

                        // 't1 := 2 * t5;'
                        modAdd(temp5, temp5, temp1);

                        // 'Xout := t2^2;'
                        montgomerySquare(temp2, outputPoint.x);

                        // 'Xout := Xout - t1;'
                        modSub(outputPoint.x, temp1, outputPoint.x);

                        // 'Xout := Xout - t4;'
                        modSub(outputPoint.x, temp4, outputPoint.x);

                        // 't3 := t5 - Xout;'
                        modSub(temp5, outputPoint.x, temp3);

                        // 't5 := t3*t2;'
                        montgomeryMultiply(temp2, temp3, temp5);

                        // 't6 := t4*Y1;'
                        montgomeryMultiply(jacobianPoint.y, temp4, temp6);

                        // 'Yout := t5-t6;'
                        modSub(temp5, temp6, outputPoint.y);

                        outputPoint.isInfinity = false;
                        outputPoint.isInMontgomeryForm = true;

                        return;
                    }
                }

                // Else if T2 != 0 then
                for (i = 0; i < temp2.length; i += 1) {
                    if (temp2[i] !== 0) {
                        //         Return infinity
                        outputPoint.isInfinity = true;
                        outputPoint.isInMontgomeryForm = true;
                        return;
                    }
                }
                // Else use DBL routine to return 2(x2, y2, 1) 
                affinePoint.copy(outputPoint);
                this.convertToJacobianForm(outputPoint);
                this.double(outputPoint, outputPoint);
                outputPoint.isInMontgomeryForm = true;

            },

            scalarMultiply: function (k, point, outputPoint) {
                /// <param name="k" type="Digits"/>
                /// <param name="point" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                // Special case for the point at infinity or k == 0
                if (point.isInfinity || cryptoMath.isZero(k)) {
                    outputPoint.isInfinity = true;
                    return;
                }

                // Runtime check for 1 <= k < order to ensure we dont get hit by
                // subgroup attacks. Since k is a FixedWidth it is a positive integer
                // and we already checked for zero above. So it must be >= 1 already.
                if (cryptoMath.compareDigits(k, curve.order) >= 0) {
                    throw new Error("The scalar k must be in the range 1 <= k < order.");
                }

                var digit;

                // Change w based on the size of the digits, 
                // 5 is good for 256 bits, use 6 for bigger sizes.
                var w = (fieldElementWidth <= 8) ? 5 : 6;
                // Generate wNAF representation.
                // Using an Array because we want to allow negative numbers.
                var nafDigits = msrcryptoUtilities.getVector(k.length * cryptoMath.DIGIT_BITS + 1);
                var numNafDigits = cryptoMath.computeNAF(k, w, temp0, nafDigits);

                // Generate pre-computation table.
                var table = generatePrecomputationTable(w, point);

                // Setup output point as Infinity, Jacobian, montgomery.
                outputPoint.isInfinity = true;

                // Main algorithm.
                for (var i1 = numNafDigits - 1; i1 >= 0; i1--) {
                    if (nafDigits[i1] === 0) {
                        this.double(outputPoint, outputPoint);
                    } else if (nafDigits[i1] < 0) {
                        digit = (-nafDigits[i1] >> 1);

                        // Negate Y coord before doing the add.
                        this.negate(table[digit], table[digit]);
                        this.mixedDoubleAdd(outputPoint, table[digit], outputPoint);
                        this.negate(table[digit], table[digit]);
                    } else if (nafDigits[i1] > 0) {
                        digit = (nafDigits[i1] >> 1);
                        this.mixedDoubleAdd(outputPoint, table[digit], outputPoint);
                    }
                }

                return;

            },

            negate: function (point, outputPoint) {
                /// <param name="point" type="EllipticCurvePointFp">Input point to negate.</param>
                /// <param name="outputPoint" type="EllipticCurvePointFp">(x, p - y).</param>

                if (point !== outputPoint) {
                    point.copy(outputPoint);
                }
                cryptoMath.subtract(point.curve.p, point.y, outputPoint.y);
            },

            convertToMontgomeryForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (point.isInMontgomeryForm) {
                    throw new Error("The given point is already in montgomery form.");
                }

                if (!point.isInfinity) {
                    montgomeryMultiplier.convertToMontgomeryForm(point.x);
                    montgomeryMultiplier.convertToMontgomeryForm(point.y);

                    if (point.z !== null) {
                        montgomeryMultiplier.convertToMontgomeryForm(point.z);
                    }
                }

                point.isInMontgomeryForm = true;
            },

            convertToStandardForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (!point.isInMontgomeryForm) {
                    throw new Error("The given point is not in montgomery form.");
                }

                if (!point.isInfinity) {
                    montgomeryMultiplier.convertToStandardForm(point.x);
                    montgomeryMultiplier.convertToStandardForm(point.y);
                    if (point.z !== null) {
                        montgomeryMultiplier.convertToStandardForm(point.z);
                    }
                }

                point.isInMontgomeryForm = false;

            },

            convertToAffineForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (point.isInfinity) {
                    point.z = null;
                    setterSupport || (point.isAffine = true);
                    return;
                }

                // DETERMINE 1/Z IN MONTGOMERY FORM --------------------------------

                // Call out to the basic inversion function, not the one in this class.
                cryptoMath.modInv(point.z, curve.p, conversionTemp2);

                if (point.isInMontgomeryForm) {
                    montgomeryMultiply(conversionTemp2, montgomeryMultiplier.rCubedModm, conversionTemp1);
                    var swap = conversionTemp2;
                    conversionTemp2 = conversionTemp1;
                    conversionTemp1 = swap;
                }

                // CONVERT TO AFFINE COORDS ----------------------------------------

                // 'temp0 <- 1/z^2'
                montgomerySquare(conversionTemp2, conversionTemp0);

                // Compute point.x = x / z^2 mod p
                // NOTE: We cannot output directly to the X digit array since it is 
                // used for input to the multiplication routine, so we output to temp1
                // and copy.
                montgomeryMultiply(point.x, conversionTemp0, conversionTemp1);
                for (var i = 0; i < fieldElementWidth; i += 1) {
                    point.x[i] = conversionTemp1[i];
                }

                // Compute point.y = y / z^3 mod p
                // temp1 <- y * 1/z^2.
                montgomeryMultiply(point.y, conversionTemp0, conversionTemp1);
                // 'y <- temp1 * temp2 (which == 1/z)'
                montgomeryMultiply(conversionTemp1, conversionTemp2, point.y);

                // Finally, point.z = z / z mod p = 1
                // We use z = NULL for this case to make detecting Jacobian form 
                // faster (otherwise we would have to scan the entire Z digit array).
                point.z = null;
                setterSupport || (point.isAffine = true);
            },

            convertToJacobianForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (!point.isAffine) {
                    throw new Error("The given point is not in Affine form.");
                }

                setterSupport || (point.isAffine = false);

                var clonedDigits;
                var i;
                if (point.isInMontgomeryForm) {

                    // Z = 1 (montgomery form)
                    clonedDigits = createArray(onemontgomery.length);
                    for (i = 0; i < onemontgomery.length; i += 1) {
                        clonedDigits[i] = onemontgomery[i];
                    }

                    point.z = clonedDigits;
                } else {

                    // Z = 1 (standard form)
                    clonedDigits = createArray(one.length);
                    for (i = 0; i < one.length; i += 1) {
                        clonedDigits[i] = one[i];
                    }

                    point.z = clonedDigits;
                }

            },

            // For tests
            generatePrecomputationTable: function (w, generatorPoint) {
                /// <param name="w" type="Number"/>
                /// <param name="generatorPoint" type="EllipticCurvePointFp"/>

                return generatePrecomputationTable(w, generatorPoint);
            }

        };
    };
    var sec1EncodingFp = function () {
        return {
            encodePoint: function (/*@type(EllipticCurvePointFp)*/ point) {
                /// <summary>Encode an EC point without compression.
                /// This function encodes a given points into a bytes array containing 0x04 | X | Y, where X and Y are big endian bytes of x and y coordinates.</summary>
                /// <param name="point" type="EllipticCurvePointFp">Input EC point to encode.</param>
                /// <returns type="Array">A bytes array containing 0x04 | X | Y, where X and Y are big endian encoded x and y coordinates.</returns>

                if (!point) {
                    throw new Error("point");
                }

                if (!point.isAffine) {
                    throw new Error("Point must be in affine form.");
                }

                if (point.isInMontgomeryForm) {
                    throw new Error("Point must not be in Montgomery form.");
                }

                if (point.isInfinity) {
                    return createArray(1); /* [0] */
                } else {
                    var xOctetString = cryptoMath.digitsToBytes(point.x);
                    var yOctetString = cryptoMath.digitsToBytes(point.y);
                    var pOctetString = cryptoMath.digitsToBytes(point.curve.p);     // just to get byte length of p
                    var mlen = pOctetString.length;
                    if (mlen < xOctetString.length || mlen < yOctetString.length) {
                        throw new Error("Point coordinate(s) are bigger than the field order.");
                    }
                    var output = createArray(2 * mlen + 1);       // for encoded x and y

                    output[0] = 0x04;
                    var offset = mlen - xOctetString.length;
                    for (var i = 0; i < xOctetString.length; i++) {
                        output[i + 1 + offset] = xOctetString[i];
                    }
                    offset = mlen - yOctetString.length;
                    for (i = 0; i < yOctetString.length; i++) {
                        output[mlen + i + 1 + offset] = yOctetString[i];
                    }

                    return output;
                }

            },
            decodePoint: function (encoded, curve) {
                /// <param name="encoded" type="Digits"/>
                /// <param name="curve" type="EllipticCurveFp"/>

                if (encoded.length < 1) {
                    throw new Error("Byte array must have non-zero length");
                }

                var pOctetString = cryptoMath.digitsToBytes(curve.p);
                var mlen = pOctetString.length;

                if (encoded[0] === 0x0 && encoded.length === 1) {
                    return curve.createPointAtInfinity();
                } else if (encoded[0] === 0x04 && encoded.length === 1 + 2 * mlen) {
                    // Standard encoding.
                    // Each point is a big endian string of bytes of length.
                    //      'ceiling(log_2(Q)/8)'
                    // Zero-padded and representing the magnitude of the coordinate.
                    var xbytes = createArray(mlen);
                    var ybytes = createArray(mlen);

                    for (var i = 0; i < mlen; i++) {
                        xbytes[i] = encoded[i + 1];
                        ybytes[i] = encoded[mlen + i + 1];
                    }

                    var x = cryptoMath.bytesToDigits(xbytes);
                    var y = cryptoMath.bytesToDigits(ybytes);

                    return EllipticCurvePointFp(curve, false, x, y);
                } else {
                    // We don't support other encoding features such as compression
                    throw new Error("Unsupported encoding format");
                }
            }
        };
    };
    var ModularSquareRootSolver = function (modulus) {
        /// <param name="modulus" type="Digits"/>

        // The modulus we are going to use.
        var p = modulus;

        // Special-K not just for breakfast anymore! This is k = (p-3)/4 + 1
        // which is used for NIST curves (or any curve of with P= 3 mod 4).
        // This field is null if p is not of the special form, or k if it is.
        var specialK = [];

        if (typeof modulus === "undefined") {
            throw new Error("modulus");
        }

        // Support for odd moduli, only.
        if (cryptoMath.isEven(modulus)) {
            throw new Error("Only odd moduli are supported");
        }

        // A montgomery multiplier object for doing fast squaring.
        var mul = cryptoMath.MontgomeryMultiplier(p);

        // 'p === 3 mod 4' then we can use the special super fast version.
        // Otherwise we must use the slower general case algorithm.
        if (p[0] % 4 === 3) {
            // 'special k = (p + 1) / 4'
            cryptoMath.add(p, cryptoMath.One, specialK);
            cryptoMath.shiftRight(specialK, specialK, 2);
        } else {
            specialK = null;
        }

        // Temp storage
        var temp0 = new Array(p.length);
        var temp1 = new Array(p.length);

        function squareRootNistCurves(a) {
            /// <summary>Given a number a, returns a solution x to x^2 = a (mod p).</summary>
            /// <param name="a" type="Array">An integer a.</param>
            /// <returns type="Array">The square root of the number a modulo p, if it exists,
            /// otherwise null.</returns>

            // beta = a^k mod n where k=(n+1)/4 for n == 3 mod 4, thus a^(1/2) mod n
            var beta = cryptoMath.intToDigits(0, 16);
            mul.modExp(a, specialK, beta);

            // Okay now we gotta double check by squaring.
            var aPrime = [0];
            cryptoMath.modMul(beta, beta, mul.m, aPrime);

            // If a != x^2 then a has no square root
            if (cryptoMath.compareDigits(a, aPrime) !== 0) {
                return null;
            }

            return beta;
        }

        var publicMethods = {

            squareRoot: function (a) {
                if (specialK !== null) {
                    // Use the special case fast code
                    return squareRootNistCurves(a);
                } else {
                    // Use the general case code
                    throw new Error("GeneralCase not supported.");
                }
            },

            // Given an integer a, this routine returns the Jacobi symbol (a/p), 
            // where p is the modulus given in the constructor, which for p an 
            // odd prime is also the Legendre symbol. From "Prime Numbers, A 
            // Computational Perspective" by Crandall and Pomerance, alg. 2.3.5.
            // The Legendre symbol is defined as:
            //   0   if a === 0 mod p.
            //   1   if a is a quadratic residue (mod p).
            //   -1  if a is a quadratic non-reside (mod p).
            jacobiSymbol: function (a) {
                /// <param name="a">An integer a.</param>

                var modEightMask = 0x7,
                    modFourMask = 0x3,
                    aPrime,
                    pPrime;

                // Clone our inputs, we are going to destroy them
                aPrime = a.slice();
                pPrime = p.slice();

                // 'a = a mod p'.
                cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);

                // 't = 1'
                var t = 1;

                // While (a != 0)
                while (!cryptoMath.isZero(aPrime)) {
                    // While a is even
                    while (cryptoMath.isEven(aPrime)) {
                        // 'a <- a / 2'
                        cryptoMath.shiftRight(aPrime, aPrime);

                        // If (p mod 8 in {3,5}) t = -t;
                        var pMod8 = (pPrime[0] & modEightMask);
                        if (pMod8 === 3 || pMod8 === 5) {
                            t = -t;
                        }
                    }

                    // Swap variables
                    // (a, p) = (p, a).
                    var tmp = aPrime;
                    aPrime = pPrime;
                    pPrime = tmp;

                    // If (a === p === 3 (mod 4)) t = -t;
                    var aMod4 = (aPrime[0] & modFourMask);
                    var pMod4 = (pPrime[0] & modFourMask);
                    if (aMod4 === 3 && pMod4 === 3) {
                        t = -t;
                    }

                    // 'a = a mod p'
                    cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);
                }

                // If (p == 1) return t else return 0
                if (cryptoMath.compareDigits(pPrime, cryptoMath.One) === 0) {
                    return t;
                } else {
                    return 0;
                }
            }

        };

        return publicMethods;
    };

    return {
        createP256: createP256,
        createP384: createP384,
        createBN254: createBN254,
        createANeg3Curve: createANeg3Curve,
        sec1EncodingFp: sec1EncodingFp,
        EllipticCurvePointFp: EllipticCurvePointFp,
        EllipticCurveOperatorFp: EllipticCurveOperatorFp,
        ModularSquareRootSolver: ModularSquareRootSolver
    };
}

var cryptoECC = cryptoECC || MsrcryptoECC();

//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />

/// <dictionary>msrcrypto, der, sha</dictionary>

/// <disable>JS3057.AvoidImplicitTypeCoercion</disable>

/// #endregion JSCop/JsHint

var msrcryptoSha1 = (function () {

    var hashFunction = function (name, der, h, k, truncateTo) {

        var blockBytes = 64;
        var hv = h.slice();
        var w = new Array(blockBytes);
        var buffer = [];
        var blocksProcessed = 0;

        function hashBlocks(/*@type(Array)*/message) {

            var blockCount = Math.floor(message.length / blockBytes);

            var ra, rb, rc, rd, re;
            var t, block, i, temp, x0, index;

            // Process each 64-byte block of the message
            for (block = 0; block < blockCount; block++) {

                // 0 ≤ t ≤ 15
                for (i = 0; i < 16; i++) {
                    index = block * blockBytes + i * 4;
                    // Convert 4 bytes to 32-bit integer
                    w[i] = (message[index] << 24) |
                           (message[index + 1] << 16) |
                           (message[index + 2] << 8) |
                            message[index + 3];
                }

                // 16 ≤ t ≤ 79
                for (t = 16; t < 80; t++) {
                    x0 = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
                    w[t] = (x0 << 1) | (x0 >>> 31);
                }

                ra = hv[0];
                rb = hv[1];
                rc = hv[2];
                rd = hv[3];
                re = hv[4];

                for (i = 0; i < 20; i++) {

                    // Ch(x, y, z)=(x & y) ^ (~x & z)
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += (rb & rc) ^ ((~rb) & rd);
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                for (i = 20; i < 40; i++) {

                    //Parity(x, y, z)= x ^ y ^ z
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += rb ^ rc ^ rd;
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                for (i = 40; i < 60; i++) {

                    //Maj(x, y, z)=(x & y) ^ (x & z) ^ (y & z)
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += (rb & rc) ^ (rb & rd) ^ (rc & rd);
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                for (i = 60; i < 80; i++) {

                    //Parity(x, y, z)= x ^ y ^ z
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += rb ^ rc ^ rd;
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                // Need to mask 32-bits when using regular arrays
                hv[0] += ra & 0xFFFFFFFF;
                hv[1] += rb & 0xFFFFFFFF;
                hv[2] += rc & 0xFFFFFFFF;
                hv[3] += rd & 0xFFFFFFFF;
                hv[4] += re & 0xFFFFFFFF;

            }

            // Keep track of the number of blocks processed.
            // We have to put the total message size into the padding.
            blocksProcessed += blockCount;

            // Return the unprocessed data.
            return message.slice(blockCount * blockBytes);
        }

        function hashToBytes() {

            var hash = new Array(256);

            // Copy the 32-bit values to a byte array
            for (var i = 0, byteIndex = 0; i < 8; i += 1, byteIndex += 4) {
                hash[byteIndex] = hv[i] >>> 24;
                hash[byteIndex + 1] = hv[i] >>> 16 & 0xFF;
                hash[byteIndex + 2] = hv[i] >>> 8 & 0xFF;
                hash[byteIndex + 3] = hv[i] & 0xFF;
            }

            return hash.slice(0, truncateTo / 8);
        }

        // This can be optimized.
        // Currently the amount of padding is computed. Then a new array, big enough
        // to hold the message + padding is created.  The message is copied to the
        // new array and the padding is placed at the end.
        // We don't really need to create an entire new array and copy to it.
        // We can just build the last padded block and store it.
        // Then when computing the hash, substitute it for the last message block.
        function padBlock( /*@type(Array)*/ message) {

            var padLen = blockBytes - message.length;

            // If there is 8 or less bytes of padding, pad an additional block.
            if (padLen <= 8) {
                padLen += blockBytes;
            }

            // Create a new Array that will contain the message + padding
            var paddedMessage = message.slice();

            // Set the 1 bit at the end of the message data
            paddedMessage.push(128);

            // Pad the array with zero. Leave 4 bytes for the message size.
            for (var i = 1; i < padLen - 4; i++) {
                paddedMessage.push(0);
            }

            // Set the length equal to the previous data len + the new data len
            var messageLenBits = (message.length + blocksProcessed * blockBytes) * 8;

            // Set the message length in the last 4 bytes
            paddedMessage.push(messageLenBits >>> 24 & 255);
            paddedMessage.push(messageLenBits >>> 16 & 255);
            paddedMessage.push(messageLenBits >>> 8 & 255);
            paddedMessage.push(messageLenBits & 255);

            return paddedMessage;
        }

        function bufferToArray(buffer) {

            // Checking for slice method to determine if this a regular array.
            if (buffer.pop) {
                return buffer;
            }

            return (buffer.length === 1) ? [buffer[0]] : Array.apply(null, buffer);
        }

        function /*@type(Array)*/ computeHash(messageBytes) {

            // Convert the input to an Array - it could be a typed array
            buffer = hashBlocks(bufferToArray(messageBytes));

            return finish();
        }

        function process(messageBytes) {

            // Append the new data to the buffer (previous unprocessed data)
            // Convert the input to an Array - it could be a typed array
            buffer = buffer.concat(bufferToArray(messageBytes));

            // If there is at least one block of data, hash it
            if (buffer.length >= 64) {
                // The remaining unprocessed data goes back into the buffer
                buffer = hashBlocks(buffer);
            }

            return;
        }

        function finish() {

            // All the full blocks of data have been processed. Now we pad the rest and hash.
            // Buffer should be empty now.
            if (hashBlocks(padBlock(buffer)).length !== 0) {
                throw new Error("buffer.length !== 0");
            }

            var result = hashToBytes();

            // Clear the hash values so this instance can be reused
            buffer = [];
            hv = h.slice();
            blocksProcessed = 0;

            return result;
        }

        return {
            name: name,
            computeHash: computeHash,
            process: process,
            finish: finish,
            der: der,
            hashLen: truncateTo,
            maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
        };

    };

    var k, h, der, upd = msrcryptoUtilities.unpackData;

    h = upd("Z0UjAe/Nq4mYutz+EDJUdsPS4fA=", 4, 1);

    k = upd("WoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroY8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdY", 4, 1);

    // DER encoding
    der = upd("MCEwCQYFKw4DAhoFAAQU");

    return {
        sha1: hashFunction("SHA-1", der, h, k, 160)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha1.hash = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha1.Sha1.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha1.Sha1.finish();
        }

        return msrcryptoSha1.sha1.computeHash(p.buffer);

    };

    operations.register("digest", "sha-1", msrcryptoSha1.hash);

}

msrcryptoHashFunctions["sha-1"] = msrcryptoSha1.sha1;

//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />

/// <dictionary>msrcrypto, der, sha</dictionary>

/// <disable>JS3057.AvoidImplicitTypeCoercion</disable>

/// #endregion JSCop/JsHint

var msrcryptoSha256 = (function () {

    var hashFunction = function (name, der, h, k, truncateTo) {

        var blockBytes = 64;
        var hv = h.slice();
        var w = new Array(blockBytes);
        var buffer = [];
        var blocksProcessed = 0;

        function hashBlocks(/*@type(Array)*/message) {

            var blockCount = Math.floor(message.length / blockBytes);

            var ra, rb, rc, rd, re, rf, rg, rh;
            var t, block, i, temp, x1, x0, index;

            // Process each 64-byte block of the message
            for (block = 0; block < blockCount; block++) {

                // 0 ≤ t ≤ 15
                for (i = 0; i < 16; i++) {
                    index = block * blockBytes + i * 4;
                    // Convert 4 bytes to 32-bit integer
                    w[i] = (message[index] << 24) |
                           (message[index + 1] << 16) |
                           (message[index + 2] << 8) |
                            message[index + 3];
                }

                // 16 ≤ t ≤ 63
                for (t = 16; t < 64; t++) {

                    x0 = w[t - 15];
                    x1 = w[t - 2];

                    w[t] = (((x1 >>> 17) | (x1 << 15)) ^ ((x1 >>> 19) | (x1 << 13)) ^ (x1 >>> 10));
                    w[t] += w[t - 7];
                    w[t] += (((x0 >>> 7) | (x0 << 25)) ^ ((x0 >>> 18) | (x0 << 14)) ^ (x0 >>> 3));
                    w[t] += w[t - 16];
                }

                ra = hv[0];
                rb = hv[1];
                rc = hv[2];
                rd = hv[3];
                re = hv[4];
                rf = hv[5];
                rg = hv[6];
                rh = hv[7];

                for (i = 0; i < 64; i++) {

                    temp =
                        rh +
                            ((re >>> 6 | re << 26) ^ (re >>> 11 | re << 21) ^ (re >>> 25 | re << 7)) +
                            ((re & rf) ^ ((~re) & rg)) +
                            k[i] + w[i];

                    rd += temp;

                    temp +=
                    ((ra >>> 2 | ra << 30) ^ (ra >>> 13 | ra << 19) ^ (ra >>> 22 | ra << 10)) +
                        ((ra & (rb ^ rc)) ^ (rb & rc));

                    rh = rg; // 'h' = g
                    rg = rf; // 'g' = f
                    rf = re; // 'f' = e
                    re = rd; // 'e' = d
                    rd = rc; // 'd' = c
                    rc = rb; // 'c' = b
                    rb = ra; // 'b' = a
                    ra = temp; // 'a' = temp

                }

                // Need to mask 32-bits when using regular arrays
                hv[0] += ra & 0xFFFFFFFF;
                hv[1] += rb & 0xFFFFFFFF;
                hv[2] += rc & 0xFFFFFFFF;
                hv[3] += rd & 0xFFFFFFFF;
                hv[4] += re & 0xFFFFFFFF;
                hv[5] += rf & 0xFFFFFFFF;
                hv[6] += rg & 0xFFFFFFFF;
                hv[7] += rh & 0xFFFFFFFF;
            }

            // Keep track of the number of blocks processed.
            // We have to put the total message size into the padding.
            blocksProcessed += blockCount;

            // Return the unprocessed data.
            return message.slice(blockCount * blockBytes);
        }

        function hashToBytes() {

            var hash = new Array(256);

            // Copy the 32-bit values to a byte array
            for (var i = 0, byteIndex = 0; i < 8; i += 1, byteIndex += 4) {
                hash[byteIndex] = hv[i] >>> 24;
                hash[byteIndex + 1] = hv[i] >>> 16 & 0xFF;
                hash[byteIndex + 2] = hv[i] >>> 8 & 0xFF;
                hash[byteIndex + 3] = hv[i] & 0xFF;
            }

            return hash.slice(0, truncateTo / 8);
        }

        // This can be optimized.
        // Currently the amount of padding is computed. Then a new array, big enough
        // to hold the message + padding is created.  The message is copied to the
        // new array and the padding is placed at the end.
        // We don't really need to create an entire new array and copy to it.
        // We can just build the last padded block and store it.
        // Then when computing the hash, substitute it for the last message block.
        function padBlock( /*@type(Array)*/ message) {

            var padLen = blockBytes - message.length;

            // If there is 8 or less bytes of padding, pad an additional block.
            if (padLen <= 8) {
                padLen += blockBytes;
            }

            // Create a new Array that will contain the message + padding
            var paddedMessage = message.slice();

            // Set the 1 bit at the end of the message data
            paddedMessage.push(128);

            // Pad the array with zero. Leave 4 bytes for the message size.
            for (var i = 1; i < padLen - 4; i++) {
                paddedMessage.push(0);
            }

            // Set the length equal to the previous data len + the new data len
            var messageLenBits = (message.length + blocksProcessed * blockBytes) * 8;

            // Set the message length in the last 4 bytes
            paddedMessage.push(messageLenBits >>> 24 & 255);
            paddedMessage.push(messageLenBits >>> 16 & 255);
            paddedMessage.push(messageLenBits >>> 8 & 255);
            paddedMessage.push(messageLenBits & 255);

            return paddedMessage;
        }

        function bufferToArray(buffer) {

            // Checking for slice method to determine if this a regular array.
            if (buffer.pop) {
                return buffer;
            }

            return (buffer.length === 1) ? [buffer[0]] : Array.apply(null, buffer);
        }

        function /*@type(Array)*/ computeHash(messageBytes) {

            // Convert the input to an Array - it could be a typed array
            buffer = hashBlocks(bufferToArray(messageBytes));

            return finish();
        }

        function process(messageBytes) {

            // Append the new data to the buffer (previous unprocessed data)
            // Convert the input to an Array - it could be a typed array
            buffer = buffer.concat(bufferToArray(messageBytes));

            // If there is at least one block of data, hash it
            if (buffer.length >= 64) {
                // The remaining unprocessed data goes back into the buffer
                buffer = hashBlocks(buffer);
            }

            return;
        }

        function finish() {

            // All the full blocks of data have been processed. Now we pad the rest and hash.
            // Buffer should be empty now.
            if (hashBlocks(padBlock(buffer)).length !== 0) {
                throw new Error("buffer.length !== 0");
            }

            var result = hashToBytes();

            // Clear the hash values so this instance can be reused
            buffer = [];
            hv = h.slice();
            blocksProcessed = 0;

            return result;
        }

        return {
            name: name,
            computeHash: computeHash,
            process: process,
            finish: finish,
            der: der,
            hashLen: truncateTo,
            maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
        };

    };

    var k256, h224, h256, der224, der256, upd = msrcryptoUtilities.unpackData;

    h224 = upd("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q", 4, 1);

    h256 = upd("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk", 4, 1);

    k256 = upd("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g", 4, 1);

    // DER encoding
    der224 = upd("MDEwDQYJYIZIAWUDBAIEBQAEIA");
    der256 = upd("MDEwDQYJYIZIAWUDBAIBBQAEIA");

    return {
        sha224: hashFunction("SHA-224", der224, h224, k256, 224),
        sha256: hashFunction("SHA-256", der256, h256, k256, 256)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha256.hash256 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.sha256.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha256.sha256.finish();
        }

        return msrcryptoSha256.sha256.computeHash(p.buffer);

    };

    msrcryptoSha256.hash224 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.sha224.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha256.sha224.finish();
        }

        return msrcryptoSha256.sha224.computeHash(p.buffer);

    };

    operations.register("digest", "sha-224", msrcryptoSha256.hash224);
    operations.register("digest", "sha-256", msrcryptoSha256.hash256);
}

msrcryptoHashFunctions["sha-224"] = msrcryptoSha256.sha224;
msrcryptoHashFunctions["sha-256"] = msrcryptoSha256.sha256;
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* global msrcryptoUtilities */
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />
/// <reference path="utilities.js" />

/// <dictionary>msrcrypto, der, sha, uint, int, maj</dictionary>

/// #endregion JSCop/JsHint

var msrcryptoSha512 = (function () {

    function add(x0, x1, y0, y1, resultArray) {

        // The sum here may result in a number larger than 32-bits.
        // Or-ing with zero forces to a 32-bit signed internal state
        // and a truncation to a 32-bit number;
        var lowSum = (x1 + y1) | 0;

        // If lowSum is less than either parameter (x1 or y1), we know we overflowed
        //   and a carry will need to be added to the high order bits.
        // The 32-bit integer is signed. So large numbers can flip to negative values.
        // The zero-shift pulls the number back out of the 32-bit state so we know
        //   we're comparing positive values.
        var carry = (lowSum >>> 0 < y1 >>> 0);

        resultArray[0] = (x0 + y0 + carry) | 0;
        resultArray[1] = lowSum;

        return;
    }

    var hashFunction = function (hashName, der, h, k, truncateTo) {

        var blockBytes = 128,
         hv = [],
         w = [],
         buffer = [],
         blocksProcessed = 0;

        initializeHashValues();

        // Hashing using 64 bit registers. 2-32bit values as high and low
        function hashBlocks( /*@type(Array)*/ message) {

            var blockCount = Math.floor(message.length / blockBytes),
                t, i,
                tah, tal, tbh, tbl, xh, xl,
                tc = [],
                td = [],
                te = [],
                block, index;

            for (block = 0; block < blockCount; block++) {

                for (t = 0; t < 32; t++) {
                    index = block * blockBytes + t * 4;
                    w[t] = message.slice(index, index + 4);
                    w[t] = (w[t][0] << 24) | (w[t][1] << 16) | (w[t][2] << 8) | w[t][3];
                }

                // 16 ≤ t ≤ 80
                for (t = 32; t < 160; t += 2) {

                    xh = w[t - 30];
                    xl = w[t - 29];

                    tah = (xh >>> 1 | xl << 31) ^ (xh >>> 8 | xl << 24) ^ (xh >>> 7);
                    tal = (xl >>> 1 | xh << 31) ^ (xl >>> 8 | xh << 24) ^ (xl >>> 7 | xh << 25);

                    xh = w[t - 4];
                    xl = w[t - 3];

                    tbh = (xh >>> 19 | xl << 13) ^ (xl >>> 29 | xh << 3) ^ (xh >>> 6);
                    tbl = (xl >>> 19 | xh << 13) ^ (xh >>> 29 | xl << 3) ^ (xl >>> 6 | xh << 26);

                    add(tbh, tbl, w[t - 14], w[t - 13], tc);

                    add(tah, tal, tc[0], tc[1], tc);

                    add(w[t - 32], w[t - 31], tc[0], tc[1], tc);

                    w[t] = tc[0]; w[t + 1] = tc[1];
                }

                var ah = hv[0], al = hv[1],
                    bh = hv[2], bl = hv[3],
                    ch = hv[4], cl = hv[5],
                    dh = hv[6], dl = hv[7],
                    eh = hv[8], el = hv[9],
                    fh = hv[10], fl = hv[11],
                    gh = hv[12], gl = hv[13],
                    hh = hv[14], hl = hv[15];

                for (i = 0; i < 160; i += 2) {

                    // S1 =======================================================================
                    tah = (eh >>> 14 | el << 18) ^ (eh >>> 18 | el << 14) ^ (el >>> 9 | eh << 23);
                    tal = (el >>> 14 | eh << 18) ^ (el >>> 18 | eh << 14) ^ (eh >>> 9 | el << 23);

                    // Ch
                    tbh = (eh & fh) ^ (gh & ~eh);
                    tbl = (el & fl) ^ (gl & ~el);

                    // C = h + S1
                    add(hh, hl, tah, tal, tc);

                    // D = ch + kConstants-i
                    add(tbh, tbl, k[i], k[i + 1], td);

                    // E = w[i] + C
                    add(tc[0], tc[1], w[i], w[i + 1], te);

                    // E = E + D  TEMP
                    add(td[0], td[1], te[0], te[1], te);

                    // D = C + E
                    add(te[0], te[1], dh, dl, tc);
                    dh = tc[0]; dl = tc[1];

                    // S0
                    tal = (al >>> 28 | ah << 4) ^ (ah >>> 2 | al << 30) ^ (ah >>> 7 | al << 25);
                    tah = (ah >>> 28 | al << 4) ^ (al >>> 2 | ah << 30) ^ (al >>> 7 | ah << 25);

                    tbl = (al & (bl ^ cl)) ^ (bl & cl);
                    tbh = (ah & (bh ^ ch)) ^ (bh & ch);

                    // S0 + maj
                    add(te[0], te[1], tah, tal, tc);
                    tah = tc[0]; tal = tc[1];

                    // 'temp' = temp + (S0 + maj)
                    add(tbh, tbl, tah, tal, tc);
                    tah = tc[0]; tal = tc[1];

                    hh = gh;
                    hl = gl; // 'h' = g
                    gh = fh;
                    gl = fl; // 'g' = f
                    fh = eh;
                    fl = el; // 'f' = e
                    eh = dh;
                    el = dl; // 'e' = d
                    dh = ch;
                    dl = cl; // 'd' = c
                    ch = bh;
                    cl = bl; // 'c' = b
                    bh = ah;
                    bl = al; // 'b' = a
                    ah = tah;
                    al = tal; // 'a' = temp
                }

                // This is how you would add without calling add()
                // hv[1] = ((hv[1] + al) | 0) >>> 0;
                // hv[0] = hv[0] + ah + (hv[1] < al >>> 0) | 0;

                add(hv[0], hv[1], ah, al, tc);
                hv[0] = tc[0]; hv[1] = tc[1];

                add(hv[2], hv[3], bh, bl, tc);
                hv[2] = tc[0]; hv[3] = tc[1];

                add(hv[4], hv[5], ch, cl, tc);
                hv[4] = tc[0]; hv[5] = tc[1];

                add(hv[6], hv[7], dh, dl, tc);
                hv[6] = tc[0]; hv[7] = tc[1];

                add(hv[8], hv[9], eh, el, tc);
                hv[8] = tc[0]; hv[9] = tc[1];

                add(hv[10], hv[11], fh, fl, tc);
                hv[10] = tc[0]; hv[11] = tc[1];

                add(hv[12], hv[13], gh, gl, tc);
                hv[12] = tc[0]; hv[13] = tc[1];

                add(hv[14], hv[15], hh, hl, tc);
                hv[14] = tc[0]; hv[15] = tc[1];
            }

            // Keep track of the number of blocks processed.
            // We have to put the total message size into the padding.
            blocksProcessed += blockCount;

            // Return the unprocessed data.
            return message.slice(blockCount * blockBytes);
        }

        function hashToBytes() {

            // Move the results to an uint8 array
            var hash = [];

            for (var i = 0; i < 16; i++) {
                hash = hash.concat([hv[i] >>> 24, (hv[i] >>> 16) & 255, (hv[i] >>> 8) & 255, hv[i] & 255]);
            }

            return hash.slice(0, truncateTo / 8);
        }

        function padBlock(/*@type(Array)*/message) {

            var padLen = blockBytes - message.length;

            // If there is 16 or less bytes of padding, pad an additional block.
            if (padLen <= 16) {
                padLen += blockBytes;
            }

            // Create a new Array that will contain the message + padding
            var paddedMessage = message.slice();

            // Set the 1 bit at the end of the message data
            paddedMessage.push(128);

            // Pad the array with zero. Leave 4 bytes for the message size.
            for (var i = 1; i < padLen - 4; i++) {
                paddedMessage.push(0);
            }

            // Set the length equal to the previous data len + the new data len
            var messageLenBits = (message.length + blocksProcessed * blockBytes) * 8;

            // Set the message length in the last 4 bytes (32-bits worth)
            // JavaScript arrays have a max size of 32-bits.
            paddedMessage.push(messageLenBits >>> 24 & 255);
            paddedMessage.push(messageLenBits >>> 16 & 255);
            paddedMessage.push(messageLenBits >>> 8 & 255);
            paddedMessage.push(messageLenBits & 255);

            return paddedMessage;
        }

        function bufferToArray(/*@type(Array)*/dataBuffer) {

            if (dataBuffer.slice) {
                return dataBuffer;
            }

            return (dataBuffer.length === 1) ? [dataBuffer[0]] : Array.apply(null, dataBuffer);
        }

        function initializeHashValues() {
            // Set the initial hash values
            for (var l = 0; l < h.length; l++) {
                hv[l] = h[l][0] << 24 | h[l][1] << 16 | h[l][2] << 8 | h[l][3];
            }
        }

        function computeHash(messageBytes) {

            buffer = hashBlocks(bufferToArray(messageBytes));

            return finish();
        }

        function process(messageBytes) {

            // Append the new data to the buffer (previous unprocessed data)
            buffer = buffer.concat(bufferToArray(messageBytes));

            // If there is at least one block of data, hash it
            if (buffer.length >= 64) {
                // The remaining unprocessed data goes back into the buffer
                buffer = hashBlocks(buffer);
            }

            return;
        }

        function finish() {

            // All the full blocks of data have been processed. Now we pad the rest and hash
            buffer = hashBlocks(padBlock(buffer));

            // Buffer should be empty now
            if (buffer.length !== 0) {
                throw new Error("buffer.length !== 0");
            }

            var result = hashToBytes();

            // Clear the state so this instance can be reused
            buffer = [];
            initializeHashValues();
            blocksProcessed = 0;

            return result;
        }

        return {
            name: hashName,
            computeHash: computeHash,
            process: process,
            finish: finish,
            der: der,
            hashLen: truncateTo,
            maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
        };

    };

    var h384, h512, k512,
        der384, der512, der512_224, der512_256,
        upd = msrcryptoUtilities.unpackData;

    h384 = upd("y7udXcEFnthimikqNnzVB5FZAVowcN0XFS/s2PcOWTlnMyZn/8ALMY60SodoWBUR2wwuDWT5j6dHtUgdvvpPpA==", 4);

    h512 = upd("agnmZ/O8yQi7Z66FhMqnOzxu83L+lPgrpU/1Ol8dNvFRDlJ/reaC0ZsFaIwrPmwfH4PZq/tBvWtb4M0ZE34heQ", 4);

    k512 = upd(
        "QoovmNcoriJxN0SRI+9lzbXA+8/sTTsv6bXbpYGJ27w5VsJb80i1OFnxEfG2BdAZkj+CpK8ZT5urHF7" +
        "V2m2BGNgHqpijAwJCEoNbAUVwb74kMYW+TuSyjFUMfcPV/7Ticr5ddPJ7iW+A3rH+OxaWsZvcBqclxx" +
        "I1wZvxdM9pJpTkm2nBnvFK0u++R4Y4TyXjD8GdxouM1bUkDKHMd6ycZS3pLG9ZKwJ1SnSEqm6m5INcs" +
        "KncvUH71Hb5iNqDEVO1mD5RUu5m36uoMcZtLbQyELADJ8iY+yE/v1l/x77vDuTG4AvzPaiPwtWnkUeT" +
        "CqclBspjUeADgm8UKSlnCg5ucCe3CoVG0i/8LhshOFwmySZNLG38WsQq7VM4DROdlbPfZQpzVIuvY95" +
        "2agq7PHeyqIHCyS5H7a7mknIshRSCNTuiv+ihTPEDZKgaZku8QjABwkuLcND4l5HHbFGjBlS+MNGS6B" +
        "nW71IY1pkGJFVlqRD0DjWFV3EgKhBqoHAyu9G4GaTBFrjS0MgeN2wIUUGrUydId0zfjuuZNLC8teGbS" +
        "Kg5HAyzxclaY07YqkrjQYrLW5zKT3dj43NoLm/z1rK4o3SPgu5d77L8eKVjb0MXL2CEyHgUofCrcozH" +
        "AggaZDnskL7/+iNjHiikUGzr3oK96b75o/eyxnkVxnF48uNyUyvKJz7O6iZhnNGGuMchwMIH6tp91s3" +
        "g6x71fU9/7m7ReAbwZ6pyF2+6CmN9xaLImKYRP5gEvvkNrhtxCzUTHEcbKNt39SMEfYQyyqt7QMckkz" +
        "yevgoVyb68Qx1nxJwQDUxMxdS+yz5Ctll/KZz8ZX4qX8tvqzrW+uxsRBmMSkdYFw==", 4, 1);

    // DER encoding
    der384 = upd("MEEwDQYJYIZIAWUDBAICBQAEMA");
    der512 = upd("MFEwDQYJYIZIAWUDBAIDBQAEQA");
    der512_224 = upd("MC0wDQYJYIZIAWUDBAIFBQAEHA");
    der512_256 = upd("MDEwDQYJYIZIAWUDBAIGBQAEIA");

    return {
        sha384: hashFunction("SHA-384", der384, h384, k512, 384),
        sha512: hashFunction("SHA-512", der512, h512, k512, 512),
        sha512_224: hashFunction("SHA-512.224", der512_224, h512, k512, 224),
        sha512_256: hashFunction("SHA-512.256", der512_256, h512, k512, 256)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha512.hash384 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha512.sha384.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha512.sha384.finish();
        }

        return msrcryptoSha512.sha384.computeHash(p.buffer);

    };

    msrcryptoSha512.hash512 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha512.sha512.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha512.sha512.finish();
        }

        return msrcryptoSha512.sha512.computeHash(p.buffer);

    };

    operations.register("digest", "sha-384", msrcryptoSha512.hash384);
    operations.register("digest", "sha-512", msrcryptoSha512.hash512);
}

msrcryptoHashFunctions["sha-384"] = msrcryptoSha512.sha384;
msrcryptoHashFunctions["sha-512"] = msrcryptoSha512.sha512;
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* global msrcryptoSha256 */
/* global msrcryptoSha512 */
/* global msrcryptoJwk */
/* global msrcryptoPseudoRandom */
/* jshint -W016 */

/// <reference path="sha256.js" />
/// <reference path="sha512.js" />
/// <reference path="operations.js" />
/// <reference path="random.js" />
/// <reference path="jwk.js" />

/// <dictionary>Hmac,ipad,msrcrypto,opad,sha,xor</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoHmac = (function () {

    var sha256,
        sha512,
        sha1;

    if (typeof msrcryptoSha256 !== "undefined") {
        sha256 = msrcryptoSha256;
    }

    if (typeof msrcryptoSha512 !== "undefined") {
        sha512 = msrcryptoSha512;
    }

    if (typeof msrcryptoSha1 !== "undefined") {
        sha1 = msrcryptoSha1;
    }

    var /*@dynamic*/ hashFunction;
    var blockSize;
    var keyBytes;

    var ipad;
    var opad;

    function xorArrays(array1, array2) {
        var newArray = new Array(array1);
        for (var i = 0 ; i < array1.length; i++) {
            newArray[i] = array1[i] ^ array2[i];
        }
        return newArray;
    }

    // Returns a new Array with zeroes padded on the end
    function padZeros(bytes, paddedLength) {
        var paddedArray = bytes.slice();
        for (var i = bytes.length ; i < paddedLength; i++) {
            paddedArray.push(0);
        }
        return paddedArray;
    }
    
    function padKey() {

        if (keyBytes.length === blockSize) {
            return keyBytes;
        }

        if (keyBytes.length > blockSize) {
            return padZeros(hashFunction.computeHash(keyBytes), blockSize);
        }

        // If keyBytes.length < blockSize
        return padZeros(keyBytes, blockSize);

    }

    var paddedKey = null;
    var keyXorOpad;

    function processHmac(messageBytes) {

        var keyXorIpad;
        var k0IpadText;

        // If this is the first process call, do some initial computations
        if (!paddedKey) {
            ipad = new Array(blockSize);
            opad = new Array(blockSize);
            for (var i = 0; i < blockSize; i++) { ipad[i] = 0x36; opad[i] = 0x5c; }

            paddedKey = padKey();
            keyXorIpad = xorArrays(paddedKey, ipad);
            keyXorOpad = xorArrays(paddedKey, opad);
            k0IpadText = keyXorIpad.concat(messageBytes);
            hashFunction.process(k0IpadText);

            // Subsequent process calls just add to the hash
        } else {

            hashFunction.process(messageBytes);
        }

        return;
    }

    function finishHmac() {

        var hashK0IpadText = hashFunction.finish();

        var k0IpadK0OpadText = keyXorOpad.concat(hashK0IpadText);

        return hashFunction.computeHash(k0IpadK0OpadText);
    }

    function clearState() {
        keyBytes = null;
        hashFunction = null;
        paddedKey = null;
    }

    function selectHashAlgorithm(hashAlgorithmName) {

        switch (hashAlgorithmName.toLowerCase()) {

            case "sha-1":
                if (sha1 === undefined) {
                    throw new Error("Sha1 object not found");
                }
                hashFunction = sha1.sha1;
                blockSize = 64;
                break;

            case "sha-224":
                hashFunction = sha256.sha224;
                blockSize = 64;
                break;

            case "sha-256":
                hashFunction = sha256.sha256;
                blockSize = 64;
                break;

            case "sha-384":
                if (sha512 === undefined) {
                    throw new Error("Sha512 object not found");
                }
                hashFunction = sha512.sha384;
                blockSize = 128;
                break;

            case "sha-512":
                if (sha512 === undefined) {
                    throw new Error("Sha512 object not found");
                }
                hashFunction = sha512.sha512;
                blockSize = 128;
                break;

            default:
                throw new Error("unsupported hash alorithm (sha-224, sha-256, sha-384, sha-512)");
        }

    }

    return {

        computeHmac: function (dataBytes, key, hashAlgorithm) {
            /// <summary>Computes the HMAC</summary>
            /// <param name="dataBytes" type="Array">Data to MAC</param>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>
            /// <returns type="Array">Returns an array of bytes as the HMAC</returns>

            keyBytes = key;

            selectHashAlgorithm(hashAlgorithm);

            processHmac(dataBytes);

            var result = finishHmac();

            clearState();

            return result;
        },

        process: function (dataBytes, key, hashAlgorithm) {
            /// <summary>Computes a partial HMAC to be followed by subsequent process calls or finish()</summary>
            /// <param name="dataBytes" type="Array">Data to MAC</param>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>

            if (!hashFunction) {
                keyBytes = key;
                selectHashAlgorithm(hashAlgorithm);
            }

            processHmac(dataBytes);
        },

        finish: function (key, hashAlgorithm) {
            /// <summary>Computes the final HMAC upon partial computations from previous process() calls.</summary>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>
            /// <returns type="Array">Returns an array of bytes as the HMAC</returns>

            // Finish could be called before any processing. We'll return the hmac
            // of an empty buffer.
            if (!hashFunction) {
                keyBytes = key;
                selectHashAlgorithm(hashAlgorithm);
                processHmac([]);
            }

            var result = finishHmac();
            clearState();
            return result;
        }

    };
})();

if (typeof operations !== "undefined") {

    msrcryptoHmac.signHmac = function (p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash;

        if (p.operationSubType === "process") {
            msrcryptoHmac.process(p.buffer, p.keyData, hashName);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoHmac.finish(p.keyData, hashName);
        }

        return msrcryptoHmac.computeHmac(p.buffer, p.keyData, hashName);
    };

    msrcryptoHmac.verifyHmac = function (p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash;

        if (p.operationSubType === "process") {
            msrcryptoHmac.process(p.buffer, p.keyData, hashName);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoUtilities.arraysEqual(msrcryptoHmac.finish(p.keyData, hashName), p.signature);
        }

        return msrcryptoUtilities.arraysEqual(msrcryptoHmac.computeHmac(p.buffer, p.keyData, hashName), p.signature);
    };

    msrcryptoHmac.generateKey = function (p) {

        var keyLength = p.algorithm.length;

        var defaultKeyLengths = { "sha-256": 32, "sha-384": 48, "sha-512": 64 };

        if (!keyLength) {
            keyLength = defaultKeyLengths[p.algorithm.hash.name];
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(keyLength),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoHmac.importKey = function (p) {

        var keyObject = { alg: p.algorithm.hash.name };

        if (p.format == "raw") {
            keyObject.k = p.keyData;
        } else {
            keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);
        }

        keyObject.alg = keyObject.alg.replace("HS", "sha-");

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: {
                algorithm: { name: "hmac", hash: { name: keyObject.alg } },
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: "secret"
            }
        };

    };

    msrcryptoHmac.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "hmac", msrcryptoHmac.importKey);
    operations.register("exportKey", "hmac", msrcryptoHmac.exportKey);
    operations.register("generateKey", "hmac", msrcryptoHmac.generateKey);
    operations.register("sign", "hmac", msrcryptoHmac.signHmac);
    operations.register("verify", "hmac", msrcryptoHmac.verifyHmac);
}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoUtilities */

/* jshint -W016 */ /* allows bitwise operators */

/// <reference path="utilities.js" />

/// <dictionary>
///    msrcrypto,aes,mult,rcon,res,tmp,xor
/// </dictionary>

/// #endregion JSCop/JsHint

var msrcryptoBlockCipher = (function()  {

    var aesConstants,
    multByTwo,
    multByThree,
    multBy14,
    multBy13,
    multBy11,
    multBy9,
    sBoxTable,
    invSBoxTable,
    rConTable;

    return {

        /// <summary>Advanced Encryption Standard implementation per FIPS 197.</summary>
        aes: function ( /*@type(Array)*/ keyBytes) {

            // Set up the constants the first time we create an AES object only.
            if (!aesConstants) {
                aesConstants = msrcryptoUtilities.unpackData("AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4bGR8dExEXFQsJDw0DAQcFOzk/PTMxNzUrKS8tIyEnJVtZX11TUVdVS0lPTUNBR0V7eX99c3F3dWtpb21jYWdlm5mfnZORl5WLiY+Ng4GHhbu5v72zsbe1q6mvraOhp6Xb2d/d09HX1cvJz83DwcfF+/n//fPx9/Xr6e/t4+Hn5QADBgUMDwoJGBseHRQXEhEwMzY1PD86OSgrLi0kJyIhYGNmZWxvaml4e359dHdycVBTVlVcX1pZSEtOTURHQkHAw8bFzM/Kydjb3t3U19LR8PP29fz/+vno6+7t5Ofi4aCjpqWsr6qpuLu+vbS3srGQk5aVnJ+amYiLjo2Eh4KBm5idnpeUkZKDgIWGj4yJiquora6npKGis7C1tr+8ubr7+P3+9/Tx8uPg5ebv7Onqy8jNzsfEwcLT0NXW39zZ2ltYXV5XVFFSQ0BFRk9MSUpraG1uZ2RhYnNwdXZ/fHl6Ozg9Pjc0MTIjICUmLywpKgsIDQ4HBAECExAVFh8cGRoADhwSODYkKnB+bGJIRlRa4O788tjWxMqQnoyCqKa0utvVx8nj7f/xq6W3uZOdj4E7NScpAw0fEUtFV1lzfW9hraOxv5WbiYfd08HP5ev5901DUV91e2lnPTMhLwULGRd2eGpkTkBSXAYIGhQ+MCIslpiKhK6gsrzm6Pr03tDCzEFPXVN5d2VrMT8tIwkHFRuhr72zmZeFi9HfzcPp5/X7mpSGiKKsvrDq5Pb40tzOwHp0ZmhCTF5QCgQWGDI8LiDs4vD+1NrIxpySgI6kqri2DAIQHjQ6KCZ8cmBuREpYVjc5KyUPARMdR0lbVX9xY23X2cvF7+Hz/aepu7WfkYONAA0aFzQ5LiNoZXJ/XFFGS9Ddysfk6f7zuLWir4yBlpu7tqGsj4KVmNPeycTn6v3wa2ZxfF9SRUgDDhkUNzotIG1gd3pZVENOBQgfEjE8Kya9sKeqiYSTntXYz8Lh7Pv21tvMweLv+PW+s6SpioeQnQYLHBEyPyglbmN0eVpXQE3a18DN7uP0+bK/qKWGi5yRCgcQHT4zJClib3h1VltMQWFse3ZVWE9CCQQTHj0wJyqxvKumhYifktnUw87t4Pf6t7qtoIOOmZTf0sXI6+bx/GdqfXBTXklEDwIVGDs2ISwMARYbODUiL2RpfnNQXUpH3NHGy+jl8v+0ua6jgI2alwALFh0sJzoxWFNORXR/Ymmwu6atnJeKgejj/vXEz9LZe3BtZldcQUojKDU+DwQZEsvA3dbn7PH6k5iFjr+0qaL2/eDr2tHMx66luLOCiZSfRk1QW2phfHceFQgDMjkkL42Gm5Chqre81d7DyPny7+Q9NisgERoHDGVuc3hJQl9U9/zh6tvQzcavpLmyg4iVnkdMUVprYH12HxQJAjM4JS6Mh5qRoKu2vdTfwsn48+7lPDcqIRAbBg1kb3J5SENeVQEKFxwtJjswWVJPRHV+Y2ixuqesnZaLgOni//TFztPYenFsZ1ZdQEsiKTQ/DgUYE8rB3Nfm7fD7kpmEj761qKMACRIbJC02P0hBWlNsZX53kJmCi7S9pq/Y0crD/PXu5zsyKSAfFg0Ec3phaFdeRUyrormwj4adlOPq8fjHztXcdn9kbVJbQEk+NywlGhMIAebv9P3Cy9DZrqe8tYqDmJFNRF9WaWB7cgUMFx4hKDM63dTPxvnw6+KVnIeOsbijquzl/vfIwdrTpK22v4CJkpt8dW5nWFFKQzQ9Ji8QGQIL197FzPP64eiflo2Eu7KpoEdOVVxjanF4DwYdFCsiOTCak4iBvrespdLbwMn2/+TtCgMYES4nPDVCS1BZZm90faGos7qFjJee6eD78s3E39YxOCMqFRwHDnlwa2JdVE9GY3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7FlIJatUwNqU4v0CjnoHz1/t84zmCmy//hzSOQ0TE3unLVHuUMqbCIz3uTJULQvrDTgguoWYo2SSydluiSW2L0SVy+PZkhmiYFtSkXMxdZbaSbHBIUP3tudpeFUZXp42dhJDYqwCMvNMK9+RYBbizRQbQLB6Pyj8PAsGvvQMBE4prOpERQU9n3OqX8s/O8LTmc5asdCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA7Ta4q9bDI67s8g1OZYRcrBH66d9Ym4WkUY1UhDH2NAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuN", 256, false);
                multByTwo = aesConstants[0];
                multByThree = aesConstants[1];
                multBy14 = aesConstants[2];
                multBy13 = aesConstants[3];
                multBy11 = aesConstants[4];
                multBy9 = aesConstants[5];
                sBoxTable = aesConstants[6];
                invSBoxTable = aesConstants[7];
                rConTable = aesConstants[8];
            }

            var blockSize = 128,
                keyLength,
                nK,
                nB = 4,
                nR,
                key;

            switch (keyBytes.length * 8) {

                case 128:
                    keyLength = 128;
                    nK = 4;
                    nR = 10;
                    break;

                case 192:
                    keyLength = 192;
                    nK = 6;
                    nR = 12;
                    break;

                case 256:
                    keyLength = 256;
                    nK = 8;
                    nR = 14;
                    break;

                default:
                    throw new Error("Unsupported keyLength");
            }

            var shiftRows = function (a) {
                var tmp = a[1]; a[1] = a[5]; a[5] = a[9]; a[9] = a[13]; a[13] = tmp;
                tmp = a[2]; a[2] = a[10]; a[10] = tmp;
                tmp = a[6]; a[6] = a[14]; a[14] = tmp;
                tmp = a[15]; a[15] = a[11]; a[11] = a[7]; a[7] = a[3]; a[3] = tmp;
            };

            var invShiftRows = function (a) {
                var tmp = a[13]; a[13] = a[9]; a[9] = a[5]; a[5] = a[1]; a[1] = tmp;
                tmp = a[10]; a[10] = a[2]; a[2] = tmp;
                tmp = a[14]; a[14] = a[6]; a[6] = tmp;
                tmp = a[3]; a[3] = a[7]; a[7] = a[11]; a[11] = a[15]; a[15] = tmp;
            };

            var mixColumns = function (state) {
                /// <summary>Operates on the state column by column, performing a multiplication by x^4 + 1 in GF(2^8)</summary>
                /// <param name="state" type="Array"> the current state (length 16)</param>
                /// <returns type="Array">The mixed state</returns>
                var a = state[0], b = state[1], c = state[2], d = state[3],
                    e = state[4], f = state[5], g = state[6], h = state[7],
                    i = state[8], j = state[9], k = state[10], l = state[11],
                    m = state[12], n = state[13], o = state[14], p = state[15];

                state[0] = multByTwo[a] ^ multByThree[b] ^ c ^ d;
                state[1] = a ^ multByTwo[b] ^ multByThree[c] ^ d;
                state[2] = a ^ b ^ multByTwo[c] ^ multByThree[d];
                state[3] = multByThree[a] ^ b ^ c ^ multByTwo[d];
                state[4] = multByTwo[e] ^ multByThree[f] ^ g ^ h;
                state[5] = e ^ multByTwo[f] ^ multByThree[g] ^ h;
                state[6] = e ^ f ^ multByTwo[g] ^ multByThree[h];
                state[7] = multByThree[e] ^ f ^ g ^ multByTwo[h];
                state[8] = multByTwo[i] ^ multByThree[j] ^ k ^ l;
                state[9] = i ^ multByTwo[j] ^ multByThree[k] ^ l;
                state[10] = i ^ j ^ multByTwo[k] ^ multByThree[l];
                state[11] = multByThree[i] ^ j ^ k ^ multByTwo[l];
                state[12] = multByTwo[m] ^ multByThree[n] ^ o ^ p;
                state[13] = m ^ multByTwo[n] ^ multByThree[o] ^ p;
                state[14] = m ^ n ^ multByTwo[o] ^ multByThree[p];
                state[15] = multByThree[m] ^ n ^ o ^ multByTwo[p];
            };

            var invMixColumns = function (state) {
                /// <summary>Operates on the state column by column, performing a multiplication by x^4 + 1 in GF(2^8)</summary>
                /// <param name="state" type="Array"> the current state (length 16)</param>
                /// <returns type="Array">The mixed state</returns>
                var a = state[0], b = state[1], c = state[2], d = state[3],
                    e = state[4], f = state[5], g = state[6], h = state[7],
                    i = state[8], j = state[9], k = state[10], l = state[11],
                    m = state[12], n = state[13], o = state[14], p = state[15];

                state[0] = multBy14[a] ^ multBy11[b] ^ multBy13[c] ^ multBy9[d];
                state[1] = multBy9[a] ^ multBy14[b] ^ multBy11[c] ^ multBy13[d];
                state[2] = multBy13[a] ^ multBy9[b] ^ multBy14[c] ^ multBy11[d];
                state[3] = multBy11[a] ^ multBy13[b] ^ multBy9[c] ^ multBy14[d];
                state[4] = multBy14[e] ^ multBy11[f] ^ multBy13[g] ^ multBy9[h];
                state[5] = multBy9[e] ^ multBy14[f] ^ multBy11[g] ^ multBy13[h];
                state[6] = multBy13[e] ^ multBy9[f] ^ multBy14[g] ^ multBy11[h];
                state[7] = multBy11[e] ^ multBy13[f] ^ multBy9[g] ^ multBy14[h];
                state[8] = multBy14[i] ^ multBy11[j] ^ multBy13[k] ^ multBy9[l];
                state[9] = multBy9[i] ^ multBy14[j] ^ multBy11[k] ^ multBy13[l];
                state[10] = multBy13[i] ^ multBy9[j] ^ multBy14[k] ^ multBy11[l];
                state[11] = multBy11[i] ^ multBy13[j] ^ multBy9[k] ^ multBy14[l];
                state[12] = multBy14[m] ^ multBy11[n] ^ multBy13[o] ^ multBy9[p];
                state[13] = multBy9[m] ^ multBy14[n] ^ multBy11[o] ^ multBy13[p];
                state[14] = multBy13[m] ^ multBy9[n] ^ multBy14[o] ^ multBy11[p];
                state[15] = multBy11[m] ^ multBy13[n] ^ multBy9[o] ^ multBy14[p];
            };

            var xorWord = function (a, b) {
                return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
            };

            var addRoundKey = function (/*@type(Array)*/state, keySchedule, offset) {
                for (var i = 0 ; i < state.length ; i += 1) {
                    state[i] ^= keySchedule[i + offset];
                }
            };

            var rotWord = function (/*@type(Array)*/word) {
                var a = word[0];
                word[0] = word[1]; word[1] = word[2]; word[2] = word[3]; word[3] = a;
            };

            var subWord = function (/*@type(Array)*/word) {
                for (var i = 0 ; i < word.length ; i += 1) {
                    word[i] = sBoxTable[word[i]];
                }
            };

            var invSubWord = function (/*@type(Array)*/word) {
                for (var i = 0 ; i < word.length ; i += 1) {
                    word[i] = invSBoxTable[word[i]];
                }
            };

            var getWord = function (tab, i) {
                return [tab[4 * i], tab[4 * i + 1], tab[4 * i + 2], tab[4 * i + 3]];
            };

            var setWord = function (/*@type(Array)*/left, /*@type(Array)*/right, indexL, indexR) {
                left[4 * indexL] = right[4 * indexR];
                left[4 * indexL + 1] = right[4 * indexR + 1];
                left[4 * indexL + 2] = right[4 * indexR + 2];
                left[4 * indexL + 3] = right[4 * indexR + 3];
            };

            var expandKey = function (key) {
                var temp, res = [], i = 0;
                while (i < 4 * nK) {
                    res.push(key[i++]);
                }

                i = nK;
                while (i < nB * (nR + 1)) {
                    temp = getWord(res, i - 1);
                    if (i % nK === 0) {
                        var index = i / nK;
                        var rcon = [rConTable[index], 0, 0, 0];
                        rotWord(temp);
                        subWord(temp);
                        temp = xorWord(temp, rcon);
                    } else if (nK > 6 && i % nK === 4) {
                        subWord(temp);
                    }
                    var newWord = xorWord(getWord(res, i - nK), temp);
                    setWord(res, newWord, i, 0);
                    i += 1;
                }
                return res;
            };

            key = expandKey(keyBytes);

            return {

                encrypt: function (dataBytes) {
                    var state = dataBytes,
                        round;

                    addRoundKey(state, key, 0);
                    for (round = 1 ; round <= nR - 1 ; round += 1) {
                        subWord(state);
                        shiftRows(state);
                        mixColumns(state);
                        addRoundKey(state, key, 4 * round * nB);
                    }
                    subWord(state);
                    shiftRows(state);
                    addRoundKey(state, key, 4 * nR * nB);

                    return state;
                },

                decrypt: function (dataBytes) {
                    var state = dataBytes,
                        round;

                    addRoundKey(state, key, 4 * nR * nB);
                    for (round = nR - 1 ; round >= 1 ; round -= 1) {
                        invShiftRows(state);
                        invSubWord(state);
                        addRoundKey(state, key, 4 * round * nB);
                        invMixColumns(state);
                    }
                    invShiftRows(state);
                    invSubWord(state);
                    addRoundKey(state, key, 0);

                    return state;
                },

                clear: function () {
                    // Reset the state
                },

                keyLength: keyLength,

                blockSize: blockSize

            };
        }

    };

})();
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */
/* global operations */
/* global msrcryptoUtilities */
/* global msrcryptoBlockCipher */
/* jshint -W016 */ /* allows bitwise operators */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="operations.js" />
/// <reference path="jwk.js" />
/// <reference path="aes.js" />

/// <dictionary>
///     Cbc,msrcrypto,res
/// </dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoPadding = msrcryptoPadding || {};

msrcryptoPadding.pkcsv7 = function (message, blockSize) {

    /// <summary>apply PKCS7 padding to message, which is updated</summary>
    /// <param name="message" type="Array"></param>
    /// <param name="blockSize" type="Number"></param>
    /// <returns></returns>
    var lastIndex = message.length - 1 >= 0 ? message.length - 1 : 0,
        lastBlock = message[lastIndex],
        lastBlockLength = lastBlock.length,
        createNewBlock = (lastBlockLength === blockSize);

    if (createNewBlock) {
        var newBlock = [], i;
        for (i = 0 ; i < blockSize; i += 1) {
            newBlock.push(blockSize);
        }
        message.push(newBlock);
    } else {
        var byteToAdd = (blockSize - lastBlockLength) & 0xff;
        while (lastBlock.length !== blockSize) {
            lastBlock.push(byteToAdd);
        }
    }
};

var msrcryptoCbc = function (blockCipher) {

    var blockSize = blockCipher.blockSize / 8;

    var paddingScheme = msrcryptoPadding.pkcsv7;

    // Merges an array of block arrays into a single byte array
    var mergeBlocks = function (/*@type(Array)*/tab) {
        var res = [], i, j;
        for (i = 0 ; i < tab.length; i += 1) {
            var block = tab[i];
            for (j = 0 ; j < block.length; j += 1) {
                res.push(block[j]);
            }
        }
        return res;
    };

    // Breaks an array of bytes into an array of block size arrays of bytes
    function getBlocks(dataBytes) {

        var blocks = [];

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(dataBytes);

        var blockCount = Math.floor(mBuffer.length / blockSize);

        for (var i = 0; i < blockCount; i++) {
            blocks.push(mBuffer.slice(i * blockSize, (i + 1) * blockSize));
        }

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(blockCount * blockSize);

        return blocks;
    }

    function encryptBlocks(blocks) {

        var result = [],
            toEncrypt;

        for (var i = 0; i < blocks.length; i++) {
            toEncrypt = msrcryptoUtilities.xorVectors(mIvBytes, blocks[i]);
            result.push(blockCipher.encrypt(toEncrypt));
            mIvBytes = result[i];
        }

        return result;
    }

    function decryptBlocks(blocks) {

        var result = [],
            toDecrypt,
            decrypted;

        for (var i = 0 ; i < blocks.length; i += 1) {
            toDecrypt = blocks[i].slice(0, blocks[i].length);
            decrypted = blockCipher.decrypt(toDecrypt);
            result.push(msrcryptoUtilities.xorVectors(mIvBytes, decrypted));
            mIvBytes = blocks[i];
        }

        return result;
    }

    function clearState() {
        mBuffer = [];
        mResultBuffer = [];
        mIvBytes = null;
    }

    var mBuffer = [],
        mResultBuffer = [],
        mIvBytes;

    return {

        init: function (ivBytes) {

            if (ivBytes.length !== blockSize) {
                throw new Error("Invalid iv size");
            }

            mIvBytes = ivBytes.slice();
        },

        // Does a full encryption of the input
        encrypt: function (plainBytes) {
            /// <summary>perform the encryption of the plain text message</summary>
            /// <param name="plainBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processEncrypt(plainBytes);

            return this.finishEncrypt();
        },

        // Encrypts full blocks of streamed input
        processEncrypt: function (plainBytes) {

            var result = encryptBlocks(getBlocks(plainBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Call when done streaming input
        finishEncrypt: function () {

            var blocks = mBuffer.length === 1 ? [[mBuffer[0]]] : [mBuffer];

            paddingScheme(blocks, blockSize);

            var result = mResultBuffer.concat(mergeBlocks(encryptBlocks(blocks)));

            clearState();

            return result;
        },

        // Does a full decryption and returns the result
        decrypt: function (/*@type(Array)*/cipherBytes) {
            /// <summary>perform the decryption of the encrypted message</summary>
            /// <param name="encryptedBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processDecrypt(cipherBytes);

            return this.finishDecrypt();
        },

        // Decrypts full blocks of streamed data
        processDecrypt: function (cipherBytes) {

            var result = decryptBlocks(getBlocks(cipherBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Called to finalize streamed decryption
        finishDecrypt: function () {

            var result = mResultBuffer;

            // Strip the padding.
            // Read the last element and strip off that many elements from the end.
            result = result.slice(0, result[result.length - 1] * -1);

            clearState();

            return result;
        }

    };
};

var cbcInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoCbc.workerEncrypt = function (p) {

        var result;

        if (!cbcInstance) {
            cbcInstance = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstance.init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstance.processEncrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstance.finishEncrypt();
            cbcInstance = null;
            return result;
        }

        result = cbcInstance.encrypt(p.buffer);
        cbcInstance = null;
        return result;
    };

    msrcryptoCbc.workerDecrypt = function (p) {

        var result;

        if (!cbcInstance) {
            cbcInstance = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstance.init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstance.processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstance.finishDecrypt();
            cbcInstance =  null;
            return result;
        }

        result = cbcInstance.decrypt(p.buffer);
        cbcInstance =  null;
        return result;
    };

    msrcryptoCbc.generateKey = function (p) { 

        if (p.algorithm.length % 8 !== 0) {
            throw new Error();
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoCbc.importKey = function (p) {

        var keyObject = {};

        if (p.format == "raw") {
            keyObject.k = p.keyData;
        } else {
            keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);
        }

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoCbc.exportKey = function (p) { 

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "aes-cbc", msrcryptoCbc.importKey);
    operations.register("exportKey", "aes-cbc", msrcryptoCbc.exportKey);
    operations.register("generateKey", "aes-cbc", msrcryptoCbc.generateKey);
    operations.register("encrypt", "aes-cbc", msrcryptoCbc.workerEncrypt);
    operations.register("decrypt", "aes-cbc", msrcryptoCbc.workerDecrypt);
}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */
/* global operations */
/* global msrcryptoUtilities */
/* global msrcryptoBlockCipher */
/* jshint -W016 */ /* allows bitwise operators */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="operations.js" />
/// <reference path="jwk.js" />
/// <reference path="aes.js" />

/// <dictionary>
///     Gcm,gcrt,Gctr,ghash,icb,msrcrypto,Subkey,utils
/// </dictionary>

/// <disable>IncorrectNumberOfArguments</disable>

/// #endregion JSCop/JsHint

var msrcryptoGcm = function (/*@type(msrcryptoAes)*/ blockCipher) {

    var utils = msrcryptoUtilities;

    var /*@type(Array)*/ mBuffer = [],
        /*@type(Array)*/ mIvBytes,
        /*@type(Array)*/ mAdditionalBytes,
        /*@type(Number)*/ mTagLength,
        /*@type(Array)*/ mJ0,
        /*@type(Array)*/ mJ0inc,
        /*@type(Array)*/ mH = blockCipher.encrypt(utils.getVector(16)),
        /*@type(Array)*/ mGHashState = utils.getVector(16),
        /*@type(Array)*/ mGHashBuffer = [],
        /*@type(Array)*/ mCipherText = [],
        /*@type(Array)*/ mGctrCb,
        /*@type(Number)*/ mBytesProcessed = 0;

    function ghash(/*@type(Array)*/hashSubkey, /*@type(Array)*/dataBytes) {

        var blockCount = Math.floor(dataBytes.length / 16),
            dataBlock;

        for (var i = 0; i < blockCount; i++) {
            dataBlock = dataBytes.slice(i * 16, i * 16 + 16);
            mGHashState = blockMultiplication(utils.xorVectors(mGHashState, dataBlock), hashSubkey);
        }

        mGHashBuffer = dataBytes.slice(blockCount * 16);

        return mGHashState;
    }

    function finishGHash() {

        var u = 16 * Math.ceil(mBytesProcessed / 16) - mBytesProcessed;

        var lenA = numberTo8Bytes(mAdditionalBytes.length * 8),
            lenC = numberTo8Bytes(mBytesProcessed * 8);

        var p = mGHashBuffer.concat(utils.getVector(u)).concat(lenA).concat(lenC);

        return ghash(mH, p);

    }

    function blockMultiplication(/*@type(Array)*/blockX, /*@type(Array)*/blockY) {

        var z = utils.getVector(16),
            v = blockY.slice(),
            r = [0xe1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            bit;

        for (var i = 0; i < 128; i++) {
            bit = getBit(blockX, i);

            if (bit === 1) {
                z = utils.xorVectors(z, v);
            }

            if (v[15] & 1) {
                shiftRight(v);
                v = utils.xorVectors(v, r);
            } else {
                shiftRight(v);
            }
        }

        return z;
    }

    function shiftRight(/*@type(Array)*/dataBytes) {

        for (var i = dataBytes.length - 1; i > 0; i--) {
            dataBytes[i] = ((dataBytes[i - 1] & 1) << 7) | (dataBytes[i] >>> 1);
        }
        dataBytes[0] = dataBytes[0] >>> 1;

        return dataBytes;
    }

    function getBit(/*@type(Array)*/byteArray, bitNumber) {
        var byteIndex = Math.floor(bitNumber / 8);
        return (byteArray[byteIndex] >> (7 - (bitNumber % 8))) & 1;
    }

    function inc(/*@type(Array)*/dataBytes) {

        var carry = 256;
        for (var i = 1; i <= 4; i++) {
            carry = (carry >>> 8) + dataBytes[dataBytes.length - i];
            dataBytes[dataBytes.length - i] = carry & 255;
        }

        return dataBytes;
    }

    function gctr(/*@type(Array)*/icb, /*@type(Array)*/dataBytes) {

        var blockCount = Math.ceil(dataBytes.length / 16),
            dataBlock,
            result = [];

        // We copy icb the first time gctr is called
        if (mGctrCb !== icb) {
            mGctrCb = icb.slice();
        }

        for (var block = 0; block < blockCount; block++) {

            dataBlock = dataBytes.slice(block * 16, block * 16 + 16);

            // The block cipher alters the input array, so we pass a copy.
            var e = blockCipher.encrypt(mGctrCb.slice());

            result = result.concat(utils.xorVectors(dataBlock, e));

            mGctrCb = inc(mGctrCb);
        }

        return result;
    }

    function numberTo8Bytes(number) {
        return [
            0, 0, 0, 0,
            (number >>> 24) & 255,
            (number >>> 16) & 255,
            (number >>> 8) & 255,
            number & 255
        ];
    }

    function padBlocks(/*@type(Array)*/dataBytes) {
        var padLen = 16 * Math.ceil(mAdditionalBytes.length / 16) - mAdditionalBytes.length;
        return dataBytes.concat(utils.getVector(padLen));
    }

    function clearState() {
        mBytesProcessed = 0;
        mBuffer = [];
        mCipherText = [];
        mGHashState = utils.getVector(16);
        mGHashBuffer = [];
        mGctrCb = mIvBytes = mAdditionalBytes = null;
    }

    function init(/*@type(Array)*/ivBytes, /*@type(Array)*/additionalBytes, tagLength) {

        mAdditionalBytes = additionalBytes || [];

        mTagLength = tagLength || 128;
        if (mTagLength % 8 !== 0) {
            throw new Error("DataError");
        }

        mIvBytes = ivBytes;

        if (mIvBytes.length === 12) {
            mJ0 = mIvBytes.concat([0, 0, 0, 1]);

        } else {
            var l = 16 * Math.ceil(mIvBytes.length / 16) - mIvBytes.length;

            mJ0 = ghash(mH,
                    mIvBytes
                    .concat(utils.getVector(l + 8))
                    .concat(numberTo8Bytes(mIvBytes.length * 8)));

            // Reset the ghash state so we don't affect the encrypt/decrypt ghash
            mGHashState = utils.getVector(16);
        }

        mJ0inc = inc(mJ0.slice());

        ghash(mH, padBlocks(mAdditionalBytes));
    }

    function encrypt(/*@type(Array)*/plainBytes) {

        mBytesProcessed = plainBytes.length;

        var c = gctr(mJ0inc, plainBytes);

        ghash(mH, c);

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        clearState();

        return c.slice().concat(t);
    }

    function decrypt(/*@type(Array)*/cipherBytes, /*@type(Array)*/tagBytes) {

        mBytesProcessed = cipherBytes.length;

        var p = gctr(mJ0inc, cipherBytes);

        ghash(mH, cipherBytes);

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        clearState();

        if (utils.arraysEqual(t, tagBytes)) {
            return p;
        } else {
            return null;
        }
    }

    function processEncrypt(/*@type(Array)*/plainBytes) {

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(plainBytes);

        // Get a run of full blocks
        var fullBlocks = mBuffer.slice(0, Math.floor(mBuffer.length / 16) * 16);

        // Keep track of the total plain bytes processed
        mBytesProcessed += fullBlocks.length;

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(fullBlocks.length);

        // Process the full block with gctr - gctr maintains it's own state
        var c = gctr(mGctrCb || mJ0inc, fullBlocks);

        mCipherText = mCipherText.concat(c);

        // Process the returned blocks from gcrt
        ghash(mH, c);
    }

    function processDecrypt(/*@type(Array)*/cipherBytes) {

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(cipherBytes);

        // Get a run of full blocks.
        // We leave enough data on the end so we don't process the tag.
        var fullBlocks = mBuffer.slice(0, Math.floor((mBuffer.length - mTagLength / 8) / 16) * 16);

        // Keep track of the total plain bytes processed
        mBytesProcessed += fullBlocks.length;

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(fullBlocks.length);

        // Process the full block with gctr - gctr maintains it's own state
        var c = gctr(mGctrCb || mJ0inc, fullBlocks);

        mCipherText = mCipherText.concat(c);

        // Process the returned blocks from gcrt
        ghash(mH, fullBlocks);
    }

    function finishEncrypt() {

        var c = gctr(mGctrCb, mBuffer);

        mCipherText = mCipherText.concat(c);

        mBytesProcessed += mBuffer.length;

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        var result = mCipherText.slice().concat(t);

        clearState();

        return result;
    }

    function finishDecrypt() {

        var tagLength = Math.floor(mTagLength / 8);

        var tagBytes = mBuffer.slice( -tagLength);

        mBuffer = mBuffer.slice(0, mBuffer.length - tagLength);

        var c = gctr(mGctrCb, mBuffer);

        mCipherText = mCipherText.concat(c);

        mBytesProcessed += mBuffer.length;

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        var result = mCipherText.slice();

        clearState();

        if (utils.arraysEqual(t, tagBytes)) {
            return result;
        } else {
            throw new Error("OperationError");
        }
    }

    return {
        init: init,
        encrypt: encrypt,
        decrypt: decrypt,
        processEncrypt: processEncrypt,
        processDecrypt: processDecrypt,
        finishEncrypt: finishEncrypt,
        finishDecrypt: finishDecrypt
    };

};

var gcm;

if (typeof operations !== "undefined") {

    msrcryptoGcm.encrypt = function ( /*@dynamic*/ p) {

        var result;

        if (!gcm) {
            gcm = msrcryptoGcm(msrcryptoBlockCipher.aes(p.keyData));
            gcm.init(p.algorithm.iv, p.algorithm.additionalData, p.algorithm.tagLength);
        }

        if (p.operationSubType === "process") {
            gcm.processEncrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = gcm.finishEncrypt();
            gcm = null;
            return result;
        }

        result = gcm.encrypt(p.buffer);
        gcm = null;
        return result;
    };

    msrcryptoGcm.decrypt = function ( /*@dynamic*/ p) {

        var result;

        if (!gcm) {
            gcm = msrcryptoGcm(msrcryptoBlockCipher.aes(p.keyData));
            gcm.init(p.algorithm.iv, p.algorithm.additionalData, p.algorithm.tagLength);
        }

        if (p.operationSubType === "process") {
            gcm.processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
             result = gcm.finishDecrypt();
            gcm = null;
            return result;
        }

        var tagLength = Math.floor(p.algorithm.tagLength / 8);
        var cipherBytes = p.buffer.slice(0, p.buffer.length - tagLength);
        var tagBytes = p.buffer.slice( -tagLength);

        result = gcm.decrypt(cipherBytes, tagBytes);
        gcm = null;
        return result;
    };

    msrcryptoGcm.generateKey = function ( /*@dynamic*/ p) {

        if (p.algorithm.length % 8 !== 0) {
            throw new Error();
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoGcm.importKey = function ( /*@dynamic*/ p) {

        var /*@dynamic*/ keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoGcm.exportKey = function ( /*@dynamic*/ p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "aes-gcm", msrcryptoGcm.importKey);
    operations.register("exportKey", "aes-gcm", msrcryptoGcm.exportKey);
    operations.register("generateKey", "aes-gcm", msrcryptoGcm.generateKey);
    operations.register("encrypt", "aes-gcm", msrcryptoGcm.encrypt);
    operations.register("decrypt", "aes-gcm", msrcryptoGcm.decrypt);
}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoUtilities */

/* jshint -W016 */

/// <reference path="utilities.js" />
/// <reference path="aes.js" />

/// <dictionary>msrcrypto, utils, xor, res, csrc, nist, nistpubs, prng</dictionary>

/// #endregion JSCop/JsHint

/* @constructor */ function MsrcryptoPrng() {
    /// <summary>Pseudo Random Number Generator function/class.</summary>
    /// <remarks>This is the PRNG engine, not the entropy collector.
    /// The engine must be initialized with adequate entropy in order to generate cryptographically secure
    /// random numbers. It is hard to get entropy, but see the entropy functoin/class for the entropy gatherer.
    /// This is not an object instantiation, but the definition of the object. The actual
    /// object must be instantiated somewhere else as needed.
    /// </remarks>

    if (!(this instanceof MsrcryptoPrng)) {
        throw new Error("create MsrcryptoPrng object with new keyword");
    }

    // Fallback for browsers which do not implements crypto API yet
    // implementation of http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf.
    // Use AES-256 in CTR mode of operation as defined in Section 10.2.1.
    var initialized = false;

    // Internal state definitions are as follows.
    // v : internal variable that will ultimately be the random output
    // key: the AES key (256 bits)
    // keyLen: the AES key length in bytes
    // reseedCounter: the number of requests for pseudorandom bits since instantiation/reseeding
    // reseedInterval: Maximum number of generate calls per seed or reseed. SP800-90A says 2^48 for AES, we use 2^24.
    var key;
    var v;
    var keyLen;
    var seedLen;
    var reseedCounter = 1;
    var reseedInterval = 1 << 24;

    // Initialize this instance (constructor like function)
    initialize();

    function addOne(counter) {
        /// <summary>Adds one to a big integer represented in an array (the first argument).</summary>
        /// <param name="counter" counter="Array">The counter byte array to add one to encoded in big endian; index 0 is the MSW.</param>
        var i;
        for (i = counter.length - 1; i >= 0; i -= 1) {
            counter[i] += 1;
            if (counter[i] >= 256) {
                counter[i] = 0;
            }
            if (counter[i]) {
                break;
            }
        }
    }

    function initialize() {
        /// <summary>Instantiate the PRNG with given entropy and personalization string.</summary>
        /// <param name="entropy" type="Array">Array of bytes obtained from the source of entropy input.</param>
        /// <param name="personalizationString" type="Array">Optional application-provided personalization string.</param>
        key = msrcryptoUtilities.getVector(32);
        v = msrcryptoUtilities.getVector(16);            // AES block length
        keyLen = 32;
        seedLen = 48;       // From SP800-90A, section 10.2.1 as of 2014.
        reseedCounter = 1;
    }

    function reseed(entropy,/*@optional*/ additionalEntropy) {
        /// <summary>Reseed the PRNG with additional entropy.</summary>
        /// <param name="entropy" type="Array">Input entropy.</param>
        /// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>
        additionalEntropy = additionalEntropy || [0];
        if (additionalEntropy.length > seedLen) {
            throw new Error("Incorrect entropy or additionalEntropy length");
        }
        additionalEntropy = additionalEntropy.concat(msrcryptoUtilities.getVector(seedLen - additionalEntropy.length));

        // Process the entropy input in blocks with the same additional entropy.
        // This is equivalent to the caller chunking entropy in blocks and calling this function for each chunk.
        entropy = entropy.concat(msrcryptoUtilities.getVector((seedLen - (entropy.length % seedLen)) % seedLen));
        for (var i = 0; i < entropy.length; i += seedLen) {
            var seedMaterial = msrcryptoUtilities.xorVectors(entropy.slice(i, i + seedLen), additionalEntropy);
            update(seedMaterial);
        }
        reseedCounter = 1;
    }

    function update(providedData) {
        /// <summary>Add the providedData to the internal entropy pool, and update internal state.</summary>
        /// <param name="providedData" type="Array">Input to add to the internal entropy pool.</param>
        var temp = [];
        var blockCipher = new msrcryptoBlockCipher.aes(key);
        while (temp.length < seedLen) {
            addOne(v);
            var toEncrypt = v.slice(0, 16);
            var outputBlock = blockCipher.encrypt(toEncrypt); // AES-256
            temp = temp.concat(outputBlock);
        }
        temp = msrcryptoUtilities.xorVectors(temp, providedData);
        key = temp.slice(0, keyLen);
        v = temp.slice(keyLen);
    }

    function generate(requestedBytes,/*@optional*/ additionalInput) {
        /// <summary>Generate pseudo-random bits, and update the internal PRNG state.</summary>
        /// <param name="requestedBytes" type="Number">Number of pseudorandom bytes to be returned.</param>
        /// <param name="additionalInput" type="Array">Application-provided additional input array (optional).</param>
        /// <returns>Generated pseudorandom bytes.</returns>
        if (requestedBytes >= 65536) {
            throw new Error("too much random requested");
        }
        if (reseedCounter > reseedInterval) {
            throw new Error("Reseeding is required");
        }
        if (additionalInput && additionalInput.length > 0) {
            while (additionalInput.length < seedLen) {
                additionalInput = additionalInput.concat(msrcryptoUtilities.getVector(seedLen - additionalInput.length));
            }
            update(additionalInput);
        } else {
            additionalInput = msrcryptoUtilities.getVector(seedLen);
        }
        var temp = [];
        var blockCipher = new msrcryptoBlockCipher.aes(key);
        while (temp.length < requestedBytes) {
            addOne(v);
            var toEncrypt = v.slice(0, v.length);
            var outputBlock = blockCipher.encrypt(toEncrypt);
            temp = temp.concat(outputBlock);
        }
        temp = temp.slice(0, requestedBytes);
        update(additionalInput);
        reseedCounter += 1;
        return temp;
    }

    return {
        reseed: reseed,
        /// <summary>Reseed the PRNG with additional entropy.</summary>
        /// <param name="entropy" type="Array">Input entropy.</param>
        /// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>

        init: function (entropy,/*@optional*/ personalization) {
            /// <summary>Initialize the PRNG by seeing with entropy and optional input data.</summary>
            /// <param name="entropy" type="Array">Input entropy.</param>
            /// <param name="personalization" type="Array">Optional input.</param>
            if (entropy.length < seedLen) {
                throw new Error("Initial entropy length too short");
            }
            initialize();
            reseed(entropy, personalization);
            initialized = true;
        },
        getBytes: function (length, /*@optional*/ additionalInput) {
            if (!initialized) {
                throw new Error("can't get randomness before initialization");
            }
            return generate(length, /*@optional*/ additionalInput);
        },
        getNonZeroBytes: function (length, additionalInput) {
            if (!initialized) {
                throw new Error("can't get randomness before initialization");
            }
            var result = [], buff;
            while (result.length < length) {
                buff = generate(length, additionalInput);
                for (var i = 0 ; i < buff.length; i += 1) {
                    if (buff[i] !== 0) {
                        result.push(buff[i]);
                    }
                }
            }
            return result.slice(0, length);
        }
    };
}

// This is the PRNG object per instantiation, including one per worker.
// The instance in the main thread is used to seed the instances in workers.
// TODO: Consider combining the entropy pool in the main thread with the PRNG instance in the main thread.
/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var msrcryptoPseudoRandom = new MsrcryptoPrng();
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoUtilities */
/* global arrayHelper */
/* global MsrcryptoPrng */

/* jshint -W016 */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="arrayHelper.js" />
/// <reference path="jsCopDefs.js" />

/// <dictionary>arr,msrcrypto,Prng,req,res,mozilla,polyfill,PRNGs,redirectlocale,redirectslug</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

function MsrcryptoEntropy() {
    /// <summary>Opportunistic entropy collector.</summary>
    /// <remarks>See E.Stark, M.Hamburg, D.Boneh, "Symmetric Cryptography in Javascript", ACSAC, 2009.
    /// This is not an object instantiation, but the definition of the object. The actual
    /// object must be instantiated somewhere else as needed.
    /// If window.{crypto,msCrypto}.getRandomValues() function is present, do not register mouse and JS load events,
    /// because they slow down the execution, and it is not clear how much they contributed over and above
    /// a cryptographic random value.
    /// </remarks>

    var poolLength = 48;      // In bytes, from SP800-90A, Section 10.2.1. See random.js for constraints.
    var collectorPool = [];
    var collectorPoolLength = 128;  // Bytes to collect before stopping; collectors are restartable.
    var collectorsRegistered = 0;
    var entropyPoolPrng = new MsrcryptoPrng();
    var initialized = false;
    var cryptographicPRNGPresent = false;
    var headerList = ["Cookie", "RedirectUri", "ETag", "x-ms-client-antiforgery-id", "x-ms-client-request-id", "x-ms-client-session-id", "SubscriptionPool"];

    function collectEntropy() {
        /// <summary>Initialize the internal pool with as much randomness as one can get in JS.
        /// In the worst case, there is zero bits of entropy.</summary>

        var i, pool = [];

        // In Safari, as of r39510, reportedly, Math.random() is cryptographically secure on Mac and Windows.
        // Even if it isn't, mix that in via XORing into the existing array.
        // According to ECMA, Math.random() returns [0,1). Thus, multiply it by 256 to get [0,256).
        for (i = 0; i < poolLength; i += 1) {
            pool[i] = Math.floor(Math.random() * 256);
        }

        // For browsers that implement window.crypto.getRandomValues, use it.
        var prngCrypto = window.crypto || window.msCrypto;       // WARNING: !!! Do not put this in a function (remember polyfill) !!!
        if (prngCrypto && typeof prngCrypto.getRandomValues === "function") {
            if (window.Uint8Array) {
                var res = new window.Uint8Array(poolLength);
                prngCrypto.getRandomValues(res);
                pool = pool.concat(Array.apply(null, /*@static_cast(Array)*/res));
                cryptographicPRNGPresent = true;
            }
        }

        // Read HTTP headers that contain entropy and reseed the entropy pool
        var req = new XMLHttpRequest();
        for (i = 0; i < headerList.length; i += 1) {
            try {
                var header = req.getResponseHeader(headerList[i]);
                if (header) {
                    var arr = msrcryptoUtilities.stringToBytes(header);
                    pool = pool.concat(arr);
                }
            }
            catch (err) {
                // Ignore any header I can't get
            }
        }

        if (!cryptographicPRNGPresent) {
            // Add any data in the collector pool, empty the collector pool, and restart collectors.
            pool = pool.concat(collectorPool.splice(0, collectorPool.length));
            collectors.startCollectors();
        }

        // Worst case: initialized with Math.random()
        initialized ? entropyPoolPrng.reseed(pool) : entropyPoolPrng.init(pool);
        initialized = true;
    }

    function updatePool(entropyData) {
        /// <summary>Collect the incoming data into the pool, and
        /// empty the pool into the entropy PRNG state when the pool is full.
        /// This function is additive entropy, only; this is not the main source of entropy.</summary>
        /// <param name="entropyData" type="Array">Entropy input.</param>
        for (var i = 0; i < entropyData.length; ++i) {
            collectorPool.push(entropyData[i]);
        }
        if (collectorPool.length >= collectorPoolLength) {
            // Stop the collectors (performance reasons).
            // The real entropy does not come from the event callbacks: these are at best uniquifiers.
            collectors.stopCollectors();
        }
    }

    // Event listeners are not supported in IE 8.
    // See https://developer.mozilla.org/en-US/docs/Web/API/EventTarget.addEventListener?redirectlocale=en-US&redirectslug=DOM%2FEventTarget.addEventListener
    // to add IE8 support.
    // BUGBUG: For the time being, I am not bothering with IE8 support - fix this.
    var collectors = (function () {
        return {
            startCollectors: function () {
                if (!this.collectorsRegistered) {
                    if (window.addEventListener) {
                        window.addEventListener("mousemove", this.MouseEventCallBack, true);
                        window.addEventListener("load", this.LoadTimeCallBack, true);
                    } else if (document.attachEvent) {
                        document.attachEvent("onmousemove", this.MouseEventCallBack);
                        document.attachEvent("onload", this.LoadTimeCallBack);
                    } else {
                        throw new Error("Can't attach events for entropy collection");
                    }

                    this.collectorsRegistered = 1;
                }
            },
            stopCollectors: function () {
                if (this.collectorsRegistered) {
                    if (window.removeEventListener) {
                        window.removeEventListener("mousemove", this.MouseEventCallBack, 1);
                        window.removeEventListener("load", this.LoadTimeCallBack, 1);
                    } else if (window.detachEvent) {
                        window.detachEvent("onmousemove", this.MouseEventCallBack);
                        window.detachEvent("onload", this.LoadTimeCallBack);
                    }

                    this.collectorsRegistered = 0;
                }
            },
            MouseEventCallBack: function (eventData) {
                /// <summary>Add the mouse coordinates to the entropy pool and the Date.</summary>
                /// <param name="eventData">Event data with mouse information.</param>
                var d = (new Date()).valueOf();
                var x = eventData.x || eventData.clientX || eventData.offsetX || 0;
                var y = eventData.y || eventData.clientY || eventData.offsetY || 0;
                var arr = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff,
                        x & 0x0ff, (x >> 8) & 0x0ff, y & 0x0ff, (y >> 8) & 0x0ff];

                updatePool(arr);
            },
            LoadTimeCallBack: function () {
                /// <summary>Add date to the entropy pool.</summary>
                /// <remarks>Date valueOf() returns milliseconds since midnight 1/1/1970 UTC in a 32 bit integer</remarks>
                var d = (new Date()).valueOf();
                var dateArray = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff];

                updatePool(dateArray);
            }
        };
    })();

    return {
        init: function () {
            collectEntropy();

            // Register collectors
            if (!cryptographicPRNGPresent && !collectorsRegistered) {
                try {
                    collectors.startCollectors();
                }
                catch (e) {
                    // Ignore errors instead of trying to do something browser specific. That is not tractable.
                    // It is expected that the calling program injects most of the entropy or the build-in collectors
                    // contributes rather than registered events.
                }
            }
        },

        reseed: function (entropy) {
            /// <summary>Mix in entropy into the pool.</summary>
            /// <param name="entropy" type="Array">Entropy to mix in.</param>
            entropyPoolPrng.reseed(entropy);
        },

        read: function (length) {
            /// <summary>Read entropy from the entropy pool. This function fails if there isn't enough entropy.</summary>
            /// <param name="length" type="Number">Number of bytes of requested entropy.</param>
            /// <returns type="Array">Entropy if there is enough in the pool, or undefined if there isn't enough entropy.</returns>
            if (!initialized) {
                throw new Error("Entropy pool is not initialized.");
            }

            var ret = entropyPoolPrng.getBytes(length);

            // TODO: Do this async?
            //       No, another call may come through before the pool is reseeded.
            //       All PRNGs have their own running state anyhow. They can reseed themselves in async mode, if need be.
            collectEntropy();

            return ret;
        }
    };
}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global cryptoMath */
/* global msrcryptoUtilities */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="cryptoMath.js " />

/// <dictionary>mgf,rsa,Struct,utils</dictionary>

/// <disable>DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoRsaBase = function (keyStruct) {

    var utils = msrcryptoUtilities,
        keyIsPrivate = keyStruct.hasOwnProperty("n") && keyStruct.hasOwnProperty("d"),
        keyIsCrt = keyStruct.hasOwnProperty("p") && keyStruct.hasOwnProperty("q"),
        modulusLength = keyStruct.n.length;

    function toBytes(digits) {

        var bytes = cryptoMath.digitsToBytes(digits);

        // Add leading zeros until the message is the proper length.
        utils.padFront(bytes, 0, modulusLength);

        return bytes;
    }

    function /*@type(Bytes)*/ modExp(/*@type(Bytes)*/ dataBytes, /*@type(Bytes)*/ expBytes,/*@type(Bytes)*/  modulusBytes) {
        /// <returns type="Array">Result in a digit array.</returns>
        var exponent = cryptoMath.bytesToDigits(expBytes);

        var group = cryptoMath.IntegerGroup(modulusBytes);
        var base = group.createElementFromBytes(dataBytes);
        var result = group.modexp(base, exponent);

        return result.m_digits;
    }

    function decryptModExp(cipherBytes) {

        var resultElement = modExp(cipherBytes, keyStruct.d, keyStruct.n);

        return toBytes(resultElement);
    }

    function decryptCrt(cipherBytes) {

        var p = keyStruct.p,
            q = keyStruct.q,
            dp = keyStruct.dp,
            dq = keyStruct.dq,
            invQ = keyStruct.qi,
            pDigits = cryptoMath.bytesToDigits(p),
            qDigits = cryptoMath.bytesToDigits(q),
            temp = new Array(pDigits.length + qDigits.length),
            m1Digits = new Array(pDigits.length + 1),
            m2Digits = new Array(qDigits.length + 1),
            cDigits = cryptoMath.bytesToDigits(cipherBytes);

        // 'm1' = (c mod p)^dP mod p
        cryptoMath.reduce(cDigits, pDigits, temp);
        cryptoMath.modExp(temp, cryptoMath.bytesToDigits(dp), pDigits, m1Digits);

        // 'm2' = (c mod q)^dQ mod q
        cryptoMath.reduce(cDigits, qDigits, temp);
        cryptoMath.modExp(temp, cryptoMath.bytesToDigits(dq), qDigits, m2Digits);

        // 'diff' = (m1 - m2). Compute as follows to have |m1 - m2|.
        //      m1 - m2     if m1>=m2.
        //      m2 - m1     if m1<m2.
        // Correct the sign after modular multiplication by qInv by subtracting the product from p.
        var carry = cryptoMath.subtract(m1Digits, m2Digits, temp);
        if (carry !== 0) {
            cryptoMath.subtract(m2Digits, m1Digits, temp);
        }

        // 'h' = (m1 - m2)^qInv mod p
        cryptoMath.modMul(temp, cryptoMath.bytesToDigits(invQ), pDigits, cDigits);
        if (carry !== 0) {
            cryptoMath.subtract(pDigits, cDigits, cDigits);
        }

        // 'm2' + q*h
        cryptoMath.multiply(cDigits, qDigits, temp);
        cryptoMath.add(m2Digits, temp, m1Digits);

        return toBytes(m1Digits);
    }

    return {

        encrypt: function (messageBytes) {

            return toBytes(modExp(messageBytes, keyStruct.e, keyStruct.n));

        },

        decrypt: function (cipherBytes) {

            if (keyIsCrt) {
                return decryptCrt(cipherBytes);
            }

            if (keyIsPrivate) {
                return decryptModExp(cipherBytes);
            }

            throw new Error("missing private key");
        }
    };

};

var rsaShared = {

    mgf1: function (seedBytes, maskLen, hashFunction) {

        var t = [], bytes, hash, counter,
            hashByteLen = hashFunction.hashLen / 8;

        for (counter = 0; counter <= Math.floor(maskLen / hashByteLen) ; counter += 1) {

            bytes = [counter >>> 24 & 0xff,
                    counter >>> 16 & 0xff,
                    counter >>> 8 & 0xff,
                    counter & 0xff];

            hash = hashFunction.computeHash(seedBytes.concat(bytes));

            t = t.concat(hash);
        }

        return t.slice(0, maskLen);
    },

    checkMessageVsMaxHash: function (messageBytes, hashFunction) {

        // The max array size in JS is 2^32-1
        if (messageBytes.length > (hashFunction.maxMessageSize || 0xFFFFFFFF)) {
            throw new Error("message too long");
        }

        return;
    }

};
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoUtilities */
/* global rsaShared */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="random.js " />
/// <reference path="rsa-base.js " />

/// <dictionary>Struct,unpad,Hashp,maskeddb,rsa,utils</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var rsaMode = rsaMode || {};
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>

rsaMode.oaep = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        random = msrcryptoPseudoRandom,
        size = keyStruct.n.length;

    if (hashFunction === null) {
        throw new Error("must supply hashFunction");
    }

    function pad(/*@type(Array)*/ message, /*@optional*/ label) {

        var lHash, psLen, psArray, i, db, seed;
        var dbMask, maskeddb, seedMask, maskedSeed;
        var /*@type(Array)*/ encodedMessage;

        if (message.length > (size - 2 * (hashFunction.hashLen / 8) - 2)) {
            throw new Error("Message too long.");
        }

        label || (label = []);

        lHash = hashFunction.computeHash(/*@static_cast(Digits)*/label);

        psLen = size - message.length - (2 * lHash.length) - 2;
        psArray = utils.getVector(psLen);

        // 'db' = 'lHash' || 'psArray' || 0x01 || message
        db = lHash.concat(psArray, [1], message);

        seed = random.getBytes(lHash.length);

        dbMask = rsaShared.mgf1(seed, size - lHash.length - 1, hashFunction);

        maskeddb = utils.xorVectors(db, dbMask);

        seedMask = rsaShared.mgf1(maskeddb, lHash.length, hashFunction);

        maskedSeed = utils.xorVectors(seed, seedMask);

        encodedMessage = [0].concat(maskedSeed).concat(maskeddb);

        message = encodedMessage.slice();

        return encodedMessage;
    }

    function unpad(/*@type(Array)*/ encodedBytes, /*@optional*/ labelBytes) {

        var lHash, maskedSeed, maskeddb, seedMask;
        var seed, dbMask, db;
        var lHashp;

        if (!labelBytes) {
            labelBytes = [];
        }

        lHash = hashFunction.computeHash(labelBytes);

        if (encodedBytes[0] !== 0) {
            throw new Error("Encryption Error");
        }

        maskedSeed = encodedBytes.slice(1, lHash.length + 1);
        maskeddb = encodedBytes.slice(lHash.length + 1);

        seedMask = rsaShared.mgf1(maskeddb, lHash.length, hashFunction);
        seed = utils.xorVectors(maskedSeed, seedMask);
        dbMask = rsaShared.mgf1(seed, size - lHash.length - 1, hashFunction);

        db = utils.xorVectors(maskeddb, dbMask);

        lHashp = db.slice(0, lHash.length);

        // lHashp should equal lHash or 'Encryption Error'
        if (!utils.arraysEqual(lHash, lHashp)) {
            throw new Error("Encryption Error");
        }

        db = db.slice(lHash.length);

        // There will be a bunch of zeros followed by a 
        var i = utils.indexOf(db, 1);

        return db.slice(i + 1);
    }

    return {

        pad: function (/*@type(Array)*/ messageBytes, /*@optional*/ labelBytes) {
            return pad(messageBytes, labelBytes);
        },

        unpad: function (/*@type(Array)*/ encodedBytes, /*@optional*/ labelBytes) {
            return unpad(encodedBytes, labelBytes);
        }
    };

};

//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoUtilities */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="random.js " />

/// <dictionary>emp,emsa,pkcs,rsa,Struct,tlen,unpad,utils</dictionary>

/// <disable></disable>

/// #endregion JSCop/JsHint

var rsaMode = rsaMode || {};

rsaMode.pkcs1Encrypt = function (keyStruct) {

    var random = msrcryptoPseudoRandom,
        size = keyStruct.n.length;

    function pad(data) {

        var randomness;

        if (data.length > size - 11) {
            throw new Error("message too long");
        }

        // A minimum of 8 random bytes
        randomness = random.getNonZeroBytes(size - data.length - 3);

        return [0, 2].concat(randomness, [0], data);
    }

    function unpad(paddedData) {
        var i;

        for (i = 1; i < paddedData.length; i += 1) {
            if (paddedData[i] === 0) {
                break;
            }
        }

        return paddedData.slice(i + 1);
    }

    return {

        pad: function (messageBytes) {
            return pad(messageBytes);
        },

        unpad: function (encodedBytes) {
            return unpad(encodedBytes);
        }
    };

};

rsaMode.pkcs1Sign = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        size = keyStruct.n.length;

    function emsa_pkcs1_v15_encode(messageBytes) {

        var paddedData,
            hash,
            tlen;

        hash = hashFunction.computeHash(messageBytes.slice());

        paddedData = hashFunction.der.concat(hash);

        tlen = paddedData.length;

        if (size < tlen + 11) {
            throw new Error("intended encoded message length too short");
        }

        return [0x00, 0x01].concat(
            utils.getVector(size - tlen - 3, 0xFF),
            [0],
            paddedData);
    }

    return {

        sign: function (messageBytes) {
            return emsa_pkcs1_v15_encode(messageBytes);
        },

        verify: function (signatureBytes, messageBytes) {
            var emp = emsa_pkcs1_v15_encode(messageBytes);

            return utils.arraysEqual(signatureBytes, emp);
        }
    };
};

//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoUtilities */
/* global rsaShared */

/* jshint -W016 */

/// <dictionary>emsa,rsa,Struct,utils,octect</dictionary>

/// <disable>DeclareVariablesBeforeUse, DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var rsaMode = rsaMode || {};
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>

rsaMode.pss = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        random = msrcryptoPseudoRandom;

    function emsa_pss_encode(messageBytes) {

        var emBits = (keyStruct.n.length * 8) - 1;

        var emLen = Math.ceil(emBits / 8);

        //// checkMessageVsMaxHash(messageBytes);

        var /*@type(Array)*/ mHash = hashFunction.computeHash(messageBytes);

        var sLen = mHash.length;

        if (emLen < (mHash.length + sLen + 2)) {
            throw new Error("encoding error");
        }

        var /*@type(Array)*/ salt = random.getBytes(sLen);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [0, 0, 0, 0, 0, 0, 0, 0].concat(mHash, salt);

        var /*@type(Array)*/ h = hashFunction.computeHash(mp);

        var /*@type(Array)*/ ps = utils.getVector(emLen - salt.length - h.length - 2);

        var /*@type(Array)*/ db = ps.concat([1], salt);

        var /*@type(Array)*/ dbMask = rsaShared.mgf1(h, emLen - h.length - 1, hashFunction);

        var /*@type(Array)*/ maskedDb = utils.xorVectors(db, dbMask);

        // Set the ((8 * emLen) - emBits) of the leftmost octect in maskedDB to zero
        var mask = 0;
        for (var i = 0; i < 8 - ((8 * emLen) - emBits) ; i++) {
            mask += 1 << i;
        }
        maskedDb[0] &= mask;

        var em = maskedDb.concat(h, [0xbc]);

        return em;
    }

    function emsa_pss_verify( /*@type(Array)*/ signatureBytes,/*@type(Array)*/ messageBytes) {

        var emBits = (keyStruct.n.length * 8) - 1;

        var emLen = Math.ceil(emBits / 8);

        //// checkMessageVsMaxHash(messageBytes);

        var mHash = hashFunction.computeHash(messageBytes);

        var sLen = hashFunction.hashLen / 8;

        var hLen = hashFunction.hashLen / 8;

        if (emLen < (hLen + sLen + 2)) {
            return false;
        }

        var maskedDb = signatureBytes.slice(0, emLen - hLen - 1);

        var h = signatureBytes.slice(maskedDb.length, maskedDb.length + hLen);

        var dbMask = rsaShared.mgf1(h, emLen - hLen - 1, hashFunction);

        var /*@type(Array)*/ db = utils.xorVectors(maskedDb, dbMask);

        // Set the leftmost 8 * emLen - emBits of db[0] to zero
        db[0] &= 0xFF >>> (8 - ((8 * emLen) - emBits));

        // Verify the leftmost bytes are zero
        for (var i = 0; i < (emLen - hLen - sLen - 2) ; i++) {
            if (db[i] !== 0) {
                return false;
            }
        }

        if (db[emLen - hLen - sLen - 2] !== 0x01) {
            return false;
        }

        var salt = db.slice( -sLen);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [0, 0, 0, 0, 0, 0, 0, 0].concat(mHash, salt);

        var hp = hashFunction.computeHash(mp);

        return utils.arraysEqual(hp, h);
    }

    return {

        sign: function (messageBytes) {
            return emsa_pss_encode(messageBytes);
        },

        verify: function (signatureBytes, messageBytes) {
            return emsa_pss_verify(signatureBytes, messageBytes);
        }
    };
};
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global msrcryptoRsaBase */
/* global rsaMode */
/* global operations */
/* global msrcryptoJwk */
/* global msrcryptoSha256 */
/* global msrcryptoSha512 */
/* global msrcryptoSha1 */

/* jshint -W016 */

/// <dictionary>Func,msrcrypto,Obj,Rsa,Struct,unpad</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoRsa = function (keyStruct, paddingMode, /*@optional*/ hashFunction) {

    var rsaBase = msrcryptoRsaBase(keyStruct);

    if (!paddingMode) {
        throw new Error("padding mode");
    }

    if (!hashFunction) {
        hashFunction = msrcryptoSha256.sha256;
    }

    var paddingFunction = null,
        unPaddingFunction = null;

    var padding;

    switch (paddingMode) {

        case "rsaes-pkcs1-v1_5":
            padding = rsaMode.pkcs1Encrypt(keyStruct, hashFunction);
            break;

        case "rsassa-pkcs1-v1_5":
            padding = rsaMode.pkcs1Sign(keyStruct, hashFunction);
            break;

        case "rsa-oaep":
            padding = rsaMode.oaep(keyStruct, hashFunction);
            break;

        case "rsa-pss":
            padding = rsaMode.pss(keyStruct, hashFunction);
            break;

        case "raw":
            padding = {
                pad: function (mb) { return mb; },
                unpad: function (eb) { return eb; }
            };
            break;

        default:
            throw new Error("invalid padding mode");
    }

    if (padding) {
        paddingFunction = padding.pad || padding.sign;
        unPaddingFunction = padding.unpad || padding.verify;
    }

    var returnObj = {

        encrypt: function (/*@type(Array)*/ dataBytes, /*@optional*/ labelBytes) {

            var paddedData;

            if (paddingFunction !== null) {
                // OAEP padding can take two arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                paddedData = paddingFunction(dataBytes, labelBytes);
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            } else {
                // Slice() has optional arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                paddedData = dataBytes.slice();
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            }

            return rsaBase.encrypt(paddedData);
        },

        decrypt: function (/*@type(Array)*/ cipherBytes, /*@optional*/ labelBytes) {

            var /*@type(Array)*/ decryptedData = rsaBase.decrypt(cipherBytes);

            if (unPaddingFunction !== null) {
                // OAEP padding can take two arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                decryptedData = unPaddingFunction(decryptedData, labelBytes);
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            } else {
                decryptedData = decryptedData.slice(0);
            }

            return decryptedData;
        },

        signData: function (/*@type(Array)*/ messageBytes) {

            return rsaBase.decrypt(paddingFunction(messageBytes));
        },

        verifySignature: function (/*@type(Array)*/ signature, /*@type(Array)*/ messageBytes) {

            var decryptedSig = rsaBase.encrypt(signature);

            return unPaddingFunction(decryptedSig, messageBytes);
        },

        paddingMode: paddingMode
    };

    return returnObj;
};

if (typeof operations !== "undefined") {

    msrcryptoRsa.sign = function ( /*@dynamic*/ p) {

        var rsaObj,
            hashFunc,
            hashName = p.algorithm.hash.name || p.algorithm.hash;

        hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()];

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.signData(p.buffer);
    };

    msrcryptoRsa.verify = function ( /*@dynamic*/ p) {

        var hashFunc,
            hashName = p.algorithm.hash.name || p.algorithm.hash,
            rsaObj;

        hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()];

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.verifySignature(p.signature, p.buffer);
    };

    msrcryptoRsa.workerEncrypt = function ( /*@dynamic*/ p) {

        var result,
            rsaObj,
            hashFunc;

        switch (p.algorithm.name) {

            case "rsaes-pkcs1-v1_5":
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                result = rsaObj.encrypt(p.buffer);
                break;

            case "rsa-oaep":
                var hashName = p.algorithm.hash.name || p.algorithm.hash;
                if (!hashName) {
                    throw new Error("unsupported hash algorithm");
                }
                hashFunc = msrcryptoHashFunctions[hashName];
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                result = rsaObj.encrypt(p.buffer);
                break;

            default:
                throw new Error("unsupported algorithm");
        }

        return result;
    };

    msrcryptoRsa.workerDecrypt = function ( /*@dynamic*/ p) {

        var result,
            rsaObj,
            hashFunc;

        switch (p.algorithm.name) {

            case "rsaes-pkcs1-v1_5":
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                result = rsaObj.decrypt(p.buffer);
                break;

            case "rsa-oaep":
                switch (p.algorithm.hash.name || p.algorithm.hash) {
                    case "sha-384":
                        hashFunc = msrcryptoSha512.sha384;
                        break;
                    case "sha-512":
                        hashFunc = msrcryptoSha512.sha512;
                        break;
                    case "sha-1":
                        hashFunc = msrcryptoSha1.sha1;
                        break;
                    default:
                        hashFunc = msrcryptoSha256.sha256;
                        break;
                }
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                result = rsaObj.decrypt(p.buffer);
                break;

            default:
                throw new Error("unsupported algorithm");
        }

        return result;
    };

    msrcryptoRsa.importKey = function ( /*@dynamic*/ p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["n", "e", "d", "q", "p", "dq", "dp", "qi"]);

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: (keyObject.d || keyObject.dq) ? "private" : "public"
            }
        };
    };

    msrcryptoRsa.exportKey = function ( /*@dynamic*/ p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("sign", "rsassa-pkcs1-v1_5", msrcryptoRsa.sign);
    operations.register("sign", "rsa-pss", msrcryptoRsa.sign);

    operations.register("verify", "rsassa-pkcs1-v1_5", msrcryptoRsa.verify);
    operations.register("verify", "rsa-pss", msrcryptoRsa.verify);

    operations.register("encrypt", "rsa-oaep", msrcryptoRsa.workerEncrypt);
    operations.register("encrypt", "rsaes-pkcs1-v1_5", msrcryptoRsa.workerEncrypt);

    operations.register("decrypt", "rsa-oaep", msrcryptoRsa.workerDecrypt);
    operations.register("decrypt", "rsaes-pkcs1-v1_5", msrcryptoRsa.workerDecrypt);

    operations.register("importKey", "rsa-oaep", msrcryptoRsa.importKey);
    operations.register("importKey", "rsaes-pkcs1-v1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "rsa-pss", msrcryptoRsa.importKey);

    operations.register("exportKey", "rsa-oaep", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsaes-pkcs1-v1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsa-pss", msrcryptoRsa.exportKey);

}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* global msrcryptoUtilities */
/* global msrcryptoSha256 */
/* global msrcryptoSha512 */
/* global msrcryptoSha1 */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="sha256.js " />
/// <reference path="sha512.js " />

/// <dictionary>alg,Func,Kdf,msrcrypto,utils</dictionary>

/// <disable>DeclareVariablesBeforeUse,DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// The "concat" key derivation function from NIST SP-800-56A.
var msrcryptoKdf = function (hashFunction) {

    var utils = msrcryptoUtilities;

    function deriveKey(/*type(Array)*/ secretBytes, /*type(Array)*/ otherInfo, keyOutputLength) {

        var reps = Math.ceil(keyOutputLength / (hashFunction.hashLen / 8)),
            counter = 1,
            digest = secretBytes.concat(otherInfo),
            output = [];

        for (var i = 0; i < reps; i++) {

            var data = utils.int32ToBytes(counter++).concat(digest);

            var /*type(Array)*/ h = hashFunction.computeHash(data);

            output = output.concat(h);
        }

        return output.slice(0, keyOutputLength);
    }

    return {

        deriveKey: deriveKey

    };

};

var msrcryptoKdfInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoKdf.deriveKey = function (/*@dynamic*/p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash;

        var hashFunction = msrcryptoHashFunctions[hashName.toLowerCase()];

        msrcryptoKdfInstance = msrcryptoKdf(hashFunction);

        var alg = p.algorithm;

        var otherInfo =
            alg.algorithmId.concat(
            alg.partyUInfo,
            alg.partyVInfo,
            alg.publicInfo || [],
            alg.privateInfo || []);

        var result =
            msrcryptoKdfInstance.deriveKey(p.keyData, otherInfo, p.derivedKeyType.length);

        msrcryptoKdfInstance = null;

        return {
            type: "keyDerive",
            keyData: result,
            keyHandle: {
                algorithm: p.derivedKeyType,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };

    };

    msrcryptoKdf.deriveBits = function (/*@dynamic*/p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash;

        var hashFunction = msrcryptoHashFunctions[hashName.toLowerCase()];

        msrcryptoKdfInstance = msrcryptoKdf(hashFunction);

        var alg = p.algorithm;

        var otherInfo =
            alg.algorithmId.concat(
            alg.partyUInfo,
            alg.partyVInfo,
            alg.publicInfo || [],
            alg.privateInfo || []);

        var result =
            msrcryptoKdfInstance.deriveKey(p.keyData, otherInfo, p.length);

        msrcryptoKdfInstance = null;

        return result;

    };

    operations.register("deriveKey", "concat", msrcryptoKdf.deriveKey);
    operations.register("deriveBits", "concat", msrcryptoKdf.deriveBits);

}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* global cryptoMath */
/* global cryptoECC */
/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */

/// <dictionary>btd,dtb,Ecdh,ecop,msrcrypto</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoEcdh = function (curve) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        e = curve,
        ecop = new cryptoECC.EllipticCurveOperatorFp(curve);

    function generateKey() {

        var privateKey = [],
            randomBytes = msrcryptoPseudoRandom.getBytes(
                curve.order.length * cryptoMath.DIGIT_NUM_BYTES);

        cryptoMath.reduce(
            cryptoMath.bytesToDigits(randomBytes),
            e.order,
            privateKey);

        if (!e.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(e.generator);
        }

        var publicKey = e.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(privateKey, e.generator, publicKey);

        return {
            privateKey: {
                x: dtb(publicKey.x),
                y: dtb(publicKey.y),
                d: dtb(privateKey)
            },
            publicKey: {
                x: dtb(publicKey.x),
                y: dtb(publicKey.y)
            }
        };
    }

    function deriveBits(privateKey, publicKey, length) {

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            e, false, btd(publicKey.x), btd(publicKey.y), null, false);

        if (!publicPoint.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(publicPoint);
        }

        if (!publicPoint.isAffine) {
            ecop.convertToAffineForm(publicPoint);
        }

        var sharedSecretPoint = e.allocatePointStorage();
        ecop.convertToJacobianForm(sharedSecretPoint);
        ecop.convertToMontgomeryForm(sharedSecretPoint);

        ecop.scalarMultiply(btd(privateKey.d), publicPoint, sharedSecretPoint);

        ecop.convertToAffineForm(sharedSecretPoint);
        ecop.convertToStandardForm(sharedSecretPoint);

        var secretBytes = cryptoMath.digitsToBytes(sharedSecretPoint.x);

        if (length && secretBytes.length < length) {
            throw new Error("DataError");
        }

        return length ? secretBytes.slice(0, length) : secretBytes;
    }

    function computePublicKey(privateKeyBytes) {

        if (!e.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(e.generator);
        }

        var publicKey = e.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(btd(privateKeyBytes), e.generator, publicKey);

        return {
            x: dtb(publicKey.x),
            y: dtb(publicKey.y)
        };
    }

    return {

        generateKey: generateKey,
        deriveBits: deriveBits,
        computePublicKey: computePublicKey
    };

};

var ecdhInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoEcdh.curves = {
        "P-256": cryptoECC.createP256,
        "P-384": cryptoECC.createP384,
        "P-521": cryptoECC.createP521
    };

    msrcryptoEcdh.deriveBits = function (p) {

        var curve = msrcryptoEcdh.curves[p.algorithm.namedCurve]();

        var privateKey = p.keyData;

        var publicKey = p.additionalKeyData;

        ecdhInstance = msrcryptoEcdh(curve);

        var secretBytes = ecdhInstance.deriveBits(privateKey, publicKey, p.length);

        return secretBytes;
    };

    msrcryptoEcdh.generateKey = function (p) {

        var curve = msrcryptoEcdh.curves[p.algorithm.namedCurve]();

        ecdhInstance = msrcryptoEcdh(curve);

        var keyPairData = ecdhInstance.generateKey();

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: keyPairData.publicKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: keyPairData.privateKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "private"
                    }
                }
            }
        };
    };

    msrcryptoEcdh.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["x", "y", "d", "crv"]);

        // If only private key data 'd' is imported, create x and y
        if (keyObject.d && (!keyObject.x || !keyObject.y)) {

            var curve = msrcryptoEcdh.curves[p.algorithm.namedCurve]();

            ecdhInstance = msrcryptoEcdh(curve);

            var publicKey = ecdhInstance.computePublicKey(keyObject.d);

            keyObject.x = publicKey.x;
            keyObject.y = publicKey.y;
        }

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: (keyObject.d) ? "private" : "public"
            }
        };
    };

    msrcryptoEcdh.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };

    };

    operations.register("importKey", "ecdh", msrcryptoEcdh.importKey);
    operations.register("exportKey", "ecdh", msrcryptoEcdh.exportKey);
    operations.register("generateKey", "ecdh", msrcryptoEcdh.generateKey);
    operations.register("deriveBits", "ecdh", msrcryptoEcdh.deriveBits);
}
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/// <reference path="utilities.js" />
/// <reference path="cryptoMath.js" />
/// <reference path="cryptoECC.js" />
/// <reference path="sha256.js" />
/// <reference path="sha512.js" />

/* global operations */
/* global msrcryptoHashFunctions */
/* global cryptoMath */
/* global cryptoECC */
/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */

/* jshint -W016 */

/// <dictionary>btd,dtb,Ecdsa,ecop,msrcrypto</dictionary>

/// <disable>DeclareVariablesBeforeUse,DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoEcdsa = function (curve) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        ecop = new cryptoECC.EllipticCurveOperatorFp(curve);

    function createKey(privateKeyBytes) {
        return createKeyInternal(btd(privateKeyBytes));
    }

    function createKeyInternal(privateKeyDigits) {

        if (!curve.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(curve.generator);
        }

        var publicKey = curve.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(privateKeyDigits, curve.generator, publicKey);

        ecop.convertToAffineForm(publicKey);
        ecop.convertToStandardForm(publicKey);

        return {
            publicKey: publicKey,
            privateKey: privateKeyDigits
        };
    }

    function generateKey() {

        var privateKey = [],
            randomBytes = msrcryptoPseudoRandom.getBytes(
                curve.order.length * cryptoMath.DIGIT_NUM_BYTES);

        cryptoMath.reduce(
            cryptoMath.bytesToDigits(randomBytes),
            curve.order,
            privateKey);

        if (!curve.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(curve.generator);
        }

        return createKeyInternal(privateKey);
    }

    function sign(privateKey, messageBytes, /*@optional*/ ephemeralKey) {

        if (!ephemeralKey) {
            do {
                ephemeralKey = generateKey();
            } while (cryptoMath.isZero(ephemeralKey.publicKey.x) ||
                cryptoMath.compareDigits(curve.order, ephemeralKey.publicKey.x) === 0);
        }

        if (!ephemeralKey.publicKey) {
            throw new Error("ephemeralKey.publicKey missing");
        }

        if (!ephemeralKey.privateKey) {
            throw new Error("ephemeralKey.privateKey missing");
        }

        var r = ephemeralKey.publicKey.x;
        var k = ephemeralKey.privateKey;

        var d = btd(privateKey.d);
        var s = [], tmp = [];

        cryptoMath.modMul(r, d, curve.order, s);
        cryptoMath.add(s, btd(messageBytes), s);
        cryptoMath.reduce(s, curve.order, s);

        cryptoMath.modInv(k, curve.order, tmp);
        cryptoMath.modMul(s, tmp, curve.order, s);

        var signature = dtb(r).concat(dtb(s));

        return signature;
    }

    function verify(publicKey, signatureBytes, messageBytes) {

        var split = Math.floor(signatureBytes.length / 2),
            r = btd(signatureBytes.slice(0, split)),
            s = btd(signatureBytes.slice(split)),
            digest = btd(messageBytes),
            u1 = [],
            u2 = [];

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            curve, false, btd(publicKey.x), btd(publicKey.y), null, false);

        cryptoMath.modInv(s, curve.order, s);
        cryptoMath.modMul(digest, s, curve.order, u1);

        cryptoMath.modMul(r, s, curve.order, u2);

        var r0 = curve.allocatePointStorage();
        ecop.convertToJacobianForm(r0);
        ecop.convertToMontgomeryForm(r0);

        if (!curve.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(curve.generator);
        }

        if (!curve.generator.isAffine) {
            ecop.convertToStandardForm(curve.generator);
        }

        ecop.scalarMultiply(u1, curve.generator, r0);

        var r1 = curve.allocatePointStorage();
        ecop.convertToJacobianForm(r1);
        ecop.convertToMontgomeryForm(r1);

        ecop.convertToMontgomeryForm(publicPoint);

        ecop.scalarMultiply(u2, publicPoint, r1);
        ecop.convertToAffineForm(r1);
        ecop.mixedAdd(r0, r1, r0);

        ecop.convertToAffineForm(r0);
        ecop.convertToStandardForm(r0);

        if (r0.isInfinity) {
            return false;
        }

        if (cryptoMath.compareDigits(r0.x, r) === 0) {
            return true;
        }

        return false;
    }

    return {
        createKey: createKey,
        generateKey: generateKey,
        sign: sign,
        verify: verify
    };

};

if (typeof operations !== "undefined") {

    msrcryptoEcdsa.curves = {
        "p-256": cryptoECC.createP256,
        "p-384": cryptoECC.createP384
    };

    msrcryptoEcdsa.sign = function ( /*@dynamic*/ p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash,
            curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve](),
            hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()],
            digest = hashFunc.computeHash(p.buffer);

        var ecdsa = msrcryptoEcdsa(curve);

        return ecdsa.sign(p.keyData, digest);
    };

    msrcryptoEcdsa.verify = function ( /*@dynamic*/ p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash,
            curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve](),
            hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()],
            digest = hashFunc.computeHash(p.buffer);

        var ecdsa = msrcryptoEcdsa(curve);

        return ecdsa.verify(p.keyData, p.signature, digest);
    };

    msrcryptoEcdsa.generateKey = function (p) {

        var curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve]();

        var ecdsa = msrcryptoEcdsa(curve);

        var keyPairData = ecdsa.generateKey();

        var dtb = cryptoMath.digitsToBytes;

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: {
                        x: dtb(keyPairData.publicKey.x),
                        y: dtb(keyPairData.publicKey.y)
                    },
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: {
                        x: dtb(keyPairData.publicKey.x),
                        y: dtb(keyPairData.publicKey.y),
                        d: dtb(keyPairData.privateKey)
                    },
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "private"
                    }
                }
            }
        };

    };

    msrcryptoEcdsa.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["x", "y", "d", "crv"]);

        // If only private key data 'd' is imported, create x and y
        if (keyObject.d && (!keyObject.x || !keyObject.y)) {

            var curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve]();

            var ecdsa = msrcryptoEcdsa(curve);

            var publicKey = ecdsa.computePublicKey(keyObject.d);

            keyObject.x = publicKey.x;
            keyObject.y = publicKey.y;
        }

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: (keyObject.d) ? "private" : "public"
            }
        };
    };

    msrcryptoEcdsa.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };

    };

    operations.register("sign", "ecdsa", msrcryptoEcdsa.sign);

    operations.register("verify", "ecdsa", msrcryptoEcdsa.verify);

    operations.register("generateKey", "ecdsa", msrcryptoEcdsa.generateKey);

    operations.register("importKey", "ecdsa", msrcryptoEcdsa.importKey);

    operations.register("exportKey", "ecdsa", msrcryptoEcdsa.exportKey);

}
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\head.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

// #region JSHint/JSCop
/* global arrayHelper */
/* global asyncMode: true */
/* global createProperty */
/* global defined */
/* global msrcryptoUtilities */
/* global msrcryptoWorker */
/* global msrcryptoPseudoRandom */
/* global fprngEntropyProvided: true */
/* global runningInWorkerInstance */
/* global scriptUrl */
/* global setterSupport */
/* global webWorkerSupport */
/* global operations */
/* jshint -W098 */
/* W098 is 'defined but not used'. We have not-yet-implemented apis stubbed out. */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="worker.js" />
/// <reference path="utilities.js" />

/// These are terms that JSCop thinks are misspelled, so we have to add them to its dictionary
/// <dictionary>
///    concat, msrcrypto, onabort, oncomplete, onerror, onmessage, onprogress, Params, prng,
///    syncWorker, webworker, webworkers, obj
/// </dictionary>

//  JSCop cannot figure out the types correctly
/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

// #endregion JSHint/JSCop

var msrcryptoSubtle;

// This code is not used in web worker instance.
if (!runningInWorkerInstance) {

    msrcryptoSubtle = (function() {
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\syncWorker.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

// This worker is used when webworkers aren't available.
// It will function synchronously but use the same
//   mechanisms that the asynchronous webworkers use.
function syncWorker() {
    var result;

    // PostMessage is how you interact with a worker. You post some data to the worker
    // and it will process it and return it's data to the onmessage function.
    // Since we're really running synchronously, we call the crypto function in
    // PostMessage and wait for the result. Then we call the OnMessage fuction with
    // that result. This will give the same behavior as a web-worker.
    function postMessage(data) {

        // Web-workers will automatically return an error message when an 
        // error is thrown within the web worker.
        // When using a sync worker, we'll have to catch thrown errors, so we
        // need a try/catch block here.
        try {
            result = msrcryptoWorker.jsCryptoRunner(/*@static_cast(typeEvent)*/{ data: data });

            // 'process' operations don't return values, so we don't
            // forward the worker return message.
            if (!data.operationSubType || data.operationSubType !== "process") {
                this.onmessage({ data: result });
            }

        } catch (ex) {
            this.onerror({ data: ex.description, type: "error" });
        }
    }

    return {
        postMessage: postMessage,
        onmessage: null,
        onerror: null,
        terminate: function () {
            // This is a no-op to be compatible with webworker.
        }
    };
}
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\operations.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// <dictionary>Obj,oncomplete,onerror</dictionary>

var ie8OnCompletePollingInterval = 100; // Milliseconds

function baseOperation(processResults) {

    var result = null,
        oncompleteCallback = null,
        onerrorCallback = null,
        retObj;

    function opAddEventListener(eventType, listener) {

    }

    function opRemoveEventListener(eventType, listener) {

    }

    function onCompleteSet(value) {
        oncompleteCallback = value;

        // If we are just now setting the oncomplete event, but we already have a result,
        //   call the oncomplete function passing the result.
        // This can happen if the crypto function finishes before the oncompleted handler has been set.
        if (this.result) {
            oncompleteCallback({ target: this });
        }
    }

    function onErrorSet(value) {
        onerrorCallback = value;
    }

    function onCompleteGet() {
        return oncompleteCallback;
    }

    function onErrorGet() {
        return onerrorCallback;
    }

    function opDispatchEvent(/*@type(Event)*/e) {

        // If the event is an Error call the onError callback
        if (e.type === "error") {

            // If the onerror callback has been set, call it.
            if (this.onerror) {
                this.onerror(e);
            }
            return;
        }

        // If we've returned from a 'process' call, do nothing.
        if (e.type === "process") {
            return;
        }

        // Otherwise call the oncomplete callback
        this.result = processResults(e.data);

        // If the oncomplete callback has been set, call it.
        if (this.oncomplete) {
            this.oncomplete({ target: this });

        } else {  // The oncomplete event has not been set

        }

        return;
    }

    retObj = {
        dispatchEvent: opDispatchEvent,
        addEventListener: opAddEventListener,
        removeEventListener: opRemoveEventListener,
        result: null
    };

    createProperty(retObj, "oncomplete", null, onCompleteGet, onCompleteSet);
    createProperty(retObj, "onerror", null, onErrorGet, onErrorSet);

    return retObj;
}

function keyOperation() {

    function processResult(result) {

        // Could be the result of an import, export, generate.
        // Get the keyData and keyHandle out.
        switch (result.type) {

            // KeyImport: save the new key
            case "keyGeneration":
            case "keyImport":
            case "keyDerive":
                keys.add(result.keyHandle, result.keyData);
                return result.keyHandle;

            // KeyExport: return the export data
            case "keyExport":
                return toArrayBufferIfSupported(result.keyHandle);

            case "keyPairGeneration":
                keys.add(result.keyPair.publicKey.keyHandle, result.keyPair.publicKey.keyData);
                keys.add(result.keyPair.privateKey.keyHandle, result.keyPair.privateKey.keyData);
                return {
                    publicKey: result.keyPair.publicKey.keyHandle,
                    privateKey: result.keyPair.privateKey.keyHandle
                };

            default:
                throw new Error("Unknown key operation");
        }

        return;
    }

    return baseOperation(processResult);
}

function cryptoOperation(cryptoContext) {

    function processResult(result) {

        // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
        result = toArrayBufferIfSupported(result);

        // A normal array will be returned.
        return result;
    }

    var op = baseOperation(processResult);

    op.process = function (buffer) {
        cryptoContext.operationSubType = "process";
        cryptoContext.buffer = utils.toArray(buffer);
        workerManager.continueJob(this,
            utils.clone(cryptoContext));
    };

    op.finish = function () {
        cryptoContext.operationSubType = "finish";
        cryptoContext.buffer = [];
        workerManager.continueJob(this,
            utils.clone(cryptoContext));
    };

    op.abort = function () {
        workerManager.abortJob(this);
    };

    op.onabort = null;
    op.onprogress = null;

    op.algorithm = cryptoContext.algorithm || null;
    op.key = cryptoContext.keyHandle || null;

    return op;
}

function toArrayBufferIfSupported(dataArray) {

    // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
    if (typedArraySupport && dataArray.pop) {

        // We can't write to an ArrayBuffer directly so we create a Uint8Array
        //   and return it's buffer property.
        return (new Uint8Array(dataArray)).buffer;
    }

    // Do nothing and just return the passed-in array.
    return dataArray;
}

// IE8 doesn't support setters/getters on non-dom objects
//   so we have to poll the oncomplete property to see if it's been
//   set, then call it when running in synchronous mode.
function ie8NoSetterFix( /*@type(baseOperation)*/operation) {

    if (operation.oncomplete) {
        operation.oncomplete({ target: operation });
    } else {
        setTimeout(
            function () {
                ie8NoSetterFix(operation);
            }, ie8OnCompletePollingInterval);
    }
}
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\keyManager.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

// Storage for the keyData.
// Stored as {keyHandle: keyHandle, keyData: keyData} objects.
var keys = [];
keys.add = function (keyHandle, keyData) {
    keys.push({ keyHandle: keyHandle, keyData: keyData });
};
keys.remove = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            keys = keys.splice(i, 1);
            return;
        }
    }
};
keys.lookup = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            return keys[i].keyData;
        }
    }
    return null;
};
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\workerManager.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

// Manages the pool of webworkers and job queue.
// We first try to find an idle webworker and pass it a crypto job.
// If there are no workers or they are all busy, we'll create a new one.
// If we're at our (somewhat arbitrary) limit for workers we'll queue the 
//   job until a worker is free.
// When a worker finishes and the queue is empty it will kill itself to
//   free resources.
// However, we will keep a couple idle workers alive for future use.
// In the case webworkers are not supported <IE10 we will run in synchronous
//   mode. Jobs will be executed synchronously as they arrive using a single
//   syncWorker (pretend webworker that just runs synchronously in this same script).
var workerManager = (function () {

    // The max number of webworkers we'll spawn.
    var maxWorkers = 15;

    // The number of idle webworkers we'll allow to live for future use.
    var maxFreeWorkers = 4;

    // Storage for webworker.
    var workerPool = [];

    // Queue for jobs when all workers are busy.
    var jobQueue = [];

    // Each job gets and id.
    var jobId = 0;

    function getFreeWorker() {

        purgeWorkerType(!asyncMode);

        // Get the first non-busy worker
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                return workerPool[i];
            }
        }

        return null;
    }

    function purgeWorkerType(webWorker) {
        for (var i = workerPool.length - 1; i >= 0; i -= 1) {
            if (workerPool[i].isWebWorker === webWorker) {
                workerPool[i].terminate();
                workerPool.splice(i, 1);
            }
        }
    }

    function freeWorkerCount() {
        var freeWorkers = 0;
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                freeWorkers += 1;
            }
        }
        return freeWorkers;
    }

    function addWorkerToPool(worker) {
        workerPool.push(worker);
    }

    function removeWorkerFromPool(worker) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i] === worker) {
                // Kill the webworker.
                worker.terminate();
                // Remove the worker object from the pool.
                workerPool.splice(i, 1);
                return;
            }
        }
    }

    function lookupWorkerByOperation(operation) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i].operation === operation) {
                return workerPool[i];
            }
        }
        // Didn't find the worker!?
        return null;
    }

    function queueJob(operation, data) {
        jobQueue.push({ operation: operation, data: data, id: jobId++ });
    }

    function jobCompleted(worker) {

        worker.busy = false;
        worker.operation = null;

        // Check the queue for waiting jobs if in async mode
        if (asyncMode) {
            if (jobQueue.length > 0) {
                var job = jobQueue.shift();
                continueJob(job.operation, job.data);

            } else if (freeWorkerCount() > maxFreeWorkers) {
                removeWorkerFromPool(worker);
            }
        }

    }

    function createNewWorker(operation) {

        // Use a web worker if supported
        //   else use a synchronous worker.
        var worker;

        if (asyncMode) {
            try {
                worker = new Worker(scriptUrl);
                worker.postMessage({ prngSeed: msrcryptoPseudoRandom.getBytes(48) });
                worker.isWebWorker = true;
            } catch (ex) {
                asyncMode = false;
                publicMethods.forceSync = true;
                worker = syncWorker();
                worker.isWebWorker = false;
            }

        } else {
            worker = syncWorker();
            worker.isWebWorker = false;
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        worker.busy = false;

        // The worker will call this function when it completes its job.
        worker.onmessage = function (/*@type(typeEvent)*/ e) {

            var op = worker.operation;

            // Check if there are queued jobs for this operation
            for (var i = 0; i < jobQueue.length; i++) {
                if (jobQueue[i].operation === worker.operation) {
                    var job = jobQueue[i];
                    jobQueue.splice(i, 1);
                    postMessageToWorker(worker, job.data);
                    return;
                }
            }

            // Send the results to the operation object and it will fire
            //   it's onCompleted event.
            if (op && e.data.type !== "process") {
                jobCompleted(worker);
                op.dispatchEvent(e);
            }
        };

        // If an error occurs within the worker.
        worker.onerror = function (/*@type(typeEvent)*/ e) {

            var op = worker.operation;

            jobCompleted(worker);

            // Send the error to the operation object and it will fire
            //   it's onError event.
            op.dispatchEvent(e);

        };

        // Add this new worker to the worker pool.
        addWorkerToPool(worker);

        return worker;
    }

    function abortJob(cryptoOperationObject) {
        var worker = lookupWorkerByOperation(cryptoOperationObject);
        if (worker) {
            removeWorkerFromPool(worker);
        }
    }

    // Creates or reuses a worker and starts it up on work.
    function runJob(/*@dynamic*/ operation, data) {

        var worker = null;

        // If the caller adds the "forceSync" property and sets it to true.
        // Then run in synchronous mode even if webworkers are available.
        // This can be turned on or off on the fly.
        asyncMode = webWorkerSupport && !(publicMethods.forceSync);


        // Get the first idle worker.
        worker = getFreeWorker();

        // Queue this job if all workers are busy and we're at our max instances
        if (asyncMode && worker === null && workerPool.length >= maxWorkers) {
            queueJob(operation, data);
            return;
        }

        // No idle workers, we'll have to create a new one.
        if (worker === null) {
            worker = createNewWorker(operation);
        }

        if (worker === null) {
            queueJob(operation, data);
            throw new Error("could not create new worker");
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        // Mark this worker as 'busy'. It's about to run a job.
        worker.busy = true;

        // Start the worker
        postMessageToWorker(worker, data);

    }

    function continueJob(/*type(cryptoOperation)*/operation, data) {

        // Lookup the worker that is handling this operation
        var worker = lookupWorkerByOperation(operation);

        if (worker) {
            postMessageToWorker(worker, data);
            return;
        }

        // If we didn't find a worker, this is probably the first
        //  'process' message so we need to start a new worker.
        runJob(operation, data);

    }

    function postMessageToWorker(worker, data) {
        // Start the worker now if using webWorkers
        //   else, defer running until later.
        if (asyncMode) {
            worker.data = data;
            worker.postMessage(data);
        } else {
            setTimeout(function () { worker.postMessage(data); }, 0);
        }

    }

    return {
        runJob: runJob,
        continueJob: continueJob,
        abortJob: abortJob
    };

})();
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\subtle.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

var utils = msrcryptoUtilities;

function checkOperation(operationType, algorithmName) {
    if (!operations.exists(operationType, algorithmName)) {
        throw new Error("unsupported algorithm");
    }
}

// The list of possible parameters passed to the subtle interface.
var subtleParameters = [
   /* 0 */ { name: "algorithm", type: "Object", required: true },
   /* 1 */ { name: "keyHandle", type: "Object", required: true },
   /* 2 */ { name: "buffer", type: "Array", required: false },
   /* 3 */ { name: "signature", type: "Array", required: true },
   /* 4 */ { name: "format", type: "String", required: true },
   /* 5 */ { name: "keyData", type: "Array", required: true },
   /* 6 */ { name: "extractable", type: "Boolean", required: false },
   /* 7 */ { name: "keyUsage", type: "Array", required: false },
   /* 8 */ { name: "derivedKeyType", type: "Object", required: true },
   /* 9 */ { name: "length", type: "Number", required: false }
];

// The set of expected parameters passed to each subtle function.
var subtleParametersSets = {
    encrypt: [0, 1, 2],
    decrypt: [0, 1, 2],
    sign: [0, 1, 2],
    verify: [0, 1, 3, 2],
    digest: [0, 2],
    generateKey: [0, 6, 7],
    importKey: [4, 5, 0, 6, 7],
    exportKey: [0, 4, 1, 6, 7],
    deriveKey: [0, 1, 8, 6, 7],
    deriveBits: [0, 1, 9]
};

// Looks up the stored key data for a given keyHandle
function lookupKeyData(handle) {
    var data = keys.lookup(handle);

    if (!data) {
        throw new Error("key not found");
    }

    return data;
}

// This function processes each parameter passed by the user. Each parameter
// is compared against an expected parameter. It should be of the expected type.
// Typed-Array parameters are converted to regular Arrays.
function buildParameterCollection(operationName, parameterSet) {

    var parameterCollection = { operationType: operationName },
        operationParameterSet = subtleParametersSets[operationName];

    for (var i = 0; i < operationParameterSet.length; i += 1) {

        var expectedParam = subtleParameters[operationParameterSet[i]];
        var actualParam = parameterSet[i];

        // Verify the required parameters are present.
        if (!actualParam) {
            if (expectedParam.required) {
                throw new Error(expectedParam.name);
            } else {
                continue;
            }
        }

        // If this parameter is a typed-array convert it to a regular array.
        if (actualParam.subarray) {
            actualParam = utils.toArray(actualParam);
        }

        // Verify the actual parameter is of the expected type.
        if (type(actualParam) !== expectedParam.type) {
            throw new Error(expectedParam.name);
        }

        // If this parameter an algorithm object convert it's name to lowercase.
        if (expectedParam.name === "algorithm") {

            actualParam.name = actualParam.name.toLowerCase();

            // If the algorithm has a typed-array IV, convert it to a regular array.
            if (actualParam.iv) {
                actualParam.iv = utils.toArray(actualParam.iv);
            }

            // If the algorithm has a typed-array AdditionalData, convert it to a regular array.
            if (actualParam.additionalData) {
                actualParam.additionalData = utils.toArray(actualParam.additionalData);
            }
        }

        parameterCollection[expectedParam.name] = actualParam;
    }

    return parameterCollection;
}

function executeOperation(operationName, parameterSet, keyFunc) {

    var pc = buildParameterCollection(operationName, parameterSet);

    checkOperation(operationName, pc.algorithm.name);

    // Add the key data to the parameter object
    if (pc.keyHandle) {
        pc.keyData = lookupKeyData(pc.keyHandle);
    }

    // ECDH.DeriveBits passes a public key in the algorithm
    if (pc.algorithm && pc.algorithm.publicKey) {
        pc.additionalKeyData = lookupKeyData(pc.algorithm.publicKey);
    }

    var op = keyFunc ? keyOperation(pc) : cryptoOperation(pc);

    // Run the crypto now if a buffer is supplied
    //   else wait until process and finish are called.
    if (keyFunc || pc.buffer || operationName === "deriveBits") {
        workerManager.runJob(op, pc);
    }

    return op;
}

var publicMethods = {

    encrypt: function (/*@type(Algorithm)*/ algorithm,/*@type(typeKeyHandle)*/ keyHandle, buffer) {
        return executeOperation("encrypt", arguments, 0);
    },

    decrypt: function (/*@type(Algorithm)*/ algorithm, /*@type(typeKeyHandle)*/ keyHandle, buffer) {
        return executeOperation("decrypt", arguments, 0);
    },

    sign: function (/*@type(Algorithm)*/ algorithm, /*@type(typeKeyHandle)*/ keyHandle, buffer) {
        return executeOperation("sign", arguments, 0);
    },

    verify: function (/*@type(Algorithm)*/ algorithm, /*@type(typeKeyHandle)*/ keyHandle, signature, buffer) {
        return executeOperation("verify", arguments, 0);
    },

    digest: function (/*@type(Algorithm)*/ algorithm, buffer) {
        return executeOperation("digest", arguments, 0);
    },

    generateKey: function (/*@type(Algorithm)*/ algorithm, extractable, keyUsage) {
        return executeOperation("generateKey", arguments, 1);
    },

    deriveKey: function (/*@type(Algorithm)*/ algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
        return executeOperation("deriveKey", arguments, 1);
    },

    deriveBits: function (/*@type(Algorithm)*/ algorithm, baseKey, length) {
        return executeOperation("deriveBits", arguments, 0);
    },

    importKey: function (format, keyData, algorithm, extractable, keyUsage) {
        return executeOperation("importKey", arguments, 1);
    },

    exportKey: function (format, /*@type(typeKeyHandle)*/ keyHandle) {
        // Export is one of the few calls where the caller does not supply an algorithm 
        // since it's already part of the key to be exported.
        // So, we're pulling out of the key and adding it to the parameter set since
        // it's used as a switch to route the parameters to the right function.
        // Now we don't have to treat this as a special case in the underlying code.
        return executeOperation("exportKey", [keyHandle.algorithm, format, keyHandle], 1);
    },

    wrapKey: function (keyHandle, keyEncryptionKey, keyWrappingAlgorithm) {
        throw new Error("not implemented");
    },

    unwrapKey: function (wrappedKey, keyAlgorithm, keyEncryptionKey, extractable, keyUsage) {
        throw new Error("not implemented");
    }

};
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\tail.js
//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

return publicMethods;

})();

}

//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

var publicMethods = {
    subtle: msrcryptoSubtle,
    getRandomValues: function(array) {
        var i;
        var randomValues = msrcryptoPseudoRandom.getBytes(array.length);
        for (i = 0; i < array.length; i+=1) {
            array[i] = randomValues[i];
        }
        return array;
    },
    initPrng: function (entropyData) {
        /// <summary>Add entropy to the PRNG.</summary>
        /// <param name="entropyData" type="Array">Entropy input to seed or reseed the PRNG.</param>

        var entropyDataType = Object.prototype.toString.call(entropyData);

        if (entropyDataType !== "[object Array]" && entropyDataType !== "[object Uint8Array]") {
            throw new Error("entropyData must be a Array or Uint8Array");
        }

        // Mix the user-provided entropy into the entropy pool - only in the main thread.
        entropyPool && entropyPool.reseed(entropyData);

        // Reseed the PRNG that was initialized below
        msrcryptoPseudoRandom.reseed(entropyPool.read(48));
        fprngEntropyProvided = true;
    },
    stringToBase64: msrcryptoUtilities.toBase64,
    base64ToString: msrcryptoUtilities.base64ToString
};

// Expose the math library if present
if (typeof cryptoMath !== "undefined") { 
    publicMethods.cryptoMath = cryptoMath; 
}

if (typeof testInterface !== "undefined") {
    publicMethods.testInterface = testInterface;
}

// Initialize the main entropy pool instance on the main thread, only.
// I want only the main thread to create and manage the central entropy pool.
// All workers would have their own PRNG instance initialized by injected entropy from the main thread.
var entropyPool;
if (!runningInWorkerInstance) {
    entropyPool = entropyPool || new MsrcryptoEntropy();

    // Initialize the entropy pool in the main thread.
    // There is only one entropy pool.
    entropyPool.init();
    var localEntropy = entropyPool.read(48);            // 48 is from SP800-90A; could be longer
    msrcryptoPseudoRandom.init(localEntropy);
}

return publicMethods;

})();
