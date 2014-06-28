(function($, window) {
    'use strict';

    var msCrypto = window.msCrypto || window.msrCrypto || null;
    var webcryptoapi = {
        getRandomValues : null,
        subtle: null
    };

    // 10. RandomSource interface
    // https://dvcs.w3.org/hg/webcrypto-api/raw-file/tip/spec/Overview.html#RandomSource-interface
    if (window.crypto && window.crypto.getRandomValues) {
        webcryptoapi.getRandomValues = function (buffer) {
            window.crypto.getRandomValues(buffer);
        };
    } else if (window.msCrypto && window.msCrypto.getRandomValues) {
        webcryptoapi.getRandomValues = function (buffer) {
            window.msCrypto.getRandomValues(buffer);
        };
    } else if (window.msrCrypto && window.msrCrypto.getRandomValues) {
        webcryptoapi.getRandomValues = window.msrCrypto.getRandomValues
    }

    // 15. SubtleCrypto interface
    // https://dvcs.w3.org/hg/webcrypto-api/raw-file/tip/spec/Overview.html#subtlecrypto-interface
    if (window.crypto && window.crypto.subtle) {
        webcryptoapi.subtle = window.crypto.subtle;

        //} else if (window.msCrypto && window.msCrypto.subtle) {
    } else if (msCrypto) {
        // IE11 msCrypto implementation was based on spec before Promise based interface
        // need to convert onerror and oncomplete to reject and resolve
        // 11. CryptoOperation interface
        // https://dvcs.w3.org/hg/webcrypto-api/raw-file/0fe9b34c13fb/spec/Overview.html#cryptooperation-interface
        webcryptoapi.subtle = {
            importKey: function (format, keyData, algorithm, extractable, keyUsages) {
                var defer = $.Deferred();

                var op = msCrypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages);
                op.onerror = function (evt) {
                    defer.reject(evt.toString());
                };
                op.oncomplete = function (evt) {
                    defer.resolve(evt.target.result);
                };

                return defer.promise();
            },
            sign: function (algorithm, key, buffer) {
                var defer = $.Deferred();

                var op = msCrypto.subtle.sign(algorithm, key, buffer);
                op.onerror = function (evt) {
                    defer.reject(evt.toString());
                };
                op.oncomplete = function (evt) {
                    defer.resolve(evt.target.result);
                };

                return defer.promise();
            },
            encrypt: function (algorithm, key, buffer) {
                var defer = $.Deferred();

                var op = msCrypto.subtle.encrypt(algorithm, key, buffer);
                op.onerror = function (evt) {
                    defer.reject(evt.toString());
                };
                op.oncomplete = function (evt) {
                    defer.resolve(evt.target.result);
                };

                return defer.promise();
            },
            decrypt: function (algorithm, key, buffer) {
                var defer = $.Deferred();

                var op = msCrypto.subtle.decrypt(algorithm, key, buffer);
                op.onerror = function (evt) {
                    defer.reject(evt.toString());
                };
                op.oncomplete = function (evt) {
                    defer.resolve(evt.target.result);
                };

                return defer.promise();
            }
        }
    }

    webcryptoapi.util = {
        // functions somewhat derived from Chromium Nightly
        // http://src.chromium.org/viewvc/blink/trunk/LayoutTests/crypto/resources/common.js
        arrayBufferToString: function (buf) {
            var i, chars = [];
            for (i = 0; i < buf.length; i++) {
                chars.push(String.fromCharCode(buf[i]));
            }

            return chars.join('');
        },

        stringToUint8Array: function (s) {
            var i, plaintextBuf = new Uint8Array(s.length);
            for (i = 0; i < s.length; i++) {
                plaintextBuf[i] = s.charCodeAt(i);
            }

            return plaintextBuf;
        },

        uint8ArrayToHexString: function (buf) {
            var i, hexChars = [];
            for (i = 0; i < buf.length; i++) {
                var bite = buf[i];
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        hexStringToUint8Array: function (s) {
            var arrayBuffer, byteValue;

            if (s.length % 2 != 0) {
                s = "0" + s;
            }
            arrayBuffer = new Uint8Array(s.length / 2);

            for (var i = 0; i < s.length; i += 2) {
                byteValue = parseInt(s.substr(i, 2), 16);
                arrayBuffer[i / 2] = byteValue;
            }

            return arrayBuffer;
        }

        // TODO look at https://developer.mozilla.org/en-US/Add-ons/Code_snippets/StringView
        /*
        uint8ArrayToBase64String: function (buf) {
            // TODO
        },

        base64StringToUint8Array: function (s) {
            // TODO
        }
        */
    };

    $.WebCryptoAPI = webcryptoapi;
})(jQuery, window);