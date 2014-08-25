(function($, window) {
    'use strict';

    // TODO rename toString as toDOMString ?
    var util = {
        // functions somewhat derived from Chromium Nightly
        // http://src.chromium.org/viewvc/blink/trunk/LayoutTests/crypto/resources/common.js
        toString: function (buf) {
            var i, chars = [];
            for (i = 0; i < buf.length; i++) {
                chars.push(String.fromCharCode(buf[i]));
            }

            return chars.join('');
        },

        fromString: function (s) {
            var i, plaintextBuf = new Uint8Array(s.length);
            for (i = 0; i < s.length; i++) {
                plaintextBuf[i] = s.charCodeAt(i);
            }

            return plaintextBuf;
        },

        toHexString: function (buf) {
            var i, hexChars = [];
            for (i = 0; i < buf.length; i++) {
                var bite = buf[i];
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        fromHexString: function (s) {
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
        toBase64String: function (buf) {
            // TODO
        },

        fromBase64String: function (s) {
            // TODO
        }
        */
    };

    $.Uint8Util = util;
})(jQuery, window);