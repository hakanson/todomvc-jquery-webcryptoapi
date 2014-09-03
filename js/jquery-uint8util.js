(function($) {
    'use strict';

    var util = {
        // functions somewhat derived from Chromium Nightly
        // http://src.chromium.org/viewvc/blink/trunk/LayoutTests/crypto/resources/common.js
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
    };

    $.Uint8Util = util;
})(jQuery);