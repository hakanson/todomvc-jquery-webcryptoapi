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
            digest: function (algorithm, buffer) {
                var defer = $.Deferred();

                var op = msCrypto.subtle.digest(algorithm, buffer);
                op.onerror = function (evt) {
                    defer.reject(evt.toString());
                };
                op.oncomplete = function (evt) {
                    defer.resolve(evt.target.result);
                };

                return defer.promise();
            },
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
            },
            deriveBits: function ( algorithm, baseKey, length) {
                var defer = $.Deferred();

                var op = msCrypto.subtle.deriveBits( algorithm, baseKey, length);
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

    $.WebCryptoAPI = webcryptoapi;
})(jQuery, window);