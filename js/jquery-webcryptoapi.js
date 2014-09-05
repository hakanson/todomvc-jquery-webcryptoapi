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

	} else if (window.crypto && window.crypto.webkitSubtle) {
		// Bug 122679 - [Meta] Implement WebCrypto SubtleCrypto interface
		// https://bugs.webkit.org/show_bug.cgi?id=122679
		webcryptoapi.subtle = window.crypto.webkitSubtle;

	} else if (msCrypto) {
		// IE11 msCrypto implementation was based on spec before Promise based interface
		// need to convert onerror and oncomplete to reject and resolve
		// 11. CryptoOperation interface
		// https://dvcs.w3.org/hg/webcrypto-api/raw-file/0fe9b34c13fb/spec/Overview.html#cryptooperation-interface
		// 12. KeyOperation interface
		// https://dvcs.w3.org/hg/webcrypto-api/raw-file/0fe9b34c13fb/spec/Overview.html#KeyOperation-interface

		var convertOperationToPromise = function (msCryptoAPI) {
			var promise = new Promise(function(resolve, reject) {
				try {
					var op = msCryptoAPI();
					op.onerror = function (evt) {
						reject(evt);
					};
					op.oncomplete = function (evt) {
						resolve(evt.target.result);
					};
				} catch (ex) {
					// For some MSDN documentation remarks:
					// This method is present in the DOM but is not supported.
					// If called, this method always throws a NOT_SUPPORTED_ERR DOM exception when called.
					reject(ex);
				}
			});

			return promise;
		};

		webcryptoapi.subtle = {
			decrypt: function (algorithm, key, buffer) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.decrypt(algorithm, key, buffer);
				});
			},
			deriveBits: function ( algorithm, baseKey, length) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.deriveBits( algorithm, baseKey, length);
				});
			},
			// deriveKey:
			digest: function (algorithm, buffer) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.digest(algorithm, buffer);
				});
			},
			encrypt: function (algorithm, key, buffer) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.encrypt(algorithm, key, buffer);
				});
			},
			exportKey: function (format, key) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.exportKey(format, key);
				});
			},
//			generateKey: function (format, keyData, algorithm, extractable, keyUsages) {
//				return convertOperationToPromise(function() {
//					return msCrypto.subtle.generateKey(format, keyData, algorithm, extractable, keyUsages);
//				});
//			},
			importKey: function (format, keyData, algorithm, extractable, keyUsages) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages);
				});
			},
			sign: function (algorithm, key, buffer) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.sign(algorithm, key, buffer);
				});
			},
			// unwrapKey:
			verify: function (algorithm, key, signature, buffer) {
				return convertOperationToPromise(function() {
					return msCrypto.subtle.verify(algorithm, key, signature, buffer);
				});
			}
			// wrapKey:
		}
	}

	$.WebCryptoAPI = webcryptoapi;
})(jQuery, window);