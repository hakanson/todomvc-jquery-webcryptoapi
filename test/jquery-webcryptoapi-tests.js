(function () {
    'use strict';

    // comment out next line to use browser native window.crypto object
    var crypto = $.WebCryptoAPI;

    var testVector = {
        data: 'The quick brown fox jumps over the lazy dog',
        sha1Hash : '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
        sha256Hash : 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',

        key: 'key',
        sha1HMAC : 'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9',
        sha256HMAC : 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
    };

    var hmacSha1 = { name: 'hmac', hash: { name: 'sha-1' } };
    var hmacSha256 = { name: 'hmac', hash: { name: 'sha-256' } };

    var dataBuf = $.Uint8Util.fromString( testVector.data );
    var keyBuf = $.Uint8Util.fromString( testVector.key );

//    QUnit.module( 'Web Cryptography API' );

    QUnit.test( 'window.crypto.subtle' , function ( assert ) {
        assert.ok(window.crypto, 'window.crypto');
        assert.ok(window.crypto.subtle, 'window.crypto.subtle');
    });

    QUnit.asyncTest( 'SHA-1', function ( assert ) {
        // OpenSSL command line
        // echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha1
        // (stdin)= 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12

        expect( 1 );

        crypto.subtle.digest( { name: 'sha-1' }, dataBuf ).then( function ( result ) {
            var hash = $.Uint8Util.toHexString( new Uint8Array( result ) );

            assert.equal( hash, testVector.sha1Hash );

            QUnit.start();
        }, function (e) {
            console.log(e);
            QUnit.start();
        });
    });

    QUnit.asyncTest( 'HMAC using SHA-1', function ( assert ) {
        // OpenSSL command line
        // echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha1 -hmac "key"
        // (stdin)= de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9

        crypto.subtle.importKey( 'raw', keyBuf, hmacSha1, true, ['sign', 'verify'] ).then( function ( keyResult ) {

            crypto.subtle.sign( hmacSha1, keyResult, dataBuf ).then( function ( result ) {
                var hash = $.Uint8Util.toHexString( new Uint8Array( result ) );

                QUnit.equal( hash, 'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9' );

                QUnit.start();
            })
        });
    });

    QUnit.asyncTest( 'SHA-256', function () {
        // OpenSSL command line
        // $ echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha256
        // (stdin)= d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592

        crypto.subtle.digest( { name: 'sha-256' }, dataBuf ).then( function ( result ) {
            var hash = $.Uint8Util.toHexString( new Uint8Array( result ) );

            QUnit.equal( hash, testVector.sha256Hash );

            QUnit.start();
        });
    });

    QUnit.asyncTest( 'HMAC using SHA-256', function () {
        // Wikipedia article
        // HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = 0xf7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8

        // OpenSSL command line
        // echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha256 -hmac "key"
        // (stdin)= f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8

        // $ echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha256 -mac HMAC -macopt hexkey:6b6579
        // (stdin)= f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8

        crypto.subtle.importKey( 'raw', keyBuf, hmacSha256, true, ['sign', 'verify'] ).then( function ( keyResult ) {

            crypto.subtle.sign( hmacSha256, keyResult, dataBuf ).then( function ( result ) {
                var hash = $.Uint8Util.toHexString( new Uint8Array( result ) );

                QUnit.equal( hash, 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8' );

                QUnit.start();
            })
        });
    });

    QUnit.asyncTest( 'AES-CBC (nested Promises)', function () {
        // $ echo -n "Message" | openssl enc -aes256 -K 0CD1D07EB67E19EF56EA0F3A9A8F8A7C957A2CB208327E0E536608FF83256C96 -iv 6C4C31BDAB7BAFD35B23691EC521E28D | xxd -p
        // 23e5ebe72d99cf302c99183c05cf050a

        var testVector = {
            plaintext: 'Message',
            iv: '6C4C31BDAB7BAFD35B23691EC521E28D',
            key: '0CD1D07EB67E19EF56EA0F3A9A8F8A7C957A2CB208327E0E536608FF83256C96',
            ciphertext: '23e5ebe72d99cf302c99183c05cf050a'
        };

        var buf = $.Uint8Util.fromString( testVector.plaintext );
        var keyBuf = $.Uint8Util.fromHexString( testVector.key );
        var ivBuf = $.Uint8Util.fromHexString( testVector.iv );

        crypto.subtle.importKey( 'raw', keyBuf, { name: 'AES-CBC' }, true, ['encrypt', 'decrypt'] ).then( function ( encryptionKey ) {
            var aesCbc = { name: 'AES-CBC', iv: ivBuf };
            crypto.subtle.encrypt( aesCbc, encryptionKey, buf ).then( function ( encryptResult ) {
                var encryptBuf = new Uint8Array( encryptResult );
                var ciphertext = $.Uint8Util.toHexString( encryptBuf );

                QUnit.equal( ciphertext, testVector.ciphertext );

                crypto.subtle.decrypt( aesCbc, encryptionKey, encryptBuf ).then( function ( decryptResult ) {
                    var plaintext = $.Uint8Util.toString( new Uint8Array( decryptResult ) );

                    QUnit.equal( plaintext, testVector.plaintext );

                    QUnit.start();
                });
            });
        });
    });
    
    QUnit.asyncTest( 'AES-CBC (chained Promises)', function () {
        // $ echo -n "Message" | openssl enc -aes256 -K 0CD1D07EB67E19EF56EA0F3A9A8F8A7C957A2CB208327E0E536608FF83256C96 -iv 6C4C31BDAB7BAFD35B23691EC521E28D | xxd -p
        // 23e5ebe72d99cf302c99183c05cf050a

        var testVector = {
            plaintext: 'Message',
            iv: '6C4C31BDAB7BAFD35B23691EC521E28D',
            key: '0CD1D07EB67E19EF56EA0F3A9A8F8A7C957A2CB208327E0E536608FF83256C96',
            ciphertext: '23e5ebe72d99cf302c99183c05cf050a'
        };

        var buf = $.Uint8Util.fromString( testVector.plaintext );
        var keyBuf = $.Uint8Util.fromHexString( testVector.key );
        var ivBuf = $.Uint8Util.fromHexString( testVector.iv );

        var aesCbc = { name: 'AES-CBC', iv: ivBuf };
        var encryptionKey;

        function importKey () {
            return crypto.subtle.importKey( 'raw', keyBuf, { name: 'AES-CBC' }, true, ['encrypt', 'decrypt'] )
        }
        
        function encrypt ( importedKey ) {
            encryptionKey = importedKey;
            return crypto.subtle.encrypt( aesCbc, encryptionKey, buf );
        }
                
        function decrypt ( encryptResult ) {
            var encryptBuf = new Uint8Array( encryptResult );
            var ciphertext = $.Uint8Util.toHexString( encryptBuf );

            QUnit.equal( ciphertext, testVector.ciphertext );

            return crypto.subtle.decrypt( aesCbc, encryptionKey, encryptBuf );
        }

        function compare ( decryptResult ) {
            var plaintext = $.Uint8Util.toString( new Uint8Array( decryptResult ) );

            QUnit.equal( plaintext, testVector.plaintext );

            QUnit.start();
        }
        
        importKey()
            .then( encrypt )
            .then( decrypt )
            .then( compare );
    });

    QUnit.asyncTest( 'PBKDF2', function () {

        var testVector = {
            password : 'password',
            salt: 'cf7488cd1e48e84990f51b3f121e161318ba2098aa6c993ded1012c955d5a3e8',
            iterations: 100,
            key: 'c12b2e03a08f3f0d23f3c4429c248c275a728814053a093835e803bc8e695b4e'
        };

        var alg = {
            name: 'PBKDF2',
            hash: 'SHA-1',
            salt: $.Uint8Util.fromHexString( testVector.salt ),
            iterations: testVector.iterations
        };

        var passwordBuf = $.Uint8Util.fromString( testVector.password );
        crypto.subtle.importKey('raw', passwordBuf, 'PBKDF2', false, ['deriveKey']).then(function ( keyResult ) {

            crypto.subtle.deriveBits( alg, keyResult, 256 ).then(function ( deriveResult ) {
                var deriveBuf = new Uint8Array( deriveResult );
                var key = $.Uint8Util.toHexString( deriveBuf );

                QUnit.equal( key, testVector.key );

                QUnit.start();
            });
        });

    });

})();