// Type definitions for WebCrypto
// Project: http://www.w3.org/TR/WebCryptoAPI/
// Definitions by: Lucas Dixon <https://github.com/iislucas/>
// Definitions: https://github.com/borisyankov/DefinitelyTyped

declare module crypto {

    interface AlgorithmIdentifier {
        // http://www.w3.org/TR/WebCryptoAPI/#algorithms-index
        name : string;
    }

    interface KeyAlgorithm {
        name : string;
    }


    // http://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface-datatypes
    interface KeyFormat extends string {
        // The recognized key format values are "raw", "pkcs8", "spki" and "jwk"
    }

    interface CryptoOperationData extends ArrayBuffer {
        // typedef (ArrayBuffer or ArrayBufferView) CryptoOperationData;
    }

    // http://www.w3.org/TR/WebCryptoAPI/#dfn-Key
    interface KeyType extends string {
        // The recognized key type values are "public", "private" and "secret"
    }

    interface KeyUsage extends string {
        // The recognized key usage values are "encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey" and "unwrapKey".
    }


    interface Key {
        type : KeyType;

        extractable : boolean;

        algorithm : KeyAlgorithm;

        usages : Array<KeyUsage>;
    }

    // http://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface
    interface SubtleCrypto {
        encrypt( algorithm : AlgorithmIdentifier, key : Key, data : CryptoOperationData) : Promise<any>;

        decrypt( algorithm : AlgorithmIdentifier, key : Key, data : CryptoOperationData) : Promise<any>;

        sign( algorithm : AlgorithmIdentifier, key : Key, data : CryptoOperationData) : Promise<any>;

        verify( algorithm : AlgorithmIdentifier, key : Key, signature : CryptoOperationData, data : CryptoOperationData) : Promise<any>;

        digest( algorithm : AlgorithmIdentifier, data : CryptoOperationData) : Promise<any>;

        generateKey( algorithm : AlgorithmIdentifier, extractable : boolean, keyUsages : Array<KeyUsage>) : Promise<any>;

        deriveKey( algorithm : AlgorithmIdentifier, baseKey : Key, derivedKeyType : AlgorithmIdentifier, extractable : boolean, keyUsages : Array<KeyUsage>) : Promise<any>;

        deriveBits( algorithm : AlgorithmIdentifier, baseKey : Key, length : number) : Promise<any>;

        importKey( format : KeyFormat, keyData : CryptoOperationData, algorithm? : AlgorithmIdentifier, extractable : boolean, keyUsages : Array<KeyUsage>) : Promise<any>;

        exportKey( format : KeyFormat, key : Key ) : Promise<any>;
    }

    // A cryptographically strong pseudo-random number generator seeded with
    // truly random values. The buffer passed in is modified, and a reference to
    // argument is returned for convenience.
    function getRandomValues(array: ArrayBufferView) : ArrayBufferView

    var subtle : SubtleCrypto;
}