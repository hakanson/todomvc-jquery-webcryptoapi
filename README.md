todomvc-jquery-webcryptoapi
===========================

jQuery TodoMVC using the Web Cryptography API

Work in progress.  Created for Kevin Hakanson's "Securing TodoMVC Using the Web Cryptography API" [presentation][1]. (gh-pages [demo][2] )

---

The open source TodoMVC project implements a Todo application using popular JavaScript MV* frameworks. Some of the implementations add support for compile to JavaScript languages, module loaders and real time backends. This presentation will demonstrate a TodoMVC implementation which adds support for the forthcoming W3C Web Cryptography API, as well as review some key cryptographic concepts and definitions.

Instead of storing the Todo list as plaintext in localStorage, this "secure" TodoMVC implementation encrypts Todos using a password derived key. The PBKDF2 algorithm is used for the deriveKey operation, with getRandomValues generating a cryptographically random salt. The importKey method sets up usage of AES-CBC for both encrypt and decrypt operations. The final solution helps address item "A6-Sensitive Data Exposure" from the OWASP Top 10.

With the Web Cryptography API being a recommendation in 2014, any Q&A time will likely include browser implementations and limitations, and whether JavaScript cryptography adds any value.

[1]: https://docs.google.com/presentation/d/1lIMvkPXM2gsieAJ56aokX9QEKsEyTCHiHcJ8SjSU4DQ/pub?start=false&loop=false&delayms=3000
[2]: https://hakanson.github.io/todomvc-jquery-webcryptoapi/
