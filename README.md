# About the keystore

* A simple cost effective solution to securely store&use blockchain private keys in the cloud<br>
-- Cost effective, alternative to HSM <br> 
-- Anywhere, anytime <br> 
-- Secure and tamper proof <br>
* Blockchain keystore embedded in a tamper resistant server <br>
-- Fully under the (remote) user (owner) control <br>
* On the client side, credentials are optionally stored in a Secure Element (access card)
* Simple and highly secure architecture <br>
-- Relies on TLS1.3 secure communication and Secure Elements <br>

# The concept
* Blockchain keystore hosted in the Internet Trusted keystore running in a secure element 
-- EAL6 <br>
-- Key generation<br>
-- Key setting<br>
-- Key computing (BIP32)<br>
-- Signature generation <br>
* Keystore App works in a TLS1.3 embedded server<br>
-- TLS-SE:  TLS Secure Element<br>
-- https://tools.ietf.org/html/draft-urien-tls-se-02<br>
* Remote Wallet works over a TLS1.3 client<br>
-- Client credentials are (optionally)  stored and used in a secure element<br>
-- TLS-IM: TLS Identity Module<br>
-- https://tools.ietf.org/html/draft-urien-tls-im-04<br>

# Why TLS1.3
* State of art for communication security
-- Several years of debates between security experts at IETF.<br>
-- Privacy enforcement with Diffie-Hellman Exchange over Elliptic Curve (ECDHE)<br>
-- Authenticated Encryption with Associated Data (AEAD)<br>
-- Server and client authentication based on PKI or pre-shared-key (PSK)<br>
* TLS-SE 1.0 works with AES-128-CCM cipher-suite, ECDHE (over SECP256k1), and 32 bytes PSK.
* Next version will support PKI

# Keystore commands
![keystore wi-fi board](https://github.com/purien/keystore/blob/main/keystore01.jpg)

# OPENSSL examples

## OPENSSL command line

openssl s_client  -tls1_3  -connect keystore.dyndns.info:443 -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket -psk 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20

Upon success your scree should display the following lines<br>
_CONNECTED(00000130)<br>
no peer certificate available<br>
No client certificate CA names sent<br>
Server Temp Key: ECDH, P-256, 256 bits<br>
SSL handshake has read 252 bytes and written 387 bytes<br>
Verification: OK<br>
Reused, TLSv1.3, Cipher is TLS_AES_128_CCM_SHA256<br>
Secure Renegotiation IS NOT supported<br>
No ALPN negotiated<br>
Early data was not sent<br>
Verify return code: 0 (ok)_<br>

## A simple session

?00             _(get version)_  <br>
Ethertrust keystore 1.0          <br>
?01abcdef       _(echo abcdef)_  <br>
abcdef  <br>
?02             _(disconnect)_   <br>







