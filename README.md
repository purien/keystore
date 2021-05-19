# About the Keystore

* A simple cost effective solution to securely store&use blockchain private keys in the cloud<br>
-- Cost effective, alternative to HSM <br> 
-- Anywhere, anytime <br> 
-- Secure and tamper proof <br>
* Blockchain keystore embedded in a tamper resistant server <br>
-- Fully under the (remote) user (owner) control <br>
* On the client side, credentials are optionally stored in a Secure Element (access card) and may use a crypto terminal.
* Simple and highly secure architecture <br>
-- Relies on TLS1.3 secure communication and Secure Elements <br>

# Making an Ethereum transaction with the keystore

See https://github.com/purien/keystore/wiki/Making-an-Ethereum-Transaction-with-the-keystore

# Demonstration Server for Windows

See https://github.com/purien/keystore/wiki/Windows-Keystore-Demonstration

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
* Short introduction (4mn) to TLS-IM et TLS-SE (Hot RFC lightning Talks, November 2020) <br>
-- https://www.youtube.com/watch?v=aRQQu_977K8
![keystore](https://github.com/purien/keystore/blob/main/keystore02.jpg)

# Why TLS1.3
* State of art for communication security
-- Several years of debates between security experts at IETF.<br>
-- Privacy enforcement with Diffie-Hellman Exchange over Elliptic Curve (ECDHE)<br>
-- Authenticated Encryption with Associated Data (AEAD)<br>
-- Server and client authentication based on PKI or pre-shared-key (PSK)<br>
* TLS-SE 1.0 works with AES-128-CCM cipher-suite, ECDHE (over SECP256k1), and 32 bytes PSK.
* Next version will support PKI

# Keystore commands
* A keystore command is a text line (ASCII) ended by CrLf (Carriage Return, Line Feed) or Lf 
* The first character is the command identifier (?, c, X, g, p, r, t, v, b, s)
* The second and third character is the command index coded in hexadecimal <br>
-- index: 00=>0, 01=1, 0A=>10, FF=>255 <br>
-- The keystore supports four keys identfified by index 00, 01, 02, 03 <br>
* Remaining characters (if any) represent the command payload <br>
-- For ?01 echo command, the payload is a set of ASCII characters <br>
-- For other commands the payload is a set of bytes encoded in hexadecimal format (even number of characters) <br>
-- For BIP32, only hardened keys are supported. The path is expressed as a list of 32bits values, with the most significant bit set to 1.<br>
* The timeout is 30 seconds, use ?02 for deconnection.

![keystore raspberry-pi board](https://github.com/purien/keystore/blob/main/keystore-rasp-pi.jpg)
![keystore wi-fi board](https://github.com/purien/keystore/blob/main/keystore01.jpg)

# OPENSSL examples

## OPENSSL command line

- without server name  <br>
openssl s_client  -tls1_3  -connect keystore.dyndns.info:7777 -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket -psk 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20

- with server name  <br>
openssl s_client  -tls1_3  -connect keystore.dyndns.info:7777  -servername key1.com -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket -psk 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
 
Upon success your scree should display the following lines: <br><br>
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
Ethertrust keystore 1.1          <br>
?01abcdef       _(echo abcdef)_  <br>
abcdef  <br>
?02             _(disconnect)_   <br>

## Generating a key
c03 _(clear key 3)_ <br>
OK <br>
g03 _(generate key 3)_ <br>
OK <br>
p03  _(get public key 3)_ <br>
04E67689C83475EFB1C91B64F56BECD926FAE5CC81631EF98AFD4EF8AF310F64460CE0D3550BD6658ABD26EDA825859746C10F781354EC1C086161B4
A808B1BD56 <br>
r03 _(get private key 3)_ <br>
5E2A0AAD12FF24E638174AE9B17F45078C5C068F08F0479AAE9CB645DFBB4408<br>
?02 _(disconnect)_<br>

## Setting a key
c03 _(clear key 3)_ <br>
OK <br>
X031234 _(set private & public key 3)_ <br>
OK <br>
p03  _(get public key 3)_ <br>
0437A4AEF1F8423CA076E4B7D99A8CABFF40DDB8231F2A9F01081F15D7FA65C1BAB96CED90A1B8F9B43A18FC900FF55AF2BE0E94B90A434FCA5B9E22
6B835024CD <br>
r03 _(get private key 3)_ <br>
0000000000000000000000000000000000000000000000000000000000001234<br>
?02 _(disconnect)_<br>

## Setting BIP32 seed and computing keys
c03 _(clear key 3)_ <br>
OK <br>
t031234 _(set tree 3 secret seed)_ <br>
OK <br>
v03  _(get tree 3 secret seed)_ <br>
1234 <br>
b0380000001  _(compute hardened  key 1H for BIP tree 3)_ <br>
p03  _(get public key 3)_ <br>
0455CB37165F08D5E85D49DA700C083B8D9D7CB33EA7BEF0FE3455F632FE50DE743E4664A488C3D825F872135BF2F139C655B9E212394717D0A9F27E
9DEA32146E <br>
r03 _(get private key 3)_ <br>
95DC50F1D52AC952B866B8AD9845F9E3EBB9DD8EDF49F8E7CC342469A8DA77C8 <br>
?02 _(disconnect)_<br>

## Generating BIP32 random secret seed
c03 _(clear key 3)_ <br>
OK <br>
t03  _(generate tree 3 secret seed)_ <br>
OK <br>
v03  _(get tree 3 secret seed)_ <br>
139CF1FED85772090C9A9AEBECD4F3ABB549B0D5D6858F77D540A9B565A98FF1<br>
?02 _(disconnect)_<br>

## Generating BIP32 test vector
see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki <br>
c03 _(clear key 3)_ <br>
OK <br>
t03000102030405060708090a0b0c0d0e0f _(set tree 3 secret seed)_ <br>
OK <br>
v03  _(get tree 3 secret seed)_ <br>
000102030405060708090a0b0c0d0e0f <br>
b0380000000  _(compute hardened key 0H for BIP tree 3)_ <br>
p03  _(get public key 3)_ <br>
045A784662A4A20A65BF6AAB9AE98A6C068A81C52E4B032C0FB5400C706CFCCC567F717885BE239DAADCE76B568958305183AD616FF74ED4DC219A74
C26D35F839<br>
r03 _(get private key 3)_ <br>
EDB2E14F9EE77D26DD93B4ECEDE8D16ED408CE149B6CD80B0715A2D911A0AFEA <br>
?02 _(disconnect)_<br>

## Signing
s03abcd _(sign with key 3)_ <br>
30440220604F3520C7112BA934B34D25DB03DD66851C84017A0216FE1DC876A4ED4F6C33022070B437A956D5D9D7B7EAEBDC122E52DC347218DA4884
EF920AA44940D48BD92F <br>
?02 _(disconnect)_<br>





