# keystore

* A simple cost effective solution to securely store&use blockchain private keys in the cloud<br>
-- Cost effective, alternative to HSM <br> 
-- Anywhere, anytime <br> 
-- Secure and tamper proof <br>
* Blockchain keystore embedded in a tamper resistant server <br>
-- Fully under the (remote) user (owner) control <br>
* On the client side, credentials are optionally stored in a Secure Element (access card)
* Simple and highly secure architecture <br>
-- Relies on TLS1.3 secure communication and Secure Elements <br>
***
# The concept
* Blockchain keystore hosted in the Internet Trusted keystore running in a secure element 
-- EAL6 <br>
-- Key generation<br>
-- Key setting<br>
-- Key computing (BIP32)<br>
-- Signature generation <br>
* Keystore App works in a TLS1.3 embedded server<br>
-- TLS-SE:  TLS Secure Element<br>
-- https://tools.ietf.org/html/draft-urien-tls-se-01<br>
* Remote Wallet works over a TLS1.3 client<br>
-- Client credentials are (optionally)  stored and used in a secure element<br>
-- TLS-IM: TLS Identity Module<br>
-- https://tools.ietf.org/html/draft-urien-tls-im-03<br>
***
