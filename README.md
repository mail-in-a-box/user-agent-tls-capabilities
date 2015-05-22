Scraped Data from Qualys's User Agent Capabilities Tables
=========================================================

[Qualys SSL Labs](https://dev.ssllabs.com) maintains great tools for checking that TLS has been set up correctly. This project scrapes their [User Agent Capabilities](https://dev.ssllabs.com/ssltest/clients.html) pages --- sorry Qualys --- and turns it into open data.

Qualys has collected data on 36 clients (e.g. Chrome, Android, OpenSSL) including:

* TLS versions supported (SSL 2, SSL 3, TLS 1.0, TLS 1.1, TLS 1.2).
* Ciphers supported (and preference order), and information on whether ciphers support forward secrecy or are weak or insecure.
* Other protocol details (e.g. support for Server Name Indication (SNI)).

You'll find this scraped and stored in this repository as [clients.json](clients.json) and [clients.csv](clients.csv), with additional cipher information in [ciphers.json](ciphers.json).

I've also copied [Mozilla's cipher name correspondence table](https://wiki.mozilla.org/Security/Server_Side_TLS) into [cipher_names.csv](cipher_names.csv).
