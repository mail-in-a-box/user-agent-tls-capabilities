#!/usr/bin/python3
#
# This script scrapes Qualys's User Agent Capabilities pages and writes the
# information into clients.json and ciphers.json.
###########################################################################

import re
import json
from collections import OrderedDict
import urllib.request, urllib.parse
from bs4 import BeautifulSoup

def fetch_page(url):
	html = urllib.request.urlopen(url).read()
	return BeautifulSoup(html)

cipher_info = [ ]
client_data = [ ]

protocol_detail_keys = {
	"OCSP stapling": "ocsp_staping",
	"Server Name Indication (SNI)": "sni",
	"Secure Renegotiation": "secure_reneg",
	"Next Protocol Negotiation": "next_proto_reneg",
	"Application Layer Protocol Negotiation": "app_level_proto_reneg",
	"Session tickets": "session_tickets",
	"SSL 2 handshake compatibility": "ssl2_handshake_compat",
	"Elliptic curves": "elliptic_curves",
	"TLS compression": "tls_compression",
	"Signature algorithms": "signature_algo",
}

client_list_url = "https://dev.ssllabs.com/ssltest/clients.html"
client_list = fetch_page(client_list_url)
for client_anchor in client_list.find_all('a'):
	url = urllib.parse.urlparse(client_anchor.get('href'))
	if url.path == "viewClient.html":
		# get name/version/platform parameters
		client = urllib.parse.parse_qs(url.query)
		client = (client['name'][0], client['version'][0], client['platform'][0] if 'platform' in client else None)

		# parse client detail page
		client_page = fetch_page(urllib.parse.urljoin(client_list_url, client_anchor.get('href')))
		tables = client_page.find_all('table', class_='reportTable')
		protocols_table, cipher_suites_table, details_table = tables

		# Parse protocols supported.
		protocols_supported = []
		for tr in protocols_table.find_all('tr'):
			if tr.text.strip() == "Protocols": continue # header
			m = re.match(r"(SSL 2|SSL 3|TLS 1.0|TLS 1.1|TLS 1.2)(?:\s+INSECURE)?\s+(Yes|No)\s*$", tr.text.replace("\n", " ").strip())
			if not m: raise Exception(tr.text)
			if m.group(2) == "Yes":
				protocols_supported.append(m.group(1))

		# Parse ciphers supported (provided in order of preference).
		cipher_list = []
		for tr in cipher_suites_table.find_all('tr'):
			if "Cipher Suites" in tr.text: continue # header
			if tr.text.strip().startswith("(1)"): continue # footer
			if tr.text.strip().startswith("(2)"): continue # footer
			m = re.match(r"((?:TLS|SSL)_\S+) \(0x([0-9a-z]+)\)(?:\s+(WEAK|INSECURE|Forward Secrecy|Forward Secrecy2))?\s+(\d+|-)\s*$", tr.text.replace("\n", " ").strip())
			if not m: raise Exception(tr.text)
			cipher_name, cipher_hex, cipher_notes, cipher_bits = m.groups()
			if cipher_notes == "Forward Secrecy2": cipher_notes = None # Cannot be used for Forward Secrecy because they require DSA keys, which are effectively limited to 1024 bits.
			cipher_list.append(cipher_name)

			# Cipher info is the same across all clients...
			cipher_info.append(OrderedDict([
				("name", cipher_name),
				("code", cipher_hex),
				("bits", cipher_bits),
				("notes", cipher_notes),
			]))

		# Parse protocol details.
		protocol_details = { }
		for tr in details_table.find_all('tr'):
			if "Protocol Details" in tr.text: continue # header
			key, value = tr.find_all('td')
			key = protocol_detail_keys[key.text.strip()]
			value = value.text.strip()
			if key in ('elliptic_curves', 'signature_algo'): value = re.split(r",\t+", value)
			protocol_details[key] = value

		# Add to master list.
		client_data.append(OrderedDict([
			("client", OrderedDict([
				("name", client[0]),
				("version", client[1]),
				("platform", client[2]),
			])),
			("protocols", protocols_supported),
			("ciphers", cipher_list),
			("details", protocol_details),
		]))

# Sort ciphers.
cipher_info.sort(key = lambda x : x['name'])

with open("ciphers.json", "w") as f:
	json.dump(cipher_info, f, indent=2)
with open("clients.json", "w") as f:
	json.dump(client_data, f, indent=2)
