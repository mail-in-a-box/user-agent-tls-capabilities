#!/usr/bin/python3
# This turns clients.json into a nice CSV table.
################################################

import json, csv

ciphers = json.load(open("ciphers.json"))
clients = json.load(open("clients.json"))

# Get the non-insecure ciphers.
all_ciphers = set(cipher['iana'] for cipher in ciphers if cipher['notes'] != "INSECURE")

# Compute a single linear order for ciphers, like a rough
# master preference order, just for the sake of making
# pretty output. Skip all INSECURE ciphers -- we don't
# care about these anymore.
# -------------------------------------------------------

# Count the number of times every pair of ciphers occurs
# in a particular order across clients.
pairwise_ordering = { }
for client in clients:
	for i, cipher1 in enumerate(client["ciphers"]):
		for cipher2 in client["ciphers"][i+1:]:
			if cipher1 in all_ciphers and cipher2 in all_ciphers:
				key = (cipher1, cipher2)
				pairwise_ordering[key] = pairwise_ordering.get(key, 0) + 1

# Assemble a master preference list by greedily adding the
# worst cipher in each iteration, where worst is based on
# where it appears between the ciphers above and below it.
cipher_order = []
ciphers_left = set(all_ciphers)
while len(ciphers_left) > 0:
	# What is the worst cipher not yet added?
	def score_cipher(cipher):
		return sum(v for k, v in pairwise_ordering.items() if k[0] in ciphers_left and k[1] == cipher ) \
			- sum(v for k, v in pairwise_ordering.items() if k[0] == cipher and k[1] not in ciphers_left )
	cipher = max(ciphers_left, key = score_cipher)
	cipher_order.append(cipher)
	ciphers_left.remove(cipher)

# And reverse it so the best are on top.
cipher_order.reverse()

# Compute a linear order to the clients that ranks them by
# how high up/low down their supported ciphers are.
def rank_client(client):
	ciphers = set(client['ciphers']) & all_ciphers
	return sum(cipher_order.index(cipher) for cipher in ciphers)/len(ciphers) \
		 + len(client['ciphers'])**.2
clients.sort(key = rank_client, reverse=True)

# Write a nice CSV.
protocols = list(reversed(['SSL 2', 'SSL 3', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2']))
protocol_details = ["ocsp_stapling", "sni", "secure_reneg", "next_proto_reneg", "app_level_proto_reneg", "session_tickets", "ssl2_handshake_compat", "tls_compression" ]
with open("clients.csv", "w") as f:
	w = csv.writer(f)
	w.writerow(["client name", "version", "platform"] + protocols + cipher_order + protocol_details)
	for client in reversed(clients):
		w.writerow(
			[
				client['client']['name'],
				client['client']['version'],
				client['client']['platform'],
			]
			+ ["Y" if p in client['protocols'] else "" for p in protocols]
			+ ["Y" if c in client['ciphers'] else "" for c in cipher_order]
			+ ["Y" if client['details'][d] == 'Yes' else "" for d in protocol_details]
			)
