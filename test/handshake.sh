#!/bin/sh

# Usage: ./handshake.sh <public key file (.pem)> <private key file (.pem)> <password>

public_key=$(cat $1)
echo "$public_key"

private_key_filepath=$2
password=$3

# Performs the handshake and decrypts the shared key data at the end
curl -s http://localhost:6969/v2/sync/users/a161a060-989d-11ec-8468-5b3dca686254 | \
	xargs -I{} websocat {} | \
	xargs -I{} curl -s -X POST {} \
	-d "{\"public_key\":\"$public_key\"}" \
	-H "Content-Type: application/json" | \
	jq -cr '.verification_url, .public_key' | \
	xargs -0 -I{} sh -c 'echo "{}" > /tmp/gateway_client_public_key.pem' && \
	verification_url=$(head -n 1 /tmp/gateway_client_public_key.pem) && \
	sed -i '/v2/d' /tmp/gateway_client_public_key.pem && \
	echo "$password" | \
	tr -d '\n' | \
	openssl pkeyutl -encrypt -inkey /tmp/gateway_client_public_key.pem -pubin \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1 | \
	base64 -w 0 | \
	xargs -0 -I{} curl -s -X POST \
	-H "Content-Type: application/json" \
	-d '{"password":"{}"}' "http://localhost:6969$verification_url" | \
	jq -cr '.shared_key' | \
	base64 --decode | \
	openssl pkeyutl -decrypt -inkey $private_key_filepath \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1
