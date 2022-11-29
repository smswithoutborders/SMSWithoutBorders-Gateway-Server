#!/usr/bin/bash

# Usage: ./handshake.sh 
# 	<user id file>
#	<password>

server_public_key=$1
echo "Server public key - $server_public_key"

public_key_file="useless_public_key.pub"

private_key_filepath="useless_private_key.key"

public_key=$(cat $public_key_file)

user_id="dead3662-5f78-11ed-b8e7-6d06c3aaf3c6"

password="dummy_password"

echo "Starting handshake..."
# verification_url="http://127.0.0.1:5000/v2/sync/users/dead3662-5f78-11ed-b8e7-6d06c3aaf3c6/sessions/000/"
verification_url="https://staging.smswithoutborders.com:15000/v2/sync/users/${user_id}/sessions/000/"
# TODO: messaging URL

echo "public_key - $public_key"
echo "user_id - $user_id"
echo "password - $password"
echo "verification url - $verification_url"

# request_body="{\"public_key\":\"$public_key\", \"password\":\"{}\", \"mgf1ParameterSpec\":\"sha256\", \"mgf1ParameterSpec_dec\":\"sha256\"}"

request_body="{\"public_key\":\"$public_key\", \"password\":\"{}\", \"mgf1ParameterSpec\":\"sha256\"}"

echo "$password" | \
	tr -d '\n' | \
	openssl pkeyutl -encrypt -inkey $server_public_key -pubin \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha256 | \
	base64 -w 0 | \
	xargs -0 -I{} curl -s -X POST \
	-H "Content-Type: application/json" \
	-d "$request_body" \
	"$verification_url" | \
	jq -cr '.shared_key' | \
	base64 --decode | \
	openssl pkeyutl -decrypt -inkey $private_key_filepath \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1
# TODO: use shared key to encrypt and transmit message to online platform
