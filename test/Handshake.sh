#!/usr/bin/bash

# Usage: ./handshake.sh 
# 	<user id file>
#	<password>

public_key_file="useless_public_key.pub"

private_key_filepath="useless_private_key.key"

public_key=$(cat $public_key_file)
echo "public_key - $public_key"

user_id=0000
echo "user_id - $user_id"

password=$1
echo "password - $password"

echo "Starting handshake..."
curl -s -X POST '127.0.0.1:5000/v2/sync/users/0000/sessions/1111/' \
	-d "{\"public_key\":\"$public_key\", \"password\":\"$password\"}" \
	-H "Content-Type: application/json" | \
	jq -cr '.verification_url' | \
	xargs -0 -I{} verification_url={}
	echo "$password" | \
	tr -d '\n' | \
	openssl pkeyutl -encrypt -inkey useless_public_key.pub -pubin \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1 | \
	base64 -w 0 | \
	xargs -0 -I{} curl -s -X POST \
	-H "Content-Type: application/json" \
	-d '{"password":"{}"}' "http://127.0.0.1:5000$verification_url" | \
	jq -cr '.shared_key' | \
	base64 --decode | \
	openssl pkeyutl -decrypt -inkey $private_key_filepath \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1
