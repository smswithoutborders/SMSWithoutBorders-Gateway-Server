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

password="testpassword"
echo "password - $password"

echo "Starting handshake..."
verification_url="http://127.0.0.1:5000/v2/sync/users/dead3662-5f78-11ed-b8e7-6d06c3aaf3c6/sessions/000/"

echo "$password" | \
	tr -d '\n' | \
	openssl pkeyutl -encrypt -inkey useless_public_key.pub -pubin \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1 | \
	base64 -w 0 | \
	xargs -0 -I{} curl -s -X POST \
	-H "Content-Type: application/json" \
	-d "{\"public_key\":\"$public_key\", \"password\":\"{}\"}" \
	"$verification_url" | \
	jq -cr '.shared_key' | \
	base64 --decode | \
	openssl pkeyutl -decrypt -inkey $private_key_filepath \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1
