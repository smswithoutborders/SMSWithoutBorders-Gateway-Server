#!/usr/bin/bash

# Use below command to extract public from chain file
# openssl x509 -in /tmp/server_pubkey.pub -pubkey -noout
#
# Usage: ./handshake.sh <path to public key file> <email address to send test email>

server_public_key=$1
echo "Server public key - $server_public_key"

public_key_file="useless_public_key.pub"

private_key_filepath="useless_private_key.key"

public_key=$(cat $public_key_file)

user_id="dead3662-5f78-11ed-b8e7-6d06c3aaf3c6"

password="dummy_password"

MSISDN="+237123456789"

echo "Starting handshake..."
# verification_url="http://127.0.0.1:5000/v2/sync/users/dead3662-5f78-11ed-b8e7-6d06c3aaf3c6/sessions/000/"
verification_url="https://staging.smswithoutborders.com:15000/v2/sync/users/${user_id}/sessions/000/"
messaging_url="https://staging.smswithoutborders.com:15000/sms/platform/gateway-server"

#echo "public_key - $public_key"
#echo "user_id - $user_id"
#echo "password - $password"
#echo "verification url - $verification_url"

# request_body="{\"public_key\":\"$public_key\", \"password\":\"{}\", \"mgf1ParameterSpec\":\"sha256\", \"mgf1ParameterSpec_dec\":\"sha256\"}"

email=$2
subject="Afkanerd - SMSWithoutBorders state of things"
body="Hi!\nThis is test on $( date ), is intended to see if SMSWithoutBorders can now publish!\n\nMany thanks, Afkanerd"
email_content="g:${email}:::${subject}:${body}"

tmp_email_content_file=/tmp/email_content.txt
echo $email_content > $tmp_email_content_file

iv=$((1234567890123456 + $RANDOM % 4))

echo "Email content:- $email_content"

encrypted_password=$( echo "$password" | tr -d '\n' | \
	openssl pkeyutl -encrypt -inkey $server_public_key -pubin \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha256 | \
	base64 -w 0 )
echo "- Encrypted password: $encrypted_password"

encrypted_shared_key=$( curl -s -X POST \
	-H "Content-Type: application/json" \
	-d "{\"public_key\":\"$public_key\", \"password\":\"$encrypted_password\", \"mgf1ParameterSpec\":\"sha256\"}" \
	"$verification_url" | \
	jq -cr '.shared_key' )
echo "- Encrypted shared key: $encrypted_shared_key"

decrypted_shared_key=$( echo $encrypted_shared_key | \
	base64 --decode | \
	openssl pkeyutl -decrypt -inkey $private_key_filepath \
	-pkeyopt rsa_padding_mode:oaep \
	-pkeyopt rsa_oaep_md:sha256 \
	-pkeyopt rsa_mgf1_md:sha1 )
echo "- Decrypted shared key: $decrypted_shared_key"
echo "- Iv: $iv"

shared_key_hex=$( echo $decrypted_shared_key | od -A n -t x1 | sed -z 's/[ \n]*//g' | sed -z 's/0a$//g' )
iv_hex=$( echo $iv | od -A n -t x1 | sed -z 's/[ \n]*//g' | sed -z 's/0a$//g' )

echo "- Shared key hex: $shared_key_hex"
echo "- Iv hex: $iv_hex"


encrypted_content=$( echo $email_content | \
	 openssl enc -aes-256-cbc -e -iv "$iv_hex" -K "$shared_key_hex" -in $tmp_email_content_file -a )
encrypted_content="${iv}${encrypted_content}"
encrypted_content_b64=$( echo $encrypted_content | base64 -w 0 )

echo "- Encrypted content: $encrypted_content_b64"

curl -X POST \
	-H "Content-Type: application/json" \
	-d "{\"text\":\"$encrypted_content_b64\", \"MSISDN\":\"$MSISDN\"}" \
	"$messaging_url"
