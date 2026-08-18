#!/bin/bash

# Prints a marketplace JWT for a user of the marketplace database.
#
# The marketplace issues tokens through its web app only, and the token subject
# is the numeric account id rather than the user name. This logs in, reads the
# account id off the account page, and asks for the token, so that only the user
# name is needed.
#
# Usage: marketplace/tools/get-jwt.sh <user> [password] [url] [sub-account]
# Example: marketplace/tools/get-jwt.sh alice
#          marketplace/tools/get-jwt.sh alice 1234 https://127.0.0.1:8888 hummbwtester

set -e

user=$1
pass=${2:-1234}
url=$3
scope=$4

if [ -z "$user" ] || [ "$user" = "-h" ] || [ "$user" = "--help" ]; then
    echo "usage: $0 <user> [password] [url] [sub-account]" >&2
    exit 1
fi

# Default to the address the marketplace was configured to listen on.
if [ -z "$url" ]; then
    api_addr=$(sed -n 's/^api_addr *= *"\(.*\)"/\1/p' gen/AS*/marketplace.toml 2>/dev/null | head -1)
    url="https://${api_addr:-127.0.0.1:8888}"
fi

jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

# The certificate is self-signed for marketplace.local, hence -k.
curl -ksSf -c "$jar" -o /dev/null \
    -d "username=$user" -d "password=$pass" "$url/login"

page=$(curl -ksSf -b "$jar" "$url/account")

# An unauthenticated /account redirects to the login page, so a missing main
# account id means the credentials were rejected.
main_id=$(sed -n 's/.*id="main-account-id">\([0-9]*\)<.*/\1/p' <<<"$page")
if [ -z "$main_id" ]; then
    echo "could not log in as $user at $url (wrong password?)" >&2
    exit 1
fi

if [ -z "$scope" ]; then
    id=$main_id
else
    id=$(sed -n "s/.*requestJWT('\([0-9]*\)','$scope').*/\1/p" <<<"$page")
    if [ -z "$id" ]; then
        echo "$user has no sub account \"$scope\" at $url" >&2
        exit 1
    fi
fi

curl -ksSf -b "$jar" -d "id=$id" "$url/account/token"
echo
