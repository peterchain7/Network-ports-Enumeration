#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

printf "
 #    # #####  #       #####  ######   ####    ####   #    #
 #    # #    # #       #   #  #       #       #    #  ##   #
 #    # #    # #       #   #  #####   #       #    #  # #  #
 #    # #####  #       #####  #       #       #    #  #  # #
 #    # #   #  #       #   #  #       #       #    #  #   ##
  ####  #    # ######  #    # ######   ####    ####   #    # by peterChain
"

echo -en "${YELLOW} [+] Enter Full domain: "
read domain
wget $domain | grep -io '<a href=['"'"'"][^"'"'"']*['"'"'"]' |sed -e 's/^<a href=["'"'"']//i' -e 's/["'"'"']$//i' | tee "out-url.txt" 
curl "$domain" | tr '"' '\n' | tr "'" '\n' | grep -e '^https://' -e '^http://' -e'^//' | sort | uniq >> "out-url.txt" 
curl -Ls "$domain" |  grep -oP 'href="\K[^"]+' | sort | uniq >> "out-url.txt" 
curl -f -L "$domain" | grep -Eo '"(http|https)://[a-zA-Z0-9#~.*,/!?=+&_%:-]*"' | sort | uniq >> "out-url.txt" 
cat "out-url.txt"|sort | uniq >> "out-urls.txt"

# subdomain
echo -e "${YELLOW} [+] Subdomain enumeration started"
curl -k -s "https://crt.sh/?q=$domain&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u >> "out-url.txt" 