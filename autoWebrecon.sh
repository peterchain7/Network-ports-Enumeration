#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

printf "
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
                          by peterChain
"

echo -en "${YELLOW} [+] Enter Full domain: "
read domain
passive_recon()
  {
    wget $domain | grep -io '<a href=['"'"'"][^"'"'"']*['"'"'"]' |sed -e 's/^<a href=["'"'"']//i' -e 's/["'"'"']$//i' | tee "${domain}-url.txt" 
    curl "$domain" | tr '"' '\n' | tr "'" '\n' | grep -e '^https://' -e '^http://' -e'^//' | sort | uniq >> "${domain}-url.txt" 
    curl -Ls "$domain" |  grep -oP 'href="\K[^"]+' | sort | uniq >> "${domain}-url.txt" 
    curl -f -L "$domain" | grep -Eo '"(http|https)://[a-zA-Z0-9#~.*,/!?=+&_%:-]*"' | sort | uniq >> "${domain}-url.txt" 
    cat "${domain}-url.txt"|sort | uniq >> "${domain}-urls.txt"
  }

# Display options and process user's choice
options='''
Choose what you wanna do?
[1] Passive recon only
[2] Active recon only
[3] Full recon [All Techniques]
'''
# [3] Normal Recon [All without permutations]
# [4] Quick Recon [All without Brute forcing and Permutations]

echo -e "${GREEN} $options ${NC}"
read -p "Enter your choice: " choice

case $choice in
    1)
        passive_recon
        ;;
    2)
        active_recon
        ;;
    3)
        full_recon
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo "[+] Finished:"