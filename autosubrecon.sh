#!/bin/bash

# Load .env file with API_KEY
set -o allexport
source .env
set +o allexport


# Set the target domain
target_domain="$1"

# Check if target_domain is provided
if [ -z "$target_domain" ]; then
  echo "[+] usage $0 domain.com "
  exit 1
fi


# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color


ascii_art=''' 
┏┓┳┳┏┳┓┏┓┏┓┳┳┳┓┳┓┏┓┏┓┏┓┳┓
┣┫┃┃ ┃ ┃┃┗┓┃┃┣┫┣┫┣ ┃ ┃┃┃┃
┛┗┗┛ ┻ ┗┛┗┛┗┛┻┛┛┗┗┛┗┛┗┛┛┗ by @peterChain
'''
echo -e "${RED} $ascii_art ${NC}"


### Check if a directory does not exist create new
if [ ! -d "subs/" ] 
then
    echo "[+] Creating subs/ Directory." 
	mkdir -p subs/{active,passive,full}
    # exit 9999 # die with error code 9999
fi
# rm -r subs/
# mkdir subs

# Check if required tools are installed and install if not availlable.
check_tools() {
    local tools=("subfinder" "puredns" "gotator" "cero" "httpx" "gospider" "unfurl" "massdns" "amass" "sublist3r" "assetfinder" "findomain")
    local missing_tools=()
    
    echo "[+] Checking for required tools..."
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[!] Please install the missing tools before running the script${NC}"

        echo -e "${YELLOW}[!] Attempting Installation"
        sudo apt update
		sudo apt install golang massdns amass sublist3r assetfinder findomain -y
		# For sublist3r
		sudo apt-get install libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev
		pip3 install dnspython requests
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install github.com/d3mondev/puredns/v2@latest
        go install github.com/Josue87/gotator@latest
        go install github.com/glebarez/cero@latest
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install github.com/jaeles-project/gospider@latest
        go install github.com/tomnomnom/unfurl@latest
		
		
         # Copy the go binaries to /usr/local/bin to make them available in path
        echo -e "${YELLOW}[!] Adding Installed binary to /usr/local/bin"
        sudo cp -r /home/$USER/go/bin/* /usr/local/bin
        exit 1
    fi
    
    echo -e "${GREEN}[+] All required tools are installed!${NC}"
}

check_tools

finish_passive() {
    echo "[+] Combining subdomains and resolving them..."
    cat "subs/passive/"*.txt | sort -u > "subs/passive/all_subs_filtered.txt"
    puredns resolve "subs/passive/all_subs_filtered.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/passive/all_subs_resolved.txt" --skip-wildcard-filter --skip-validation &> /dev/null
    
    echo -e "${YELLOW}[+] Saving  live hosts to subs/passive/filtered_hosts.txt"
    cat "subs/passive/all_subs_resolved.txt" | httpx -random-agent -retries 4 --silent -o "subs/passive/filtered_live_hosts.txt"  &> /dev/null
    echo -e "${YELLOW}[+] Done with subdomain enumeration!"
}

finish_active() {
    echo "[+] Combining subdomains and resolving them..."
    cat "subs/active/"*.txt | sort -u > "subs/active/all_subs_filtered.txt"
    puredns resolve "subs/active/all_subs_filtered.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/active/all_subs_resolved.txt" --skip-wildcard-filter --skip-validation &> /dev/null
    
	echo -e "${YELLOW}[+] Saving  live hosts to subs/active/filtered_hosts.txt"
	cat "subs/active/all_subs_resolved.txt" | httpx -random-agent -retries 4 --silent -o "subs/active/filtered_live_hosts.txt"  &> /dev/null
    echo -e "${YELLOW}[+] Done with subdomain enumeration!"
}

passive_recon() {
	# URLs to fetch subdomains from various sources
	urls=(
		"https://rapiddns.io/subdomain/$target_domain?full=1#result"
		"http://web.archive.org/cdx/search/cdx?url=*.$target_domain/*&output=text&fl=original&collapse=urlkey"
		"https://crt.sh/?q=%.$target_domain"
		"https://crt.sh/?q=%.%.$target_domain"
		"https://crt.sh/?q=%.%.%.$target_domain"
		"https://crt.sh/?q=%.%.%.%.$target_domain"
		"https://otx.alienvault.com/api/v1/indicators/domain/$target_domain/passive_dns"
		"https://api.hackertarget.com/hostsearch/?q=$target_domain"
		"https://urlscan.io/api/v1/search/?q=$target_domain"
		"https://jldc.me/anubis/subdomains/$target_domain"
		"https://www.google.com/search?q=site%3A$target_domain&num=100"
		"https://www.bing.com/search?q=site%3A$target_domain&count=50"
	)
    # Passive subdomain enumeration
    echo "[+] Let's start with passive subdomain enumeration!"
    
    echo  "[+] Getting $target_domain subdomains using [crt.sh,rapiddns,alienvault,hackertarget,urlscan,jldc.me,google,bing]"

	for url in "${urls[@]}"; do
		curl -s "$url" | grep -o  '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.'"$target_domain"'' >> "subs/passive/passive.txt"
	done

	wait
    
	echo  "[+] Removing duplicates....."
	echo  "[+] Saving to quick_passive.txt"

    curl -k -s "https://crt.sh/?q=$target_domain&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u >> "subs/passive/passive-2-url.txt" 
	cat "subs/passive/passive.txt" | sort -u > "subs/passive/quick_passive.txt"
	rm "subs/passive/passive.txt"

	echo -e "${YELLOW}[+] Using subfinder for passive subdomain enumeration "
	subfinder -d $target_domain --all --silent -o "subs/passive/subfinder.txt" > /dev/null 2>&1 
    
	echo -e "${YELLOW}[+] Enumerating subdomains using Sublist3r"
 	sublist3r -d "$target_domain" -o "subs/passive/sublist3r_Tool.txt" 2> /dev/null 

	echo -e "${YELLOW}[+] Enumerating subdomains using amass"
	amass enum -passive -d "$target_domain" > "subs/passive/amass_Tool.txt" 2>/dev/null

	echo -e "${YELLOW}[+] Enumerating subdomains using Assetfinder"
	assetfinder "$target_domain" > "subs/passive/assetfinder_Tool.txt" 2>/dev/null

	echo -e "${YELLOW}[+] Enumerating subdomains using Findomain"
	findomain -t "$target_domain" -u "subs/passive/findomain_Tool.txt" > /dev/null 2>&1

	# TLS probing using cero
	echo  "[+] TLS probing using cero"
	cero "$target_domain" | sed 's/^*.//' | grep  "\." | sort -u |  grep ".$target_domain$" > "subs/passive/tls_probing.txt"

    echo -e "${YELLOW}[+] Enumerating subdomains using dnsdumpster"
	curl -s -H "X-API-Key: $API_KEY" https://api.dnsdumpster.com/domain/$target_domain |grep -oP "(?<=\")[a-zA-Z0-9.-]+$target_domain" | sort -u > "subs/passive/dnsdumpster_results.txt"
	
    echo -e "${YELLOW}[+] That's it, we are done with passive subdomain enumeration!"
	finish_passive
}

# Define a function for active reconnaissance
active_recon() {
    # Active subdomain enumeration
    echo "[+] Start active subdomain enumeration!"
    
    echo  "[+] DNS Brute Forcing using puredns"
	puredns bruteforce "wordlist/brute/2m-subdomains.txt" "$target_domain" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/active/dns_bf.txt" --skip-wildcard-filter --skip-validation &> /dev/null

	echo  "[+] resolving brute forced subs...."
	puredns resolve "subs/active/dns_bf.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/active/dns_bf_resolved.txt"  --skip-wildcard-filter --skip-validation &> /dev/null

	# Permutations using gotator - DNS wordlist generator
	echo  "[+] Permutations using gotator"
	gotator -sub "subs/active/dns_bf_resolved.txt" -perm "wordlist/dns/dns_permutations_list.txt" -depth 1 -numbers 5 -mindup -adv -md -fast -silent | sort -u > "subs/active/possible-permutations.txt"
	# Validate valid subdomain
	puredns resolve "subs/active/possible-permutations.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/active/permutations.txt" --skip-wildcard-filter --skip-validation &> /dev/null


	# TLS probing using cero
	echo  "[+] TLS probing using cero"
	cero "$target_domain" | sed 's/^*.//' | grep  "\." | sort -u |  grep ".$target_domain$" > "subs/active/tls_probing.txt"

	# Scraping (JS/Source) code
	echo  "[+] Scraping JS Source code "
	cat "subs/active/"* | sort -u > "subs/active/filtered_subs.txt"
	cat "subs/active/filtered_subs.txt" | httpx -random-agent -retries 2 -o "subs/active/filtered_hosts.txt" &> /dev/null

	# Crawling using gospider
	echo  "[+] Crawling for js files using gospider"
	gospider -S "subs/active/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/active/gospider.txt"

	# Extracting subdomains from JS Files
	echo  "[+] Extracting Subdomains......"
	sed -i '/^.\{2048\}./d' "subs/active/gospider.txt"
	cat "subs/active/gospider.txt" | grep -o 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/active/scrap_subs.txt"
	rm "subs/active/gospider.txt"
    
    echo "[+] Done with Active subdomain enumeration!"
	finish_active
}



# Define a function for full reconnaissance
full_recon() {
    passive_recon
    active_recon
	finish_passive
	finish_active
	echo "[+] Full Recon is complete!"
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