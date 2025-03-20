#!/bin/bash

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
# if [ ! -d "subs/" ] 
# then
#     echo "[+] Creating subs/ Directory." 
# 	mkdir -p subs/{active,passive,full}
#     exit 9999 # die with error code 9999
# fi
rm -r subs/
mkdir subs

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

finish_work() {
    echo "[+] Combining subdomains and resolving them..."
    cat "subs/"* | sort -u > "subs/all_subs_filtered.txt"
    puredns resolve "subs/all_subs_filtered.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/all_subs_resolved.txt" --skip-wildcard-filter --skip-validation &> /dev/null
    echo -e "${YELLOW}[+] Saving  live hosts to subs/filtered_hosts.txt"
	cat "subs/all_subs_resolved.txt" | httpx -random-agent -retries 2 --silent -o "subs/filtered_hosts.txt"  &> /dev/null
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
		curl -s "$url" | grep -o  '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.'"$target_domain"'' >> "subs/passive.txt"
	done

	wait

	echo  "[+] Removing duplicates....."
	echo  "[+] Saving to quick_passive.txt"

	cat "subs/passive.txt" | sort -u > "subs/quick_passive.txt"
	rm "subs/passive.txt"

	echo  "${YELLOW}[+] Using subfinder for passive subdomain enumeration "
	subfinder -d $target_domain --all --silent -o "subs/subfinder.txt" > /dev/null 2>&1 
    
	echo -e "${YELLOW}[+] Enumerating subdomains using Sublist3r"
 	sublist3r -d "$target_domain" -o "subs/sublist3r_Tool.txt" 2> /dev/null 

	echo -e "${YELLOW}[+] Enumerating subdomains using amass"
	amass enum -passive -d "$target_domain" > "subs/amass_Tool.txt" 2>/dev/null

	echo -e "${YELLOW}[+] Enumerating subdomains using Assetfinder"
	assetfinder "$target_domain" > "subs/assetfinder_Tool.txt" 2>/dev/null

	echo -e "${YELLOW}[+] Enumerating subdomains using Findomain"
	findomain -t "$target_domain" -u "subs/findomain_Tool.txt" > /dev/null 2>&1

    echo -e "${YELLOW}[+] Enumerating subdomains using dnsdumpster"
	curl -s -H "X-API-Key: xxxxxxxx" https://api.dnsdumpster.com/domain/$target_domain |grep -oP "(?<=\")[a-zA-Z0-9.-]+$target_domain" | sort -u > "subs/dnsdumpster_results.txt"
	
    echo -e "${YELLOW}[+] That's it, we are done with passive subdomain enumeration!"
	finish_work
}

# Define a function for active reconnaissance
active_recon() {
    # Active subdomain enumeration
    echo "[+] Start active subdomain enumeration!"
    
    echo  "[+] DNS Brute Forcing using puredns"
	puredns bruteforce "wordlist/brute/2m-subdomains.txt" "$target_domain" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/dns_bf.txt" --skip-wildcard-filter --skip-validation &> /dev/null

	echo  "[+] resolving brute forced subs...."
	puredns resolve "subs/dns_bf.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/dns_bf_resolved.txt"  --skip-wildcard-filter --skip-validation &> /dev/null

	# Permutations using gotator - DNS wordlist generator
	echo  "[+] Permutations using gotator"
	gotator -sub "subs/dns_bf_resolved.txt" -perm "wordlist/dns/dns_permutations_list.txt" -depth 1 -numbers 5 -mindup -adv -md -fast -silent | sort -u > "subs/possible-permutations.txt"
	# Validate valid subdomain
	puredns resolve "subs/possible-permutations.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/permutations.txt" --skip-wildcard-filter --skip-validation &> /dev/null


	# TLS probing using cero
	echo  "[+] TLS probing using cero"
	cero "$target_domain" | sed 's/^*.//' | grep  "\." | sort -u |  grep ".$target_domain$" > "subs/tls_probing.txt"

	# Scraping (JS/Source) code
	echo  "[+] Scraping JS Source code "
	cat "subs/"* | sort -u > "subs/filtered_subs.txt"
	cat "subs/filtered_subs.txt" | httpx -random-agent -retries 2 -o "subs/filtered_hosts.txt" &> /dev/null

	# Crawling using gospider
	echo  "[+] Crawling for js files using gospider"
	gospider -S "subs/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider.txt"

	# Extracting subdomains from JS Files
	echo  "[+] Extracting Subdomains......"
	sed -i '/^.\{2048\}./d' "subs/gospider.txt"
	cat "subs/gospider.txt" | grep -o 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/scrap_subs.txt"
	rm "subs/gospider.txt"
    
    echo "[+] Done with Active subdomain enumeration!"
	finish_work
}

# Define a function for normal reconnaissance
normal_recon() {
    passive_recon
    
    # Active subdomain enumeration
	echo  "[+] Start active subdomain enumeration!"

	# 1. DNS Brute Forcing using puredns
	echo  "[+] DNS Brute Forcing using puredns"
	puredns bruteforce "wordlist/brute/2m-subdomains.txt" "$target_domain" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/dns_bf.txt" --skip-wildcard-filter --skip-validation &> /dev/null

	echo  "[+] resolving brute forced subs...."
	puredns resolve "subs/dns_bf.txt" -r "wordlist/dns/resolvers-trusted.txt" -w "subs/dns_bf_resolved.txt"  --skip-wildcard-filter --skip-validation &> /dev/null

	# 3. TLS probing using cero
	echo  "[+] TLS probing using cero"
	cero "$target_domain" | sed 's/^*.//' | grep  "\." | sort -u |  grep ".$target_domain$" > "subs/tls_probing.txt"

	# 4. Scraping (JS/Source) code
	echo  "[+] Scraping JS Source code "
	cat "subs/"* | sort -u > "subs/filtered_subs.txt"
	cat "subs/filtered_subs.txt" | httpx -random-agent -retries 2 -o "subs/filtered_hosts.txt" &> /dev/null

	# Crawling using gospider
	echo  "[+] Crawling for js files using gospider"
	gospider -S "subs/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider.txt"

	# Extracting subdomains from JS Files
	echo  "[+] Extracting Subdomains......"
	sed -i '/^.\{2048\}./d' "subs/gospider.txt"
	cat "subs/gospider.txt" | grep -o 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/scrap_subs.txt"
	rm "subs/gospider.txt"

	# Done with active subdomain enumeration
	echo  "[+] Done with Active subdomain enumeration!"
    
    echo "[+] Normal Recon is complete!"
	finish_work
}

# Define a function for quick reconnaissance
quick_recon() {
    passive_recon
    
	# TLS probing using cero
	echo  "[+] TLS probing using cero"
	cero "$target_domain" | sed 's/^*.//' | grep  "\." | sort -u |  grep ".$target_domain$" > "subs/tls_probing.txt"

	# Scraping (JS/Source) code
	echo  "[+] Scraping JS Source code "
	cat "subs/"* | sort -u > "subs/filtered_subs.txt"
	cat "subs/filtered_subs.txt" | httpx -random-agent -retries 2 -o "subs/filtered_hosts.txt" &> /dev/null

	# Crawling using gospider
	echo  "[+] Crawling for js files using gospider"
	gospider -S "subs/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider.txt"

	# Extracting subdomains from JS Files
	echo  "[+] Extracting Subdomains......"
	sed -i '/^.\{2048\}./d' "subs/gospider.txt"
	cat "subs/gospider.txt" | grep -o 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/scrap_subs.txt"
	rm "subs/gospider.txt"    
    echo "[+] Quick Recon is complete!"
	finish_work
}

# Define a function for full reconnaissance
full_recon() {
    passive_recon
    active_recon
    
    echo "[+] Full Recon is complete!"
	finish_work
}

# Display options and process user's choice
options='''
Choose what you wanna do?
[1] Passive recon only
[2] Active recon only
[3] Normal Recon [All without permutations]
[4] Quick Recon [All without Brute forcing and Permutations]
[5] Full recon [All Techniques]
'''

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
        normal_recon
        ;;
    4)
        quick_recon
        ;;
    5)
        full_recon
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo "[+] Finished:"