# Installation of security tools
## https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/Josue87/gotator@latest
go install github.com/glebarez/cero@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/unfurl@latest

# Install sublist3r
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt

# Install amass
sudo apt install amass

# Install jq for parsing JSON
sudo apt install jq
```

# precon tool
```bash
Here are the links to the tools used in Precon:

1. amass: GitHub - https://github.com/OWASP/Amass
2. assetfinder: GitHub - https://github.com/tomnomnom/assetfinder
3. subfinder: GitHub - https://github.com/projectdiscovery/subfinder
4. sublist3r: GitHub - https://github.com/aboul3la/Sublist3r
5. chaos: GitHub - https://github.com/projectdiscovery/chaos-client
6. crt.sh: Website - we will fetch crt.sh results with curl 
7. findomain: GitHub - https://github.com/Edu4rdSHL/findomain
8. knockpy: GitHub - https://github.com/guelfoweb/knock
9. Crobat: go get github.com/cgboal/sonarsearch/cmd/crobat
10. figlet: GitHub - https://github.com/cmatsuoka/figlet
11. sudo apt update && sudo apt install jq
Install all the tools from here if you don't have any
```