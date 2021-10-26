# Port scanning
## Theory

To find open ports that could be of use to an attacker during an attack. 
Different OS have different vulnerabilities depending available ports.
Practice

To detect the OS type.
One PowerShell script that quietly run a single connection test against one or multiple FQDN or IP is as follows

```PowerShell

# $NAMES =  Get-Content "$ENV:USERPROFILE\desktop\servers.txt"
# $NAMES =  "192.168.0.200"
$NAMES = 78.137.156.45
$names = "www.rte.ie"
$REPORT = @()

foreach ($NAME in $NAMES){
$T2L = Test-Connection $NAME -Count 1 -ErrorAction SilentlyContinue | select -exp ResponseTimeToLive
$HTTL= Switch($T2L)
{
 {$_ -le 60} {"AIX"; break}
 {$_ -le 64} {"Linux"; break}
 {$_ -le 128} {"Windows"; break}
 {$_ -le 255} {"UNIX"; break}
} 
$REPORT += New-Object psobject -Property @{OS=$HTTL;TTL=$T2L;SERVER=$NAME}
} 
$REPORT | Export-CSV c:\temp\\TTL_RESULTS.csv -NoTypeInformation -Append
$report 

```
Reference from Chris Duck @gpduck 
*This text will be italic*
_This will also be italic_

**This text will be bold**
__This will also be bold__
_You **can** combine them_

# NMAP Scans
Scan using TCP port is very reliable, the -P0 will stop Nmap using ping and give us away.
```
nmap -sT -P0 192.168.1.115
```
This will be a full TCP connection and therefore may be logged, so…
We use a SYN connect scan to see if the port is open, but as we do not complete the three way handshake, nothing is logged.

nmap -sS -P0 192.168.1.115

Use NMAP for a port scan and use a slower speed to avoid IDS and NPS systems

nmap -sS -P0 -T sneaky 192.168.1.115

Other speeds available

paranoid 0, sneaky 1, polite 2, normal 3, aggressive 4, insane 5

Here, the scan will slowly test hopefully getting past the network intrusion detection system and the firewall without being detected. Patience is key, with some scans, like the sneaky scan, taking up to five hours per IP address, while the default scan will take less than a second.
Other scans, but a more noisy

nmap -sU -P0 10.0.2.15

UDP scan

nmap -sN -P0 10.0.2.15

TCP Null scan

nmap -sX -P0 10.0.2.15

All ports scan.
Resources

Nmap download - https://nmap.org/download.html

