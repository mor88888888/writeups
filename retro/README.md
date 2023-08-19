Retro
===
###### tags: `THM` `Hard`
###### Link: https://tryhackme.com/room/retro

# Recon

## Nmap
```bash
$ sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $ip
```
```
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
```

### OS
TTL --> WIN

### Detect services
```bash
$ nmap -sCV -p 80,3389 $ip
```
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2022-04-07T08:34:31+00:00
|_ssl-date: 2022-04-07T08:34:32+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2022-04-06T07:44:59
|_Not valid after:  2022-10-06T07:44:59
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Dirsearch | Gobuster
```bash
$ gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
```
/retro                (Status: 301) [Size: 149] [--> http://10.10.163.86/retro/]
```

Under `/retro`:

![7a1d6c90e489bb53a926ddc5851fe9ab.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/7a1d6c90e489bb53a926ddc5851fe9ab.png)

```
[04:42:14] 200 -   19KB - /retro/license.txt
[04:42:26] 200 -    7KB - /retro/readme.html
[04:42:38] 200 -   69B  - /retro/wp-content/plugins/akismet/akismet.php
[04:42:38] 200 -    0B  - /retro/wp-content/
[04:42:39] 301 -  161B  - /retro/wp-includes
[04:42:39] 200 -    1KB - /retro/wp-admin/install.php
[04:42:40] 200 -    0B  - /retro/wp-cron.php
[04:42:40] 200 -    0B  - /retro/wp-config.php
[04:42:40] 200 -    3KB - /retro/wp-login.php
[04:42:40] 302 -    0B  - /retro/wp-signup.php
```

# Explotation

## Web Autentication
https://wfuzz.readthedocs.io/en/latest/user/basicusage.html
```
wfuzz -c -z "file,/usr/share/wordlists/wfuzz/others/names.txt" --sc 200 --hs "There is no account with that username or email address" -d "user_login=FUZZ&redirect_to=&wp-submit=Get+New+Password" http://$ip/retro/wp-login.php?action=lostpassword -v
```

Meanwhile, let's take a look to the blog:

![e383f794b65132da59e47fc05f3315b7.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/e383f794b65132da59e47fc05f3315b7.png)

The writer of the post is "Wade". This user exists!

![261a40ea2b8e1b9ad43d5d78db74e887.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/261a40ea2b8e1b9ad43d5d78db74e887.png)

And it's inside our wordlist, but fuzz is too slow and we don't need anymore:

![2da390ee41c998bb0665a3cab59d8f73.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/2da390ee41c998bb0665a3cab59d8f73.png)

So we are going to guess the password of that user:
```
hydra -l wade -P /usr/share/wordlists/rockyou.txt -v $ip http-post-form '/retro/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=%2Fretro%2Fwp-admin%2F&testcookie=1:is incorrect'
```

It breaks at some point after many attempts. Let's do somre research on the blog looking for hints for his password:

![addbbcec6a39b434ba6a81ec171a5d1b.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/addbbcec6a39b434ba6a81ec171a5d1b.png)

Here is the clue we needed. Looking for info about this chracter:
https://readyplayerone.fandom.com/wiki/Wade_Watts

![b338a01dbf05484d73ac468eba094c98.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/b338a01dbf05484d73ac468eba094c98.png)

**wade:parzival**

And that's the password:

![389af819cb8faf26f4be18f705137559.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/389af819cb8faf26f4be18f705137559.png)

## Spawn a shell
Next thing to do is to inject a reverse shell in some page of the blog. For example:
http://10.10.216.229/retro/wp-content/themes/90s-retro/404.php

![e9b053cfd6628560129022dd180ea758.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/e9b053cfd6628560129022dd180ea758.png)

Edit the page with the revshells.com payload and access to it:

![a23cbbbbd8ef40f761467d61cf3d0fd5.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/a23cbbbbd8ef40f761467d61cf3d0fd5.png)

![89f877de1e7ba285b62e33aaeec01071.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/89f877de1e7ba285b62e33aaeec01071.png)

# Post-explotation

## User flag

We start the shell as iis apppool\retro.

Privileges:

![06f547a73f9878d633cf2e6967f8a67e.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/06f547a73f9878d633cf2e6967f8a67e.png)

Looking for more users in the machine, there is a user named Wade too:

![39f5af011465b271a98a5ef087456b4f.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/39f5af011465b271a98a5ef087456b4f.png)

And you can login with it trough RDP. Let's test the password we already know:

![75d5f56e230c85cc2cc1a907b1711632.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/75d5f56e230c85cc2cc1a907b1711632.png)

## Privilege escalation - root flag
I share a folder and I copy everything that seems interesting:

![ae12e7cda235c031c9987c62a7e4041e.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/ae12e7cda235c031c9987c62a7e4041e.png)

Paths:

Pictures:

![ae70c9f18a497b0bcc4e7281b4d109a9.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/ae70c9f18a497b0bcc4e7281b4d109a9.png)

Trash bin:

![450a996b3b5ffd4e8bfe095d7312873b.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/450a996b3b5ffd4e8bfe095d7312873b.png)

The hhupd.msi file is part of a exploit of the vuln [CVE-2019–1388](https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f)

I tried to exploit it but it doesn't work because there is no posibility to open the HTTP page:

![aceed49e8f0ecae8581174f065c95fe8.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/aceed49e8f0ecae8581174f065c95fe8.png)

A database from [TileDataLayer](https://4sysops.com/archives/roaming-profiles-and-start-tiles-tiledatalayer-in-the-windows-10-1703-creators-update/):

![bc0aa26a9e00ee5b7bf819bdce647355.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/bc0aa26a9e00ee5b7bf819bdce647355.png)

Google Chrome installed but no passwords found:

![171769f1c798c81257f778d8ec5f981c.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/171769f1c798c81257f778d8ec5f981c.png)

And no history:

![02f3dc3a0c4af15b88513052ca3c0b52.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/02f3dc3a0c4af15b88513052ca3c0b52.png)

Adobe flash player posibly installed:

![1eb7e7f27f38068547cd7bd717cddc60.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/1eb7e7f27f38068547cd7bd717cddc60.png)

Found this in the www dir:

![8582c6d41b2439342e6ed8b95eac31ca.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/8582c6d41b2439342e6ed8b95eac31ca.png)

Open the file and we have the user:pass to the DB:
```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress567');

/** MySQL database username */
define('DB_USER', 'wordpressuser567');

/** MySQL database password */
define('DB_PASSWORD', 'YSPgW[%C.mQE');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

Looking for more exploits for this buold of Windows with https://github.com/GDSSecurity/Windows-Exploit-Suggester I found it's vulnerable to CVE-2017-0213. So executing the [exploit](https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2017-0213/CVE-2017-0213_x86.zip) I obtained the root flag:

![7547acbabd1e47b2b50847ea062bddb8.png](https://raw.githubusercontent.com/mor88888888/writeups/main/retro/_resources/7547acbabd1e47b2b50847ea062bddb8.png)
