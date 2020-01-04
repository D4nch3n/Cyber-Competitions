
# HackTheBox Craft Writeup
This has been one of my favorite boxes, due to it having a light bit of everything that's presented in a not-too-difficult manner. There's a tiny bit of reversing, web exploitation, custom scripting, enumeration, networking, and much more!
It's a medium difficulty box that emulates realistic scenarios, and without further ado, here's how we go to get root on this box!

Note: This writeup is made post exploitation. A good portion of the enumeration/trial-error process is skipped. If you think I should include anything else, feel free to message me at [@D4nch3n](https://twitter.com/D4nch3n)


## Info card:

![](https://i.imgur.com/ZVWorIC.png)

## Summary:
Enumerating the HTTPS server gives us access to a custom API and its gogs repository. We enumerate the repo to find credentials, and use the login on the API to exploit a vulnerable python function to get onto the API's docker container. Enumeration on the container tells us that we can connect to another container that's serving mysql, and we can write a script to get more credentials from the mysql container. Logging back into gogs with the new credentials gives us a SSH key, which we can use with a reused passphrase to get user access on the host. Finally, we use a given root vault token to ssh onto the host as the root user.
## Recon:
Running Nmap on the IP address 10.10.10.110 gives us the following:

```
Nmap scan report for 10.10.10.110
Host is up (0.016s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp open  ssl/http nginx 1.15.8
|_http-server-header: nginx/1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 14 16:40:59 2019 -- 1 IP address (1 host up) scanned in 15.45 seconds
```

Looks like a relatively typical web server, with a web server running HTTPS.

Visiting the webpage gives us some more information

![](https://i.imgur.com/iwcEyK7.png)

Ok, so it looks like the server's hosting a custom craft API! Mousing over API shows that the link leads to https://api.craft.htb/api, and mousing over the weird symbol to the right of "API" leads go https://gogs.craft.htb. However, trying to access them doesn't work, as our connection times out:

![](https://i.imgur.com/FePeq3l.png)

Maybe it's because our machine cannot resolve these hostnames to 10.10.10.110. We can change that by modifying our /etc/hosts file on kali linux as follows:

```
127.0.0.1       localhost
10.10.10.110   api.craft.htb   gogs.craft.htb
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Now, when we visit api.craft.htb, we get a page:

![](https://i.imgur.com/JbyVcco.png)

Woah, this API looks like it has a lot of functionality! We can either do authentication operations or brewing operations. However, trying to do anything in brew results in the following:

![](https://i.imgur.com/Y4yU4hF.png)

Ok, so maybe we have to login first. Trying to login gives us a HTTP-basic auth:

![](https://i.imgur.com/ku3usZp.png)

We don't have any credentials yet. We can try to brute force, however we'll save that as the last resort (Over-the-net brute forcing is very rare in hackthebox)

Finally, we have a link to https://api.craft.htb/api/swagger.json. However, visiting it just gives us documentation on each craft feature, so it isn't really useful:

![](https://i.imgur.com/Fh7Lhuh.png)

## Getting dinesh's credentials

Let's explore https://gogs.craft.htb next! Going to it gives us this page:

![](https://i.imgur.com/BR7YEEF.png)

It looks like the server's hosting a version control service as well as the API. This is interesting as we might be able to view the source code of the craft API if it is in the repository.

We do have links on the top. Let's see what's in explore:

![](https://i.imgur.com/kSsh4Mn.png)

Nice, so we do have access to the source code of the craft API! Let's take a look at it:

![](https://i.imgur.com/r0IBDyF.png)

Wow, that's quite a few files to go through. However, remember that we need to get a username and password first.

We notice that there's 6 commits in this repository. Let's take a look at them: 

![](https://i.imgur.com/2QSEvqb.png)

Let's go through them and see what we can find! Going through the 5th commit (SHA1 = a2d28ed155) we find something very interesting:

![](https://i.imgur.com/ot2cOrF.png)

We can see that dinesh tried to delete his committed credentials from the repository. (This is why you should not ever push credentials onto a repo!) This means that we have some valid credentials to test with! Let's go back to https://api.craft.htb/api to login using `dinesh: 4aUh0A8PbVJxgd`:

![](https://i.imgur.com/p5G1hwq.png)

Yay we got a login token! Let's try to verify it by using "check":

![](https://i.imgur.com/ktXD7WZ.png)

Hmm, I thought we got our token already? Let's go back to the repository to see how we can use it.

Let's take a look at this snippet of code from auth.py:

![](https://i.imgur.com/S5gTCsR.png)

Oh, so we need to supply our token in the X-Craft-Api-Token. However, we cannot modify http headers through the web API interface. Therefore, we will have to use curl's -H option to add the X-Craft-Api-Token header. Trying that with the given token shows that our token is valid:

![](https://i.imgur.com/2EcZiLd.png)

(Our token expired unfortunately, so we had to regenerate a new one by relogging in)

Nice, we know that our token works! Now we can make some brews!

## Gaining code execution

Let's do some more enumeration on the repository. Besides the 6 commits, we also see one issue:

![](https://i.imgur.com/bzpFo3w.png)

Wow, one of the commit messages literally says "Add fix for bogus ABV values" Let's take a closer look at what this issue is all about:

![](https://i.imgur.com/duyyVGW.png)

Hmm, so the brew API used to not check if the ABV value is a proper value, so Dinesh created an issue regarding it. Dinesh eventually pushed out a patch for it, which was criticized by Gilfoyle for being a bad patch. Let's see what the patch is by viewing the referenced commit c414b16057:

![](https://i.imgur.com/C2LF5RH.png)

Hmm, so the patch checks if the value from the 'abv' json parameter is greater than 1, and if so return a 400 response. Looking at the rest of the commits doesn't indicate that this portion of code was ever changed, meaning that this check is a part of the current version of the brew API.

However, do you see what I see?!? Dinesh tried to use `eval()` to evaluate the abv, and the abv value we control is interpreted as a string. Therefore, we don't have to supply a number as the abv value, and since `eval()` executes the argument as python code, we can enter valid python code and have `eval()` execute it!

Let's first try to see if we can ping back to us. Looking at ifconfig tells us that our IP address is 10.10.15.206:
```
root@kali:~/hackthebox/craft# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fec9:3c87  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:c9:3c:87  txqueuelen 1000  (Ethernet)
        RX packets 44297  bytes 44565353 (42.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 17003  bytes 1759239 (1.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 30  bytes 1590 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 30  bytes 1590 (1.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.206  netmask 255.255.254.0  destination 10.10.15.206
        inet6 fe80::bc7f:da81:1b18:2f31  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::11cc  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 100  (UNSPEC)
        RX packets 1119  bytes 968128 (945.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1007  bytes 95740 (93.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

Let's set up a tcpdump listener to see if we get our pings at the tun0 interface:

![](https://i.imgur.com/mjpbWl4.png)

Finally, let's begin by using the builtin `__import__()` to import os, and then use `os.system()` to execute our shell command. We only want ping to ping us 2 times, so our abv value looks like this: `__import__('os').system('ping -c 2 10.10.15.206')`

Our final curl command looks like this:

![](https://i.imgur.com/2pwK7FS.png)

We get an exception. However, looking at tcpdump we do get two ping requests back:

![](https://i.imgur.com/8PAq2lS.png)

Sweet! Now let's try to execute /bin/sh and use netcat to get our reverse shell! We will be using the nc reverse shell from [pentest-monkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). Let's first setup a netcat listener at port 9001:

![](https://i.imgur.com/6BxVTEm.png)

Next let's execute another curl command to execute the second netcat reverse shell from pentestmonkey:

![](https://i.imgur.com/SYLpMfx.png)

Our command hangs, which is a good sign. When we go back to the netcat listener, we discover that we do have a shell!

![](https://i.imgur.com/G1SxUn2.png)

# Escaping from docker

Woah, we have root access? This is too easy. However, /root/root.txt does not exist!

Looking at the root directory tells us why this is the case:

![](https://i.imgur.com/bduQcn0.png)

The presence of a .dockerenv file tells us that we are just in a docker container. We're going to need to figure out a way to break free.

Looking at the /opt/app directory, we see a set of files that's suspiciously similar to those in the gogs repository. However, going to /opt/app/craft_api, we see an extra file called settings.py: 

![](https://i.imgur.com/082wEyD.png)

```python=
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
```

Yay, more credentials! However, it looks like the MYSQL database is at a different container with a hostname of 'db'. Let's ping 'db' and run ifconfig and see what happens:

![](https://i.imgur.com/SNVN20I.png)

Hmm, so we are 172.20.0.6, and mysql is running on 172.20.0.4. How do we connect to it?

Recall that there are some python scripts that connect to the database server. One such script is in /opt/app/dbtest.py:

```python=
#!/usr/bin/env python

import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `id`, `brewer`, `name`, `abv` FROM `brew` LIMIT 1"
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

finally:
    connection.close()
```

Running the script does indicate that it can successfully connect to the database:

![](https://i.imgur.com/TyVBEZK.png)

However, since we're root, we can copy this script and create one that can execute any query I want! Or, even better, we can replace `sql = "SELECT id, brewer, name, abv FROM brew LIMIT 1"` with `sql = argv[1]` so that it executes and returns the result from any query I make as an command-line arguement to the script. We're also going to want to replace `result = cursor.fetchone()` with `result = cursor.fetchall()` so we can view more than one entry that is returned.

Let's try it out after our changes! (The modified script is in query.py)

![](https://i.imgur.com/KZYY1Kf.png)

Nice! We can execute any query we want inside it now!

The above query shows what databases are in the database container. It returned two results, which is craft and information_schema.

I wonder if it's possible to read files by using LOAD_FILE(). Unfortunately, it doesn't look like we have the permissions, as we get no results:

![](https://i.imgur.com/qRC72lX.png)

Let's poke more at the craft database! We'll figure out what tables are in craft by executing "SHOW TABLES":


![](https://i.imgur.com/fN4CcUH.png)

The user table looks very interesting! Let's execute "SELECT * FROM user" to see what's inside:

![](https://i.imgur.com/r98BBdF.png)

Wow, so many more creds! Where can we use them?

## Getting User

Let's see if one of these work for SSH. However, when we tried them, we get an interesting response back:

![](https://i.imgur.com/QFWcN7w.png)

Hmm, so we can only use publickey or keybord-interactive authentication (MFA) with this SSH service.

We can try to login onto the craft API, but if we somehow manage code execution there, we'll just end back onto the first container. However, we can try logging into gogs!

Dinesh's creds do work for gogs, but his profile is relatively empty, as his only repository is the craft-api:

![](https://i.imgur.com/3t1axNs.png)

Ebachman's credentials doesn't work with gogs. However, Gilfoyle's credentials do, and we see some more activity:

![](https://i.imgur.com/gtXrNoU.png)

Gilfoyle has a craft-infra repository! Let's look at it to see what it contains:

![](https://i.imgur.com/NYxT2uu.png)

Looks like these are the files used to set up the docker containers. However, the .ssh directory looks interesting:

![](https://i.imgur.com/3mEsapd.png)

Woah, SSH keys! We can assume that these keys belong to the gilfoyle user. Let's see what happens when we try logging onto the host with gilfoyle's id_rsa private key!

![](https://i.imgur.com/d8diNju.png)

Hmm, looks like there's a passphrase. What if we tried gilfoyle's gogs password as the passphrase?

![](https://i.imgur.com/Fy4qQOJ.png)

Nice, it works, and we get user.txt!

## Privesc to root

Looking around in gilfoyle's home directory, we see a hidden file called `.vault-token`. Let's take a look at what's inside:

![](https://i.imgur.com/ypTRrrz.png)

Looks like some sort of token. The name of the file suggests that vault is installed, and we do get a help prompt when we run vault:

![](https://i.imgur.com/VBnp8KB.png)

A google search reveals that vault from HashiCorp is installed (https://www.vaultproject.io/docs/). Let's look at what permissions this token has:

![](https://i.imgur.com/sWWCqQy.png)

Oh wow, we have a root-level token access here! This is dangerous because we can basically do anything in vault!

Let's look at what secrets are available:

![](https://i.imgur.com/90T04z4.png)

Nice, the ssh secrets engine is enabled. With this we should be able to find a way to ssh in as root!

First, we'll need to see what roles exist for the root user. Unfortunately, we don't have good ways of enumerating vault paths with the vault client. However, after playing around with the vault client, we get an interesting error message when we use unwrap:

![](https://i.imgur.com/2JpIcXX.png)

Interesting, so there's a vault HTTPS server at vault.craft.htb! Let's ping it to see what IP it is:

![](https://i.imgur.com/GGUx7qx.png)

Oh, so it's another one of these containers.

Looking further into the documentation, we find the documentation for the HTTP SSH secrets API here: (https://www.vaultproject.io/api/secret/ssh/index.html)

Let's first see what roles are available. We can do so by making a LIST request to /ssh/roles with our vault token via a curl command from the above link:

![](https://i.imgur.com/GvXw9Hz.png)

![](https://i.imgur.com/onXnjd4.png)

Nice! We're given a root_otp role, which is an OTP key. According to the documentation, we can use this type of role to generate a single use key to SSH!

Let's get some more info by making a GET request to /ssh/roles/root_otp with our vault token (output shown below):

![](https://i.imgur.com/WEbBMzl.png)

According to the documentation, this role allows us to SSH as the root user to any address in the cidr 0.0.0.0/0, which translates to any ip address between 0.0.0.0 to 255.255.255.255!

Since we're using a OTP role, we'll look at this documentation to figure out how to generate our one time key:

https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html

Let's generate a valid credential for 10.10.10.110! To do that we will use `vault write` as follows:

![](https://i.imgur.com/7q8FObe.png)

The highlighted key will be our one time use key to get root! Finally, we'll just need to ssh as root to 10.10.10.110 to get root.txt!

![](https://i.imgur.com/xGBTost.png)

Thank you [@rotarydrone](https://twitter.com/rotarydrone) and HackTheBox for this nice little server! Privesc to root could be made slightly harder, but other than that this box was a lot of fun!
