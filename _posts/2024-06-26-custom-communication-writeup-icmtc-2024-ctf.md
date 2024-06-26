---
layout: post
title: Custom Communication writeup | ICMTC 2024 CTF
description: My solution to the Custom Communication challenge
date: 2024-06-26 23:40 +0300
categories: [Reverse,  CTFs, ICMTC]
---
This is a cryptography challenge and it's an easy one.

challenge.py
```py
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad

def encrypt(msg1,key,secret):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    secret = pad(secret,128)
    msg1 = pad(msg1,128)
    c0 = cipher.encrypt(secret)
    c1 = strxor(c0,msg1)
    return c1

FLAG = "EGCTF{FAKE_FLAAAAAAAAAAAAG}"

# shared data between Alice and Bob
secret = "[PRIVATE]"
key = "[PRIVATE]"

print(f"Alice: Hi Bob, what do you want to share today?")

print(f"Bob: Hi Alice, I believe we're being monitored. I'll encrypt my message before sending it to you.")

print(f"Alice: Sure, use our custom encryption method.")

msg = "[Bob's Secret Message]"
cipher = encrypt(msg,key,secret).hex()

print(f"Bob: Here we go. {cipher}")

FLAG_ENC = encrypt(FLAG,key,secret).hex()

print(f"Alice: thanks for your message, this gift for you ;) {FLAG_ENC}")

print(f"Bob: thanks for your gift, see you soon ISA")

print(f"Alice: Good Bye")
```

## Analysis
- We only receive c1 from encrypt.
- The same key and secret are used for both messages.

Since the last operation in the function is XOR between `c0` and the message, XORing the two plaintexts cancels out `c0`.This technique, called "crib dragging," is a known-plaintext attack.
[source](https://www.nku.edu/~christensen/Stream%20ciphers%20known%20plaintext%20attack%20on%20depth%20of%20two.pdf).
> "Crib dragging" involves sliding a known or suspected piece of plaintext (a "crib") across the ciphertext to uncover the original message.
{: .prompt-info }
> "The known-plaintext attack (KPA) is an attack model for cryptanalysis where the attacker has access to both the plaintext (called a crib) and its encrypted version (ciphertext)." - [Wikipedia](https://en.wikipedia.org/wiki/Known-plaintext_attack)
{: .prompt-tip }

This yields an XORed value of the two plaintexts. Given one plaintext, we can derive the other. The known part of the flag `EGCTF{` helps recover the first 6 characters of the message.
> If you XOR two things together, and then XOR the result against one of them, you get the other one.
{: .prompt-info }

Using [cribdrag](http://cribdrag.com/), we find:

| Plain           | first_key     | second_key  |
| :-------------- | :-------------| :---------- |
| The on          | dd40df00...   | cc6ff974... |
| Well d          | 7efed373...   | 6cdcfc4b... |
| Do one          | 74dcbef1...   | 75f4ddca... |
| You mu          | 91ceb361...   | 8de68515... |

Completing the last one to `You must` and verifying:

| Plain    |
| :------- |
| The only |
| Well don |
| Do one t |
| You must |

by that we get that part of the flag `EGCTF{a2`
the mostly likely to be correct is `Well done`

| Plain     |
| :-------- |
| The only  |
| Well done |
| Do one th |
| You must  |

The same with `do one thing`

| Plain          |
| :------------- |
| The only thin  |
| Well done is   |
| Do one thing   |
| You must be t  |

By Googling `Well done is`, we get the quote: "well done is better than well said."

Which will lead to the full flag: `EGCTF{a27d69*****************90}`
