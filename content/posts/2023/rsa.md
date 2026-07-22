---
title: "RSA and Python"
summary: "Understanding, implementing and cracking RSA"
date: 2023-03-06
math: true
tags:
  - crypto
  - python
---

## Understanding RSA

{{<callout type="Info">}}
To keep this guide sweet and simple we restrain ourself to using small primes.

**(We also won't use padding schemes or other security measures)**

Should you use RSA in production always make sure to use numbers which are at least 512 Bit / 64 Byte long.
{{</callout>}}

RSA is an asymmetric cryptographic method consisting of a public key for encryption and a private key for decyption.

This means that the ascii value of a letter, for example, is converted into a cipher using the public key and converted back into plaintext using the private key.

RSA provides security if the public key and the private key are sufficiently long (min. 64bytes). This is the case because it is theoretically possible to calculate the private key from the public key with immense effort for small prime numbers.

### Private and Public key

#### Choose Numbers

The first step of key generation consists of choosing `p` and `q` such that:

$$
\begin{align}
p \not= q
\end{align}
$$

and that both numbers are prime.

Here, for example, we can choose `p` and `q` as follows:

$$
\begin{align}
p = 67 \\\
q = 97
\end{align}
$$

```python
p = 67
q = 97
```

#### Calculating the product of p and q

Now `n` has to be determined from the multiplication of the two previously selected numbers:

$$
\begin{align}
n &= p \cdot q \\\
  &= 67 \cdot 97 \\\
n &= \underline{6499}
\end{align}
$$

```python {hl_lines=[3,4]}
p = 67
q = 97
print(f"n={p*q}")
# n=6499
```

#### Calculating phi of n and e

After we have chosen `p` and `q` and calculated `n`, now follows the calculation of a number by calculating phi of `n`:

$$
\begin{align}
\phi(n) &= (p-1) \cdot (q-1) \\\
&= (67-1) \cdot (97-1) \\\
&= (66) \cdot (96) \\\
\phi(n) &= \underline{6336} \\\
\end{align}
$$

```python {hl_lines=[7, 9, 10]}
p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336
```

is relatively prime, i.e. the following applies:

$$
\begin{align}
\gcd(e, \phi(n)) &= 1 \\\
\gcd(e, 6336) &= 1 \\\
\gcd(\underline{47}, 6336) &= 1
\end{align}
$$

Our goal is to choose a small but not too small odd number for `e`, therefore we use 47 for `e`.

```python {hl_lines=[1, "14-15", "17-18"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47
```

#### Calculating the private key

Formula for calculating the private key:

$$
\begin{align}
e \cdot d \mod \phi(n) &= 1 \\\
47 \cdot d \mod 6336 &= 1 \\\
47 \cdot \underline{2831} \mod 6336 &= 1
\end{align}
$$

```python {hl_lines=["20-24", "26-27"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47

d = 0
for i in range(0, phi):
    if (i*e) % phi == 1:
        d = i
        break

print(f"d={d}")
# d=2831
```

Resulting keys:

$$
\begin{align}
\textrm{Public key: } (e,n) \rightarrow (47, 6499) \\\
\textrm{Private key: } (d,n) \rightarrow (2831, 6499) \\\
\end{align}
$$

### Encrypting

To encrypt a string, we first need to convert the characters in the string to their numeric representation:

Example string: `hello:)`

| Characters | h   | e   | l   | l   | o   | :   | )   |
| ---------- | --- | --- | --- | --- | --- | --- | --- |
| Numeric    | 104 | 101 | 108 | 108 | 111 | 58  | 41  |

```python {hl_lines=["28-33"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47

d = 0
for i in range(0, phi):
    if (i*e) % phi == 1:
        d = i
        break

print(f"d={d}")
# d=2831

example_string = "hello:)"
print(f"example_string={example_string}")
# example_string=hello:)
example_string_numeric = [ord(c) for c in example_string]
print(f"example_string_numeric={example_string_numeric}")
# example_string_numeric=[104, 101, 108, 108, 111, 58, 41]
```

We can now encrypt each characters numeric value by applying the following formula:

$$
\begin{align}
e(m) = m^e \mod n
\end{align}
$$

where `m` is the character to encrypt and `e` and `n` are pieces of the public key:

$$
\textrm{Public key: } (e,n) \rightarrow (47, 6499) \\\
$$

$$
\begin{align}
e(104)&=104^{47} \mod 6499=2508 \\\
e(101)&=101^{47} \mod 6499=6378 \\\
e(108)&=108^{47} \mod 6499=1799 \\\
e(108)&=108^{47} \mod 6499=1799 \\\
e(111)&=111^{47} \mod 6499=381 \\\
e(58)&=58^{47} \mod 6499=4564 \\\
e(41)&=41^{47} \mod 6499=3809 \\\
\end{align}
$$

```python {hl_lines=["36-38", "40-43"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47

d = 0
for i in range(0, phi):
    if (i*e) % phi == 1:
        d = i
        break

print(f"d={d}")
# d=2831

example_string = "hello:)"
print(f"example_string={example_string}")
# example_string=hello:)
example_string_numeric = [ord(c) for c in example_string]
print(f"example_string_numeric={example_string_numeric}")
# example_string_numeric=[104, 101, 108, 108, 111, 58, 41]

encrypted = []
for c in example_string_numeric:
    encrypted.append(c ** e % (p*q))

print(f"encrypted={encrypted}")
# encrypted=[2508, 6378, 1799, 1799, 381, 4564, 3809]
print(f"chiffre={' '.join([str(i) for i in encrypted])}")
# chiffre=2508 6378 1799 1799 381 4564 3809
```

| Characters | h    | e    | l    | l    | o    | :    | )    |
| ---------- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| Numeric    | 104  | 101  | 108  | 108  | 111  | 58   | 41   |
| Chiffre    | 2508 | 6378 | 1799 | 1799 | 381  | 4564 | 3809 |

### Decrypting

Decrypting a chiffre encrypted with RSA is simply applying the private key to the given integer and afterwards converting the result to its character representation.

Formula for decrypting:

$$
\begin{align}
d(c) = c^d \mod n
\end{align}
$$

where `c` is the character to decrypt and `d` and `n` are pieces of the private key:

$$
\textrm{Private key: } (d,n) \rightarrow (2831, 6499) \\\
$$

$$
\begin{align}
d(2508)&=2508^{2831} \mod 6499=104 \\\
d(6378)&=6378^{2831} \mod 6499=101 \\\
d(1799)&=1799^{2831} \mod 6499=108 \\\
d(1799)&=1799^{2831} \mod 6499=108 \\\
d(381)&=381^{2831} \mod 6499=111 \\\
d(4564)&=4564^{2831} \mod 6499=58  \\\
d(3809)&=3809^{2831} \mod 6499=41  \\\
\end{align}
$$

```python {hl_lines=["45-47", "49-52"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47

d = 0
for i in range(0, phi):
    if (i*e) % phi == 1:
        d = i
        break

print(f"d={d}")
# d=2831

example_string = "hello:)"
print(f"example_string={example_string}")
# example_string=hello:)
example_string_numeric = [ord(c) for c in example_string]
print(f"example_string_numeric={example_string_numeric}")
# example_string_numeric=[104, 101, 108, 108, 111, 58, 41]

encrypted = []
for c in example_string_numeric:
    encrypted.append(c ** e % (p*q))

print(f"encrypted={encrypted}")
# encrypted=[2508, 6378, 1799, 1799, 381, 4564, 3809]
print(f"chiffre={' '.join([str(i) for i in encrypted])}")
# chiffre=2508 6378 1799 1799 381 4564 3809

decrypted = []
for c in encrypted:
    decrypted.append(c ** d % (p*q))

print(f"decrypted={decrypted}")
# decrypted=[104, 101, 108, 108, 111, 58, 41]
print(f"result={''.join([chr(i) for i in decrypted])}")
# result=hello:)
```

| Numeric    | 104 | 101 | 108 | 108 | 111 | 58  | 41  |
| ---------- | --- | --- | --- | --- | --- | --- | --- |
| Characters | h   | e   | l   | l   | o   | :   | )   |

## Cracking RSA

As mentioned at the beginning, RSA can be cracked in several ways:

- [Attacks against plain RSA](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA>)
- [RSA security](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Security_and_practical_considerations>)
- "If n is 300 bits or shorter, it can be factored in a few hours in a personal computer, using software already freely available"
- "In 1994, Peter Shor showed that a quantum computer – if one could ever be practically created for the purpose – would be able to factor in polynomial time, breaking RSA; see Shor's algorithm."

In the following chapter we will crack our private key we generated before using [prime factorization](https://en.wikipedia.org/wiki/Integer_factorization#Prime_decomposition) to split our `n` into `p` and `q`.

### Factorizing

The factorizing integers defines the process of calculating the factors which multiplied together result in the integer we factorize.

This is extremely useful to work our way back from the public key to the private key.

$$
\textrm{Public key: } (e,n) \rightarrow (47, 6499) \\\
$$

$$e = 47 \\\ n = 6499$$

$$
\begin{align}
n = p \cdot q
\end{align}
$$

Using the following script, we can perform the integer factorization and calculate `p` and `q`:

```python {hl_lines=["54-66"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47

d = 0
for i in range(0, phi):
    if (i*e) % phi == 1:
        d = i
        break

print(f"d={d}")
# d=2831

example_string = "hello:)"
print(f"example_string={example_string}")
# example_string=hello:)
example_string_numeric = [ord(c) for c in example_string]
print(f"example_string_numeric={example_string_numeric}")
# example_string_numeric=[104, 101, 108, 108, 111, 58, 41]

encrypted = []
for c in example_string_numeric:
    encrypted.append(c ** e % (p*q))

print(f"encrypted={encrypted}")
# encrypted=[2508, 6378, 1799, 1799, 381, 4564, 3809]
print(f"chiffre={' '.join([str(i) for i in encrypted])}")
# chiffre=2508 6378 1799 1799 381 4564 3809

decrypted = []
for c in encrypted:
    decrypted.append(c ** d % (p*q))

print(f"decrypted={decrypted}")
# decrypted=[104, 101, 108, 108, 111, 58, 41]
print(f"result={''.join([chr(i) for i in decrypted])}")
# result=hello:)

def prime_factors(n):
    factors = []
    d = 2
    while n > 1:
        while n % d == 0:
            factors.append(d)
            n //= d
        d = d + 1
    return factors

factors = prime_factors(p*q)
print(f"factors={factors}")
# factors=[67, 97]
```

$$
\begin{align}
6499 &= p \cdot q \\\
&= \underline{67 \cdot 97}
\end{align}
$$

Now we calculate phi of n:

$$
\begin{align}
\phi(n) &= (p-1) \cdot (q-1) \\\
&= (67-1) \cdot (97-1) \\\
&= 66 \cdot 96 \\\
\phi(n) &= \underline{6336}
\end{align}
$$

This can be used to calculate `d`:

$$
\begin{align}
e \cdot d \mod \phi(n) &= 1 \\\
47 \cdot d \mod 6336 &= 1
\end{align}
$$

To calculate this `d`, we simply use a for loop:

```python {hl_lines=["67-72"]}
from math import gcd

p = 67
q = 97

print(f"n={p*q}")
# n=6499

phi = (p-1)*(q-1)

print(f"phi={phi}")
# phi=6336

e = 47
assert gcd(e, phi) == 1

print(f"e={e}")
# e=47

d = 0
for i in range(0, phi):
    if (i*e) % phi == 1:
        d = i
        break

print(f"d={d}")
# d=2831

example_string = "hello:)"
print(f"example_string={example_string}")
# example_string=hello:)
example_string_numeric = [ord(c) for c in example_string]
print(f"example_string_numeric={example_string_numeric}")
# example_string_numeric=[104, 101, 108, 108, 111, 58, 41]

encrypted = []
for c in example_string_numeric:
    encrypted.append(c ** e % (p*q))

print(f"encrypted={encrypted}")
# encrypted=[2508, 6378, 1799, 1799, 381, 4564, 3809]
print(f"chiffre={' '.join([str(i) for i in encrypted])}")
# chiffre=2508 6378 1799 1799 381 4564 3809

decrypted = []
for c in encrypted:
    decrypted.append(c ** d % (p*q))

print(f"decrypted={decrypted}")
# decrypted=[104, 101, 108, 108, 111, 58, 41]
print(f"result={''.join([chr(i) for i in decrypted])}")
# result=hello:)

def prime_factors(n):
    factors = []
    d = 2
    while n > 1:
        while n % d == 0:
            factors.append(d)
            n //= d
        d = d + 1
    return factors

factors = prime_factors(p*q)
print(f"factors={factors}")
# factors=[67, 97]
new_phi = (factors[0]-1)*(factors[1]-1)
for i in range(0, new_phi):
    if (e * i) % new_phi == 1:
        print(f"d={i}")
        break
# d=2831
```

$$
\begin{align}
47 \cdot \underline{2831} \mod 6336 = 1 \\\
\end{align}
$$

$$
\begin{align}
\textrm{Private key} = (d,n) \rightarrow (2831, 6499)
\end{align}
$$

`d` and `n` are now given, therefore we cracked the private key and are now able to [decrypt](#decrypting) the chiffre.
