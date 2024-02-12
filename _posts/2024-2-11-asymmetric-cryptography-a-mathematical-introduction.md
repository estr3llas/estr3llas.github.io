---
layout: post
title:  "Asymmetric cryptography: A mathematical introduction."
categories: [Cryptography,Math]
excerpt: Asymmetric cryptography, or Public-key cryptography, is the type of cryptography which, instead of symmetric cryptography, utilizes pairs of keys. Each pair is made up by a Public Key and a Private Key. As their names says, the Public Key can be exposed to anyone in the world, but the Private Key must be kept in secret, only you should know what is its values.
---

Asymmetric cryptography, or Public-key cryptography, is the type of cryptography which, instead of symmetric cryptography, utilizes pairs of keys. Each pair is made up by a Public Key and a Private Key. As their names says, the Public Key can be exposed to anyone in the world, but the Private Key must be kept in secret, only you should know what is its values.

> After this line, I'll be referring Public Key as PK and Private Key as SK (secret key).

In that cryptographic system, anyone with a PK can encrypt a message with their own PK, resulting in a ciphertext. That ciphertext can only be decrypted by the key pair of the PK which encrypted the data, or in other words, the correspondent SK.

This type of system is highly used in digital signature systems, where a message is encrypted using the person's SK, forming a 256-bit signature. So, to validate that a message X was sent by the person acclaiming it, we can use a type of "validation function", which takes X, the 256-bit signature and the PK, returning True or False. The key point here is that, given the number of possibilities of a 256-bit signature and the commutative property of key pairs in asymmetric encryption, we can be extremely confident that the only way of someone could have produced that signature from the given message, is if they know the SK paired with that PK.

> To provide you with a sense of the scale associated with 256-bits, there is this awesome video from 3Blue1Brown: <https://www.youtube.com/watch?v=S9JGmA5_unY>

The key space (number of possible keys in a particular cipher) of asymmetric cryptography is much lower than symmetric. Each user communicating with each other in a net will have a PK and a SK, hence they will use other uses PK to encrypt a message to that person. That fact leads us to a key space of 2n, where for 1000 users, there will be 2000 keys.

Asymmetric Cryptography is a fundamental concept in modern cryptosystems. There are plenty of protocols, algorithms and applications such as: TLS, IPsec, SSH, PGP, RSA, DSA, Diffie-Hellman and many others applies that system in their systems.

# Time for some math!

Such systems basically relies on the concept of one-way functions, or trapdoor functions if you prefer. A one-way function is a function which is easy to solve in one direction, but extremely hard to solve in the opposite direction. Meaning that if we have F(x), the result is trivial, but aware of the result and the function, it is nearly impossible to figure out what was the given input.

> The only known way of discovering that is through brute-forcing!

Asymmetric cryptography also relies on two mathematical problems: integer factorization and discrete logarithm.

We'll discuss how those problem are applied on algorithms as the article goes on. But for now, the reader must understand how the concept of how one-way functions are applied to those problems.

Integer factorization is the decomposition of a positive number into a product of integers. A integer factorization operation results in a composite number, which is the product of two or more integers greater than 1. On the other hand, a number that does satisfy those conditions is called a prime number.

Pick 12 and 7. 12 is a composite number because: 2 x 6 = 12, so 2 and 6 are factors of 12. 7 is a prime number, the only factors of 7 are 1 and itself.

The one-way function applied to that problem, as the reader could have figured out at this point, is that finding the product of two numbers is easy, but knowing only the product, finding what were the numbers that made up this number is hard. This problem gets even harder when you multiply two incredibly long numbers.

With Discrete Logarithm, consider the following equation:

- a^x = y (mod p)

When you know a and x, finding y is simple. But if you only know a and y, finding x is exceedingly difficult.

> We'll be covering what does "mod" means later on this article.

# The beauty of prime numbers

A prime number is a number which does not have any divisor other than 1 and itself. A coprime number, is a number that

> Note that the number 1 is not considered as a prime number. If it was, it'll go against the theorem of unique factorization, which states that a composite number only has one integer factorization. 

You can check out a list of prime numbers at: <https://en.wikipedia.org/wiki/List_of_prime_numbers>

Those numbers are essential to cryptographic systems. A common function used in cryptography is the multiplication of two large prime numbers. The product of that multiplication is called a semiprime. Applying the integer factorization problem, it is almost impossible to guess what are the two large prime numbers that resulted in an even larger semiprime number.

Also, cryptosystems typically use modular arithmetic, which if added with prime numbers, becomes the state of art of cryptography for some algorithms.

> As the reader may have noticed, the modulo operation is added to the problem of discrete logarithm as a form to make it a one-way function.

## Modular Arithmetic

As the reader might have seen across the world wide web, most of the explanations on this subject uses a clock as an example. I'll be doing a different approach.

Modular Arithmetic is the process of "fitting" a number inside another. Take the number 15 as a example.

15 = 3 mod 12, because the number 12 "fits" 1 time within 15, with the remainder of 3.
15 = 1 mod 7, because 7 "fits" 2 times within 15 without surpassing its value, with the remainder of 1.

Also, this operation can be read as: a = (km) + b, where a is 15, k is the quotient, m is the 12 and b is 3, so:

15 = 3 (mod 12) -> 15 = ( 1 * 12 ) + 3 -> 15

We can also use the modulo operation as way to find if a number A is a divisor of another number B. If B mod A is equal to 0, then A is a factor of B.

Is 3 a divisor of 108?

108 mod 3 = 0, hence 3 is indeed a divisor of 108.

But how do we test the primality of a number? I invoke Fermat and Euler!

## Fermat's little theorem

The Fermat's little theorem states that: When N is a prime number and A is coprime to N, the equation:

- a^n-1 = 1 (mod n)

Is true.

Therefore, we can test the primality of a number by a contraposition. The theorem says that the remainder of the above equation is 1 for a prime number, hence we can check for the numbers who are NOT primes.

If a^n-1 != 1 (mod n), then N is not a prime number.

The only problem with Fermat's little theorem is that it can determine pseudo-prime numbers, a number which passes several tests with another coprimes, but in reality it is not a prime number.

Take the example as n = 3.215.031.751.

- 2^3.215.031.751 = 1 (mod 3.215.031.750)
- 3^3.215.031.751 = 1 (mod 3.215.031.750)
- 5^3.215.031.751 = 1 (mod 3.215.031.750)
- 7^3.215.031.751 = 1 (mod 3.215.031.750)

But, performing a integer factorization on this number, retrieves us:

- 3.215.031.751 = 151 * 751 * 28351

Aware of that, there comes Euler.

## Euler's theorem

Euler stated that: For a natural number N and a coprime A, the following is true:

- a^Φ(n) = 1 (mod n)

Φ(n) (phi), also known as Euler's totient function, retrieves the count of numbers which are coprime to N. 

- Φ(7) = {1, 2, 3, 4, 5, 6}

For a prime number, Φ(n) will be n-1.

As the reader might have noticed, Φ(n) and n-1 are essentially the same thing. 

- a^Φ(n) = a^n-1 = 1

Meaning that Fermat's little theorem and Euler's theorem accord to each other.

Now the reader should have all the mathematical concepts required to understand Asymmetric Cryptograph.

# RSA

RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem, one of the oldest widely used for secure data transmission.

## Key Pair generation

First, select 2 large prime numbers P & Q.

Calculate N, which is the product of P and Q, or pq.

Given N, calculate T, which is Φ(N). T can be simplified as:

- Φ(N) = Φ(p*q) = Φ(p)Φ(q) = (p-1)(q-1)

> Remember that P and Q are prime numbers, so the number of coprimes to P and Q will always be P-1 and Q-1.

For security reasons, discard P & Q.

Now, select a arbitrary positive number E which satisfy all of the 3 rules:

- Must be a prime number.
- Must be less than T.
- Must NOT be a factor of T.

or:

- 1 < E < φ(N) && m^e >N!

This selected positive number will be our PK.

Thus, holding E and T, we calculate our  arbitrary SK:

- (SK*E) = 1 mod T

Done that, the key pair is ready.

## How it works

RSA encryption work as the following:

- C = m^e (mod n)

Where the remainder C of the plaintext m powered to the PK e, then divided by the product of 2 large prime numbers N, becomes the ciphertext

And the decryption:

- m = C^d (mod n)

Where d is the SK.

Let's put it into practice:

P = 7, Q = 19
N = 133
T = 108
E = 29
D = 41
M = 60

- C = m^e (mod n)
- C = (60^29) mod 133
- C = (3.6845653286788892983296e+51) mod 133
- C = 86

So, encrypting the message "60" with the PK "29", gives us 86 as the cyphertext. Now let's decrypt this thing

- m = C^d (mod n)
- m = (86^41) mod 133
- m = (2.0627020537113559472006651210124e+79) mod 133
- m = 60

> If the reader switches the PK and SK, it will eventually get to the same result.

And as simple as that, you understood the RSA algorithm and the math behind it!

But how secure is RSA? The security in RSA comes after the fact that factoring a large number which is the product of two very large number is impractical and takes A LOT of time. In other words, the security comes by the one-way function applied in integer factorization.

> Currently, RSA utilizes 2048 bits keys. Try factoring a 2048 bit number.

# Diffie-Hellman key exchange

Diffie-Hellman is a algorithm that allows two parties to establish a shared secret over a unsecured medium. It is mainly used for key exchange through the world wide web.

The shared secret is genera with the following:

First, the 2 parties agree in 2 commons number. A prime number P that is at least 2048 bits longer, and a generator G.

Then, a SK D is randomly generated.

Holding those 3 variables, the PK E is calculated, which consists of:

- G^D = E mod P

Where G is the generator, D the SK, P the prime number and the remainder becomes E the public key.

After that calculation, the two parties exchanges those PK's, becoming a shared key S for the party that received it.

Now the shared secret T can be generated. It consists of:

- S^D = T mod P

Finishing that, the shared secret is used to generate a symmetric key, and the parties can have a safe communication with each other over a unsecure channel.

The security in Diffie-Hellman lies in the discrete logarithm problem, where in logarithm, we have:

- G^X = N

Given G and X, finding N is easy. But, given G and N, finding X is difficult, but not impossible.

There it comes the discretization. The discretization in logarithm simply adds a modulo operation:

- G^X = P mod N

Given G, X and P, it is easy to find N. But with only G, P and N, finding X is almost impossible. The only known way is via brute-forcing.

And last but not least, this is how a 2048-bits number looks like ;)

```
27426180351059218005414589914595472398649565308052147378116950404161528907346987024990416351059898598158779889482304709038464625579146305769344674063612418754660584317496565340582798154775837615998686078567058075944211047685528279236801963272025995971257398765567472684003435629681600983399929363616631675519486743062041724484720006539899706837251753823675523802195154415522305797285386251878918144478181026014685653978603810416065454722834876437874372571999903624904412072955861437126282332809209525657386512249580115249561619834092929914787353519414525306431787713559744802439979924068924303352259117186167382529603525839784417205921
```

Haha, that is it for our introduction! Hope you enjoyed it. See you next time.

