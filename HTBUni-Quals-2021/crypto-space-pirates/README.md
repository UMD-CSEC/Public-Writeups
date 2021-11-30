# (crypto) Space Pirates

## Proof of Concept

The challenge is building some kind of curve with coefficients (**x** and **y**)
based on the flag.The challenge gives us coordinates on this curve as well as the
second coefficient, which is derived from the first. There are 10 total terms to
this polynomial and we can derive 8 more of these coefficients from the having
the second coefficient.

The equation turns out to be:
`a*x^9 + b*x^8 + c*x^7 + d*x^6 + e*x^5 + f*x^4 + g*x^3 + h*x^2 + coeff[1]*x + secret % p = y`

With the given coefficient, we can derive **a**, **b**, **c**, **d**, **e**,
**f**, **g**, and **h**. We also know what **p**, **y** and **x**, we can find
**secret**! Let's call the whole known part of the right side of the equation
into a variable called `known_stuff` (revolutionary, right?). Now we have the equation:
`y = known_stuff + secret % p`

Using the modular arithmetic properties, we can reduce this formula to:

```
y - known_stuff % p = secret % p
secret = y - known_stuff % p
```

This allows us to properly compute **secret**, allowing us to decrypt the
ciphertext given in **msg**. This should contain the flag :)

## Vulnerability Explanation

The "vulnerability" here is that we were given the second coefficient and a point
on the curve, which let us derive an equation to solve for the first coefficient,
being the key to AES decrypt the ciphertext, which gives us the flag.

## Solvers/Scripts Used

I created **space-pirates-solve.py** to solve this challenge. This needs to be
ran with Python3.9 or above because anything Python3.8 and below does not support
the `random.randbytes()` functionality.


```sh
$ python3.9 solve.py
coeffs = [93526756371754197321930622219489764824, 240113147373490959044275841696533066373, 277069233924763976763702126953224703576, 251923626603331727108061512131337433905, 303281427114437576729827368985540159120, 289448658221112884763612901705137265192, 175064288864358835607895152573142106157, 28168790495986486687119360052973747333, 320025932402566911430256919284757559396]

y = secret + 93526756371754197321930622219489764824*x^1 + 240113147373490959044275841696533066373*x^2 + 277069233924763976763702126953224703576*x^3 + 251923626603331727108061512131337433905*x^4 + 303281427114437576729827368985540159120*x^5 + 289448658221112884763612901705137265192*x^6 + 175064288864358835607895152573142106157*x^7 + 28168790495986486687119360052973747333*x^8 + 320025932402566911430256919284757559396*x^9

secret = 39612257993477957104
flag should be: b'The treasure is located at galaxy VS-708.\nOur team needs 3 light years to reach it.\nOur solar cruise has its steam canons ready to fire in case we encounter enemies.\nNext time you will hear from us brother, everyone is going to be rich!\nHTB{1_d1dnt_kn0w_0n3_sh4r3_w45_3n0u9h!1337}\x08\x08\x08\x08\x08\x08\x08\x08'
```
