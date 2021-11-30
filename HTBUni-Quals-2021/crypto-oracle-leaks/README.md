# (crypto) Oracle Leaks

### Proof of Concept

To solve this challenge, one would need to know how to implement Manger's attack.
Manger's attack requires an oracle to tell us if the plaintext is less than **B**
or not such that:

```
B = 2^(8*(k-1))
k = ceiling(log256(n)) <--- byte length of n
```

In the case of this challenge, we are given the byte length of the plaintext, which
is decrypted by the ciphertext we pass to the oracle. It just so turns out that
anything greater than or equal to **B** is 128 bytes long and anything less than
**B** is 127 bytes or less. We can use this knowledge for Manger's attack.

Manger's attack allows us to narrow down the possible range of messages to a
**single message** in O(log(n)) time (queries).

We will be using the malleability property of RSA:
```
c = ciphertext sent to us (using option 2 of oracle)
n, e = public key sent to us (using option 1 of oracle)
d = private key known to oracle
x = constant we choose
pt = decrypted value

(x^e)*c = (x^e)(m^e % n) = (x*m)^e % n
```

To start the attack, we will send values of **x** like `2^1`, `2^2`, ..., `2^i`
until we reach find a value for **i** such that the length value returned from
sending `c * (2^i)^e >= B`. Finding this value ensures that `B <= c * (2^i)^e <= 2B`.
From this, we know that `B/2 <= c * (2^(i-1))^e <= B`

For the next part of the attack, we will be sending values of **j** until the
length of the plaintext decrypted from sending `c * ((2^(i-1)) * (j + (n+B)/B))^e`
is greater than B. This tells us that the modulo reduction wrapped what we sent
around **n** into something smaller than **B**. This then implies that
`n <= m* ((2^(i-1)) * (j + (n+B)/B))^e <= n + B`.

For the third part of Manger's attack, we will be narrowing down the range of messages
until we get down to our one message (aka. the flag). We will be setting **min**
and **max** values and narrowing them down until we find the one value we are looking
for in the `min - max` range. We will send a value spanning a single boundary point
and determine whether to narrow down **min** or **max** depending on the comparison
of the result length and **B**.

[Kudelski Manger's Attack Research](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/)


### Vulnerability Explanation

The vulnerability is that there is an oracle which gives us information when we
send a ciphertext to be decrypted. In this case, it tells us what the length of
the plaintext is after decryption, but this can be exploited using Manger's attack.

### Solvers/Scripts Used

To solve this challenge, I created a script called

```sh

$ python3 oracle-solve.py 167.172.51.181:30163
[+] Opening connection to 167.172.51.181 on port 30163: Done
(n,e): ('d5b6b30aa872e4502af2190625c1dd57411cb59137337bc0801b2904f41b3dbfea01d56e951c14d3e14eca742a1f98cc17a9ebbc26df0ed95f81a65f311a6fbdf8525bbf8f885f1d62f092cce84e97f29ce8f37f6c6930320fec2c028f3c2f7c5eb56fe37e04d15ab920bbf69f703ea1644d14bb4b2ae6efe8ee2ce8aa929ac5', '10001')

n = 150074842348357516891736465379306136112508180675987540875033637786712130055839823231064819894691642975930015417355307683696544567509729899626321069026220948861834936975917770257425390144350978339971661134805256249131969659881519640268899249303068838839678125288181481875765308039044272737154216157618157820613
e = 65537
Encrypted text: 3668e03a2ed2e58331986d07f64c690ab7552172bdc320107669c77bc7e194ca170b218d8c76fdf51aee54a3357045d4257561c227845069ec662b014c2edb2764c9e0088f8ac21ec0081f8b599abbfcfd564cc9542eef72cdbf81bdf7fe487bb5c81f943d4b3bbd12a180c8cc55aa35ec50ba2b048daa770209c94e0ba386b3

ct = 38207770629651691397219491887564612284114952453750891231034794450910841096572303605677110383756095300333768042470748869482030227255867463925102367561120256913380484237508616323653578970150537300900767574280846682917677049414712155068547576402056851431702226238524303938543152595752066640708921500999260276403
i = 7 ---- length = 128
---------------- i found ----------------
j = 0 ---- length = 128
j = 1 ---- length = 128
j = 2 ---- length = 128

...

j = 77 ---- length = 128
j = 78 ---- length = 128
j = 79 ---- length = 128
j = 80 ---- length = 128
j = 81 ---- length = 127
---------------- j found ----------------
mmax - mmin = 37194061483347041920379228821608198441182322955473437763471199921736931401760494557052038640924493516022269324324556689796326670255895917987960025208445222370267787801423771284987052188419891692484830788219388441976908162229885891459611922036552245506850526078478031117573831008855211430919656285095053 ---- length = 127
mmax - mmin = 18597030741673520960189614410804099220591161477736718881735599960868465700880247278526019320462246758011134662162278344898163335127947958993980012604222611185133893900711885642493526094209945846242415394109694220988454081114942945729805961018276122753425263039239015558786915504427605715459828142547526 ---- length = 127

...

mmax - mmin = 120121 ---- length = 128
mmax - mmin = 60659 ---- length = 128
mmax - mmin = 30409 ---- length = 127
mmax - mmin = 15033 ---- length = 127
mmax - mmin = 7480 ---- length = 127
mmax - mmin = 3709 ---- length = 128
mmax - mmin = 1867 ---- length = 128
mmax - mmin = 941 ---- length = 127
mmax - mmin = 465 ---- length = 127
mmax - mmin = 231 ---- length = 128
mmax - mmin = 116 ---- length = 128
mmax - mmin = 58 ---- length = 127
mmax - mmin = 28 ---- length = 128
mmax - mmin = 14 ---- length = 127
mmax - mmin = 6 ---- length = 128
mmax - mmin = 3 ---- length = 128
mmin = b'\x02\xe6\xa0va%B&\xadn\x9d\x9f\x9c\x0cg\x0e\x1a\xf3R\x07\xf5b\xacV\x1cT?\xe8\x81\xf3\xd3\x19O\xc0\xef\x14\xb9\x11\xa1\xd7\x17\xe1J&r\x1a1!\xb1>\r\xdbtmS6\xa2\xee\xe5\x1c\x99T\xfe\x08\x80.i\xa3\x07\x9a \xe0*B9\xb0\n?\x8ciT\x81\xb4\x00HTB{m4ng3r5_4tt4ck_15_c001_4nd_und3rv4lu3d}'
mmax = b'\x02\xe6\xa0va%B&\xadn\x9d\x9f\x9c\x0cg\x0e\x1a\xf3R\x07\xf5b\xacV\x1cT?\xe8\x81\xf3\xd3\x19O\xc0\xef\x14\xb9\x11\xa1\xd7\x17\xe1J&r\x1a1!\xb1>\r\xdbtmS6\xa2\xee\xe5\x1c\x99T\xfe\x08\x80.i\xa3\x07\x9a \xe0*B9\xb0\n?\x8ciT\x81\xb4\x00HTB{m4ng3r5_4tt4ck_15_c001_4nd_und3rv4lu3d~'
```
