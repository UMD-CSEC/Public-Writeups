# (crypto) Waiting List

### Proof of Concept

We basically needed to satisfy the following requirements while passing in values
for **pt**, **r**, and **s**:

```
pt = "william;yarmouth;22-11-2021;09:00"
r = 5^k % n

st.

k = (c*(h + key*r)) % n
c = (s^-1) % n

given that n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
```

To start, we can easily derive **h** since it is directly derived from **pt**,
which we will obviously assume satisfies the string above. Using the **pt** above,
we get `h = 1348738191679027155444901250636491938924255322699`

At this point I thought to myself, what can I put as **s** and **r** to bypass all
of this math? If I used `s = 0`, this causes `c --> (0^-1) % n = 0` which causes
`k --> (0*(h + key*r)) % n = 0`, which gives me what my **r** value should be in
this scenario: `r = 5^0 % n = 1`  

Sending the following json data should satisfy the conditions to give us the flag:
`{"pt": "william;yarmouth;22-11-2021;09:00", "r": "1", "s": "0"}`

### Vulnerability Explanation

The vulnerability here is that the values for **r** and **s** are left unsanitized,
allowing me to "schedule an appointment" with improper values.

### Solvers/Scripts Used
No scripts were used, but here is proof of the solve with the service:

```sh
$ nc 64.227.38.214 30929
Welcome to the SteamShake transplant clinic where our mission is to deliver the most vintage and high tech arms worldwide.
Please use your signature to verify and confirm your appointment.
Estimated waiting for next appointment: 14 months
> {"pt": "william;yarmouth;22-11-2021;09:00", "r": "1", "s": "0"}
Your appointment has been confirmed, congratulations!
Here is your flag: HTB{t3ll_m3_y0ur_s3cr37_w17h0u7_t3ll1n9_m3_y0ur_s3cr37_15bf7w}
```
