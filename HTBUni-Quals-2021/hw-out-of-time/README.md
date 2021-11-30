# (hardware) Out of Time

### Proof of Concept

The service provides power usage for our inputs. 
The power usage for any invalid input of length `n` appear to similar, but an input that is the prefix of the flag results in a distinct power usage graph. 

We can identify the correlation coefficient to identify whether an input is closely correlated to an invalid input. If it is, then we know that it can't be the right character to choose. This way, we can bruteforce one character at a time and choose the one that is least correlated with an invalid input.

### Vulnerability Explanation

We use the power usage as a side channel to identify how closely inputs are correlated to known-invalid inputs, and choose the least-correlated input.

### Solvers/Scripts Used

The following script handles the per-character bruteforce to identify the entire flag.

```python3
import socket_interface as si
import numpy as np
from numpy import corrcoef

def avg_traces(string, n = 10):
    traces = []
    for i in range(n):
        leakage = si.connect_to_socket(b'1', string)
        traces.append(si.b64_decode_trace(leakage))
        # time.sleep(0.1)
    return np.median(traces, axis = 0)
    

known = ''
while True:
    wrong_val = avg_traces(known + '\xff', n=1)

    min_corr = 1
    good_char = ''

    traces = dict()
    for c in '_{}1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()':
        traces[c] = avg_traces(known + c, n = 1)
        corr = corrcoef(wrong_val, traces[c])[0][1]
        print('\r', c, corr, '[', good_char, min_corr, ']', end='')
        if corr < min_corr:
            min_corr = corr
            good_char = c
        if corr < 0.2:
            break
    known += good_char
    print('\r')
    print(known)
```