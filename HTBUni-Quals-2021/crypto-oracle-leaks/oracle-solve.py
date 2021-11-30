from pwn import *
import sys
from binascii import *
from Crypto.Util.number import *
import math

#functions required for manger's attack
def f1(i):
    return (pow(2,i))

def f2(j,i,n,B):
    return ((n+B)//B + j)*f1(i-1)

def f3(ik,mmin,n):
    return (ik*n // mmin) + 1

def option1(r):
    r.recv()
    r.send(b'1\n')
    data = r.recv().decode()
    print(data)
    n = data.split("(n,e): ('")[1].split('\'')[0]
    n = int(n, 16)
    e = 0x10001
    print(f'n = {n}\ne = {e}')
    return n,e

def option2(r):
    r.recv()
    r.send(b'2\n')
    data = r.recv().decode()
    print(data)
    ct = data.split("Encrypted text: ")[1].strip()
    ct = int(ct, 16)
    print(f'ct = {ct}')
    return ct

def option3(r, ct):
    r.recv()
    r.send(b'3\n')
    r.recv()
    r.send((ct + '\n').encode())
    len_val = r.recv().decode().strip().split("Length: ")[1]
    return int(len_val)


def main(arg):
    r = remote(arg.split(':')[0], arg.split(':')[1])
    n,e = option1(r)
    c = option2(r)

    k = int(math.ceil(math.log(n,256)))
    B = pow(2,8*(k-1))

    #query variable denotes the integer which needs to be passed to the oracle
    i = 7
    while True:
        query = (pow(f1(i),e,n)*c) % n
        ct = hexlify(long_to_bytes(query)).decode()
        len_val = option3(r,ct)
        print(f'i = {i} ---- length = {len_val}')
        if (len_val > 127):
            print(f'---------------- i found ----------------')
            break
        i += 1


    j = 0
    while True:
        query = (pow(f2(j,i,n,B),e,n)*c) % n
        ct = hexlify(long_to_bytes(query)).decode()
        len_val = option3(r,ct)
        print(f'j = {j} ---- length = {len_val}')
        if not (len_val > 127):
            print(f'---------------- j found ----------------')
            break
        j += 1

    mmin = n // f2(j,i,n,B) + 1
    mmax = (n+B) // f2(j,i,n,B)

    while mmax - mmin > 1:
        ftmp  = 2*B // (mmax-mmin)
        ik = ftmp*mmin // n
        f3k = f3(ik,mmin,n)
        query = (pow(f3k,e,n)*c) % n
        ct = hexlify(long_to_bytes(query)).decode()
        try:
            len_val = option3(r,ct)
        except:
            print("EOF probably")
            break
        print(f'mmax - mmin = {mmax - mmin} ---- length = {len_val}')
        if (len_val > 127):
            mmin = ((ik*n+B) // f3k) + 1
        else:
            mmax = (ik*n +B) // f3k


    #SUCCESS!!
    m = long_to_bytes(mmin)
    print(f'mmin = {m}')

    #OR

    m = long_to_bytes(mmax)
    print(f'mmax = {m}')


if __name__ == "__main__":
    main(sys.argv[1])
