# (misc) Insane Bolt

### Proof of Concept

The service provides us a maze, which is trivial to solve using a naive breadth-first-search.

### Vulnerability Explanation

Once we script the maze solving, we just have to let it run for a couple of iterations and then we get the flag.

### Solvers/Scripts Used

```python3
from pwn import *

r = remote('167.172.51.173', 30122)

def solve(maze, start=None, path=None, seen=None):
    # Avoid F and D
    # L is OK
    # End at G
    # Start at R

    if start is None:        
        for x in range(len(maze)):
            for y in range(len(maze[x])):
                if maze[x][y] == 'R':
                    start = (x, y)

    path = path or []
    seen = seen or set()

    sx, sy = start

    directions = [('L', (0, -1)), ('R', (0, 1)), ('D', (1, 0))]

    seen.add((sx, sy))

    print(sx, sy)

    for d, (x, y) in directions:
        if (sx + x, sy + y) in seen:
            continue

        if maze[sx + x][sy + y] == 'F' or maze[sx + x][sy + y] == 'D':
            # fail path
            continue
            
        if maze[sx + x][sy + y] == 'G':
            return path + [d]

        ret = solve(maze, (sx + x, sy + y), path + [d], seen)

        if ret:
            return ret

    return None

r.sendlineafter(b'>', b'2')

while True:

    r.recvuntil(b'\n')
    maze = r.recvuntil(b'\n\n>', drop=True)

    maze = maze.replace(b'  ', b' ').replace(b'\xf0\x9f\x94\xa5', b'F').replace(b'\xe2\x98\xa0\xef\xb8\x8f', b'D').replace(b'\xf0\x9f\xa4\x96', b'R').replace(b'\xf0\x9f\x94\xa9', b'L').replace(b'\xf0\x9f\x92\x8e', b'G')
    maze = maze.decode()

    maze = [x.split() for x in maze.split('\n')]
    [print(x) for x in maze]

    solution = solve(maze)

    r.sendline((''.join(solution)).encode())

    r.recvuntil(b'\n')
```
