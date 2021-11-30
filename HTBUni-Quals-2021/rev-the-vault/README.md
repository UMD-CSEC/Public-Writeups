# (rev) The Vault

### Proof of Concept

We can open the binary in Ghidra. We can quickly identify the flag validation function that does the following:
 1. Reads a character
 2. Looks up a function based on the current index, and call it.
 3. Check that the return value matches the input character.
 4. Repeat 0x19 times.

### Vulnerability Explanation

From here, it's simply a matter of identifying the function being called and getting its return value.
It's made even easier with the template names of the functions being included in the binary.

### Solvers/Scripts Used

Since there's only 25 characters, it's significantly faster to solve by hand than to automate it. 

The idea is straight-forward:
1. Look up the corresponding mapping from flag index to function index.
2. Get the template label for that function (which looks like `TheCharacter<(unsigned_char)35>::VTT`)
3. Convert the associated number to its corresponding ASCII representation.
4. Repeat for each character.

Doing this provides us the flag: `HTB{vt4bl3s_4r3_c00l_huh}`.
