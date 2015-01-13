socket-control
==============

This is a project to controll the socket syscall using hijacking the syscall table.
Configure file is in JSON format and transferred into kernel by netlink.

Working well on Unbuntu 14.04.1 (kernel 3.13.0)

To compile ccdaemon
``` c
gcc -o ccdaemon ccdaemon.c -lm
```

To compile CCModule.ko
``` c
    make clean
    make
```
To install module
``` c
    insmod CCModule.ko
```
To run ccdaemon
``` c
    ./ccdaemon black.json
```
