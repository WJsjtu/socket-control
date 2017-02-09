socket-control
==============

This is a project to controll the socket syscall using hijacking the syscall table.
Configure file is in JSON format and transferred into kernel by netlink.

Working well on ubuntu-14.04.4-desktop-i386, system kernel info
```
Linux version 4.2.0-27-generic (buildd@lgw01-45) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) )
```

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
