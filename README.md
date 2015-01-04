socket-control
==============

This is a project to controll the socket syscall using hijacking the syscall table.
Configure file is in JSON format and transferred into kernel by netlink.

To compile ccdaemon
    gcc -o ccdaemon ccdaemon.c -lm
    
To compile CCModule.ko
    make clean
    make
