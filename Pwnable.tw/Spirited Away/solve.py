#!/usr/bin/env python3

from pwn import *

exe = ELF("./spirited_away_patched")
libc = ELF("./libc6_2.24-9ubuntu2.2_i386.so")
ld = ELF("./ld-2.24.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
