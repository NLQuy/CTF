from pwn import *

exe = context.binary = ELF('./chall')
r = process(exe.path)

ret_start = b'0x7f'