#coding:utf-8
l = [7,0,1,2,0,3,0,4,2,3,0,3,2,1,2,0,1,7,0,1] 
count = 0
flag = True
stack = []
tag = 0
for i in l:
	if i not in stack:
		if len(stack) < 3:
			stack.append(i)
		else:
			stack[-3:-1:] = stack[1:3:]
			stack.pop()
			stack.append(i)
			flag = True
		count += 1
	else:
		flag = False
		tag = stack.index(i)
		if tag == 2:
			pass
		if tag ==0:
			stack[-3:-1:] = stack[1:3:]
			stack.pop()
			stack.append(i)
		if tag == 1:
			stack[1:3:] = stack[-1:-3:-1]
	print stack,"缺页了" if flag is True else "不缺页"
print"LRU算法结束，总的缺页次数为:",count