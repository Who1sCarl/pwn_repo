#coding:utf-8
from socket import*
import time
import random
HOST = "0.0.0.0"
PORT = 9007
client = socket(AF_INET,SOCK_STREAM)
client.connect((HOST,PORT))
data = client.recv(2048)
time.sleep(2)
for i in xrange(100):
	time.sleep(0.2)
	rec = client.recv(2048)
	idx = rec.find('N=')
	if idx != -1:
		tmp = rec[idx:].split(" ")
		totalnum = int(tmp[0][2:])
		trials = int(tmp[1][2:])
	print "get"+"N="+str(totalnum)+"  "+"C="+str(trials)+"\n"
	left = 0
	right = totalnum - 1
	mid = (left + right) / 2
	answer = ""
	for i in xrange(trials):
		ss = [str(n) for n in range(left,mid+1)]
		sends = " ".join(ss)
		client.send(sends+"\n")
		rec = client.recv(2048)
		rec.split("\n")
		rec = int(rec)
		print "weight="+str(rec)+"  "+"l=%d mid=%d r=%d"%(left,mid,right)
		if rec != (mid - left + 1) * 10:
			right = mid 
			mid = (left + right) / 2
		else:
			left = mid + 1
			mid = (left + right) / 2
	client.send(str(mid)+"\n")
	answer = client.recv(2048)
	print answer
answer = client.recv(2048)
print "answer=%s"%answer
client.close()