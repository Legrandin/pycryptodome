#!/usr/local/bin/python 
from sys import*;from string import *;t,x,y,j,s,a=range(256),0,0,0,1,argv[1]
k=(map(lambda b:atoi(a[b:b+2],16), range(0,len(a),2))*256)[:256]
for i in t[:]:j=(k[i]+t[i]+j)%256;t[i],t[j]=t[j],t[i]
while(s):s=stdin.read(1);l,x=len(s),(x+1)%256;y,c=(y+t[x])%256,l and ord(s);(
t[x],t[y])=t[y],t[x];stdout.write(chr(c^t[(t[x]+t[y])%256])[:l])

