#!/usr/local/bin/python 
from sys import*;t=p=1;s=stdout;[i,j]=map(lambda f: open(f, 'r'), argv[1:3])
while(t and p):t,p=i.read(1),j.read(1);t and p and s.write(chr(ord(t)^ord(p)))
