#!/usr/local/bin/python 
from sys import*;from string import*;a=argv;[s,p,q]=filter(lambda x:x[:1]!=
'-',a);d='-d'in a;e,n=atol(p,16),atol(q,16);l=(len(q)+1)/2;o,inb=l-d,l-1+d
while s:s=stdin.read(inb);s and map(stdout.write,map(lambda i,b=pow(reduce(
lambda x,y:(x<<8L)+y,map(ord,s)),e,n):chr(b>>8*i&255),range(o-1,-1,-1)))
