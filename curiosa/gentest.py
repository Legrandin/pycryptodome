import string
hexstr='0123456789abcdef'
s=''
for i in range(0,16,2): s=s+chr(string.atol(hexstr[i:i+2], 16))
f=open('data', 'w')
f.write(s)
f.close()

