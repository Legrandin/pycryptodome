
import pgp, sys

indent=0
def loop(s=None, indent=0):
    import sys
    while (1):
	if s==None: p,dummy=pgp.readPacket(sys.stdin)
	else: p,s=pgp.readPacket(s)
	if p==None: break
	print indent*'\t', p.CTBT, p
	if p.CTBT==pgp.CTBT_COMPR: 
	    loop(p.decompress(),indent+1)
	if p.CTBT==pgp.CTBT_SIG:
	    print p.__dict__
    
loop()
