
ITER=50

def isPrime(N):
    N1=N-1 ; exp=N1/2
    minusOneSeen=0
    for i in range(2, ITER+2):
	r=pow(i, exp, N)
	if r==N1: minusOneSeen=1
	elif r!=1: return 0
    return minusOneSeen

def findPrime(N):
    while not isPrime(N): N=N+2
    return N

def GCD(x,y):
    if x<0: x=-x
    if y<0: y=-y
    while x>0: x,y = y%x, x
    return y

def Inverse(u, v):
    u3, v3 = long(u), long(v)
    u1, v1 = 1L, 0L
    while v3>0:
	q=u3/v3
	u1, v1 = v1, u1-v1*q
	u3, v3 = v3, u3-v3*q
    return u1 % v









