#!/usr/bin/python

import math
import numpy as np
import matplotlib.pyplot as plt

def p(k, t):
    c = 8 * (math.pow(math.pi, 2) - 6) / 3
    d = 2.00743 * math.log(2) / 4
    p_M = []
    M_max = 2 * int(math.sqrt(k - 1)) - 1
    for M in xrange(3, M_max + 1):
        sums = 0
        for j in xrange(2, M + 1):
            for m in xrange(j, M + 1):
                if j == 2:
                    continue
                exponent = max(-800, m * (1- t) - j - (k - 1) / j)
                sums += math.pow(2.0, exponent)
        p_M.append(d * (math.pow(2, -M * t) + c * sums * math.pow(2, t)))
    return min(p_M)


## Bit size 160..512
plt.subplot(1, 2, 1)
x = np.arange(100, 512+1, )
for t in xrange(10, 40+1, 5):
    y = np.vectorize(lambda param: p(param, t))(x)
    plt.plot(x, np.log2(y), label="t=%d"%t)
plt.ylabel(r"$log_{10} \/ p{k,t}$", fontsize=20)
plt.xlabel(r"$size (bits)$", fontsize=20)
plt.ylim([-256, 0])
plt.xlim([100, 512])
plt.axhline(y=-100, color="gray", linestyle="--")
plt.yticks(size=10)
plt.xticks([100, 160, 224, 256, 384, 512], size=10)
plt.legend(ncol=2, prop={'size':10})
plt.grid(True)

## Bit size 512..4096
plt.subplot(1, 2, 2)
x = np.arange(512, 4096+1, 512)
for t in xrange(1, 8):
    y = np.vectorize(lambda param: p(param, t))(x)
    plt.plot(x, np.log2(y), label="t=%d"%t)
plt.xlabel(r"$size (bits)$", fontsize=20)
plt.ylim([-256, 0])
plt.xlim([512, 4096])
plt.axhline(y=-100, color="gray", linestyle="--")
plt.yticks(size=10)
plt.xticks([512, 1024, 1536, 2048, 3072, 4096], size=10)
plt.legend(ncol=2, prop={'size':10})
plt.grid(True)

plt.show()
