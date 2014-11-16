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

x = np.arange(512, 4096+1, 512)
for t in xrange(1, 8):
    y = np.vectorize(lambda param: p(param, t))(x)
    plt.plot(x, np.log2(y), label="t=%d"%t)

plt.ylabel(r"$log_{10} \/ p{k,t}$", fontsize=20)
plt.xlabel(r"$size (bits)$", fontsize=20)
plt.ylim([-256, 0])
plt.xlim([512,4096])
plt.axhline(y=-100, color="gray", linestyle="--")
plt.xticks([512, 1024, 1536, 2048, 3072, 4096])
plt.legend(ncol=2)
plt.grid(True)
plt.show()
