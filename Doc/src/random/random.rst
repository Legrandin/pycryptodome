:mod:`Crypto.Random` package
============================

.. function:: Crypto.Random.get_random_bytes(N)

    Return a random byte string of length *N*.

:mod:`Crypto.Random.random` module
----------------------------------

.. function:: Crypto.Random.random.getrandbits(N)

    Return a random integer, at most *N* bits long.

.. function:: Crypto.Random.random.randrange([start,] stop[, step])

    Return a random integer in the range *(start, stop, step)*.
    By default, *start* is 0 and *step* is 1.

.. function:: Crypto.Random.random.randint(a, b)

    Return a random integer in the range no smaller than *a*
    and no larger than *b*.

.. function:: Crypto.Random.random.choice(seq)

    Return a random element picked from the sequence *seq*.

.. function:: Crypto.Random.random.shuffle(seq)

    Randomly shuffle the sequence *seq* in-place.

.. function:: Crypto.Random.random.sample(population, k)

    Randomly chooses *k* distinct elements from the list *population*.
