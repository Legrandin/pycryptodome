Contribute and support
======================

- Do not be afraid to contribute with small and apparently insignificant
  improvements like correction to typos. Every change counts.
- Read carefully the :doc:`license` of PyCryptodome. By submitting your code,
  you acknowledge that you accept to release it according to the `BSD 2-clause license`_.
- You must disclaim which parts of your code in your contribution were partially
  copied or derived from an existing source. Ensure that the original is licensed
  in a way compatible to the *BSD 2-clause license*.
- You can propose changes in any way you find most convenient.
  However, the preferred approach is to:

  * Clone the main repository on `GitHub`_.
  * Create a branch and modify the code.
  * Send a `pull request`_ upstream with a meaningful description.

- Provide tests (in ``Crypto.SelfTest``) along with code. If you fix a bug
  add a test that fails in the current version and passes with your change.
  The tests run with `pytest`_. To run them against your working copy,
  install it in editable mode (this compiles the C extensions in place;
  repeat it only when you change C code)::

      pip install -r requirements-test.txt
      pip install -e .
      python -m Crypto.SelfTest --skip-slow-tests

  The option ``--skip-slow-tests`` skips the tests marked as ``slow``
  (mostly the larger sets of test vectors) for a faster turnaround.
  Run ``python -m Crypto.SelfTest`` without it to execute the complete suite,
  as the CI does, before submitting your change. If you add a test that takes
  long to run, mark it with ``@pytest.mark.slow``.

  Any other argument is passed on to pytest, for instance ``-k AES`` to only run the AES tests.
- If your change breaks backward compatibility, highlight it and include
  a justification.
- Ensure that your code complies to `PEP8`_ and `PEP257`_.
- If you add or modify a public interface, make sure it has
  inline type annotations.
- Ensure that your code does not use constructs or includes modules not
  present in Python 3.8.
- Add a short summary of the change to the file ``Changelog.rst``.
- Add your name to the list of contributors in the file ``AUTHORS.rst``.

The PyCryptodome mailing list is hosted on `Google Groups <https://groups.google.com/forum/#!forum/pycryptodome>`_.
You can mail any comment or question to *pycryptodome@googlegroups.com*.

Bug reports can be filed on the `GitHub tracker <https://github.com/Legrandin/pycryptodome/issues>`_.

.. _BSD 2-clause license: https://opensource.org/licenses/BSD-2-Clause
.. _GitHub: https://github.com/Legrandin/pycryptodome
.. _pull request: https://help.github.com/articles/about-pull-requests/
.. _pytest: https://docs.pytest.org/
.. _PEP8: https://www.python.org/dev/peps/pep-0008/
.. _MIT license: https://opensource.org/licenses/MIT
.. _PEP257: https://legacy.python.org/dev/peps/pep-0257/
