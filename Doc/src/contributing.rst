How to contribute
=================

- Do not be afraid to contribute with small and apparently insignificant
  improvements like correction to typos. Every change counts.
- Read carefully the :doc:`license` of PyCryptodome. By submitting your code,
  you acknowledge that you accept to release it according to those terms
  to the public domain. If your contribution was partially copied or derived
  from somewhere else, you must verify that the source is in the public domain.
- You can propose changes in any way you find most convenient.
  However, the preferred approach is to:

  * Clone the main repository on `GitHub`_.
  * Create a branch and modify the code. 
  * Send a `pull request`_ upstream with a meaningful description.

- Provide tests (in ``Crypto.SelfTest``) along with code. If you fix a bug
  add a test that fails in the current version and passes with your change.
- If your change breaks backward compatibility, hightlight it and include
  a justification.
- Ensure that your code complies to `PEP8`_ and `PEP257`_.
- Ensure that your code does not use constructs or includes modules not
  present in `Python 2.4`_.
- Add a short summary of the change to the file ``Changelog.rst``.
- Add your name to the list of contributors in the file ``AUTHORS.rst``.

.. _GitHub: https://github.com/Legrandin/pycryptodome
.. _pull request: https://help.github.com/articles/using-pull-requests
.. _PEP8: http://www.python.org/dev/peps/pep-0008/
.. _PEP257: http://legacy.python.org/dev/peps/pep-0257/
.. _Python 2.4: http://rgruet.free.fr/PQR24/PQR2.4.html
