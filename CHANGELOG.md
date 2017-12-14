Release notes
=============

1.0.1
-----

* Bugfix: Static `EwpRsaAes128GcmDecoder` methods returned truncated SHA-256
  hashes. Only the first 16 bytes were returned (instead of the full 32 bytes).


1.0.0
-----

*Released on 2017-12-13*

First official release.
