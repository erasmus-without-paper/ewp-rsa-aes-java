ewp-rsa-aes-java Library
========================

Java implementation of an [`ewp-rsa-aes128gcm` Encryption][encr-spec].


Installation and Documentation
------------------------------

This library is in beta. We don't deploy to *Maven Central Repository* yet (but
we are planning to, once the [`ewp-rsa-aes128gcm` document][encr-spec] becomes
stable). If you want to test it now, then you'll need to `mvn install` it
locally.

Requires **Java 8 SE**.

**Upgrading?** Check out the [changelog (release notes)](CHANGELOG.md).


Versioning strategy
-------------------

We use [semantic versioning](http://semver.org/) (`MAJOR.MINOR.PATCH`) for our
release version numbers.

 * **Major version** is incremented when our changes are likely to break your
   builds or runtime behavior.

 * **Minor version** is incremented when new features are added. (Note, that
   such changes still can break your builds in some rare cases.)

 * **Patch version** is incremented on bug fixes, documentation updates, etc.


[encr-spec]: https://github.com/erasmus-without-paper/ewp-specs-sec-rsa-aes128gcm
