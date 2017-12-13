ewp-rsa-aes-java Library
========================

Java implementation of an [`ewp-rsa-aes128gcm` Encryption][encr-spec].


Installation and Documentation
------------------------------

Requires **Java 8 SE**.

Releases are deployed to *Maven Central Repository*. You'll simply need to
include a proper reference in your build's dependencies. Click the image below
for the artifact details.

[
    ![Maven Central](https://maven-badges.herokuapp.com/maven-central/eu.erasmuswithoutpaper/ewp-rsa-aes-java/badge.svg)
](https://maven-badges.herokuapp.com/maven-central/eu.erasmuswithoutpaper/ewp-rsa-aes-java)

You can also browse the project's Javadocs here:

[
    ![Javadocs](http://javadoc.io/badge/eu.erasmuswithoutpaper/ewp-rsa-aes-java.svg?color=red)
](http://javadoc.io/doc/eu.erasmuswithoutpaper/ewp-rsa-aes-java)

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
