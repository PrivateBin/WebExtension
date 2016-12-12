# PrivateBin-webextension

**PrivateBin browser extension to verify integrity of PrivateBin instances**

**Work in progress!**

This web extension was created out of the interest to secure PrivateBin installations even more. As even with many security features, which have been implemented in PrivateBin, one fundamental issue remains: [As a user you have to trust the server](https://github.com/PrivateBin/PrivateBin/wiki/FAQ#but-javascript-encryption-is-not-secure).

This add-on tries to resolve this issue by adding a local security layer, which can ensure that a PrivateBin instance delivers the original code as published in the [main repository](https://github.com/PrivateBin/PrivateBin) and the server admin has not tampered with it.
It is based on [Subresource integrity](https://en.wikipedia.org/wiki/Subresource_Integrity) and thus only supported by browsers, which support this security feature.

