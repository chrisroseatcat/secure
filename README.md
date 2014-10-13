secure
======

Package `secure` exports secure encryption and decryption functions and provides example commands.



Structure
---------

The `secure` package exports the following functions:
* Encrypt - secure encryption
* Decrypt - secure decryption
* IsAuthError - returns true if error returned by Decrypt is an authentication error

The `secure` package `commands` folder includes the following commands utilizing Encrypt and Decrypt
* Wrap - encryption
* Unwrap - decryption
These are examples of the use of the functions exported by `secure`.  They are also safe commands for the secure encryption
and decryption of single files.  The command switch -h provides a listing of the parameters of each command.

Requirements
------------

Secure is a golang project.  Access golang at golang.org.
