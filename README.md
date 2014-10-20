secure
======

Package `secure` exports secure encryption and decryption functions and provides example commands.

`secure` is designed to allow text passwords to be used as secure encryption keys.  This does not mitigate the need to select hard to guess passwords that are sufficiently long and that utilize a sufficiently diverse character set.  However, the text password is then processed by PBKDF2 to create a 32 byte pseudorandom masterkey.  A variable number of interations exceeding 250,000 slows down any brute force attack on the text password.  HKDF is then used to expand the master key into two cryptographically independent keys, one for encryption/decryption and one for MAC authentication.

Structure
---------

The `secure` package exports the following functions:
* `Encrypt` - secure encryption
* `Decrypt` - secure decryption
* `IsAuthError` - returns true if error returned by Decrypt is an authentication error

A `go test` source file is included to verify the correct operation of these functions.

The `secure` package `commands` folder includes the following commands utilizing Encrypt and Decrypt:
* `wrap` - encryption
* `unwrap` - decryption

These are examples of the use of the functions exported by `secure`.  They are also safe commands for the secure encryption
and decryption of single files.  The command switch -h provides a listing of the parameters of each command.

This is a pipeline example verifying the basic functionality of these commands:

`ls -al | ./wrap -pw foo -stdin | ./unwrap -pw foo -stdin`

Requirements
------------

`secure` is a golang project.  Access golang at golang.org.

`secure` uses the following go packages from sub-repositories not included in the base `go` development environment.  They can be accessed with `go get`:

* "code.google.com/p/go.crypto/pbkdf2"
* "code.google.com/p/go.crypto/hkdf"
* "code.google.com/p/gopass" - only needed by the `wrap` and `unwrap` commands

`secure` has only been tested on linux.  

To Do
-----

* Test `secure` on Windows and OS X.  `secure` should function well under Windows as-is, except that the non-echoed password entry provided by `gopass` will not be available.  OS X should be a similar situation.  Non-echoed passwords may work.
* Host binary versions for all environments.
