secure
======

Package `secure` exports secure encryption and decryption functions and provides example commands.

`secure` is designed to allow text passwords to be used as secure encryption keys.  This does not mitigate the need to select hard to guess passwords that are sufficiently long and that utilize a sufficiently diverse character set.  The text password is processed by PBKDF2 to create a 32 byte pseudorandom masterkey.  A variable number of interations (minimum 250,000 iterations) slows down any brute force attack on the text password.  HKDF is then used to expand the master key into two cryptographically independent keys, one for encryption/decryption and one for MAC authentication.

Encryption/decryption is done using AES in CBC mode with a 256 bit key.  MAC authentication is performed by HMAC using SHA256. 

Structure
---------

The `secure` package exports the following functions:
* `Encrypt` - secure encryption
* `Decrypt` - secure decryption
* `IsAuthError` - returns true if error returned by Decrypt is an authentication error

A `go test` source file is included to verify the correct operation of these functions.

The `secure` package includes the following commands utilizing Encrypt and Decrypt:
* `wrap` - encryption
* `unwrap` - decryption

These are examples of the use of the functions exported by `secure`.  They are also safe commands for the secure encryption
and decryption of single files.  The command switch -h provides a listing of the parameters of each command.

This is a pipeline example verifying the basic functionality of these commands:

`ls -al | ./wrap -pw foo -stdin | ./unwrap -pw foo -stdin`

To encrypt file a into aEncrypted.blk with a double checked non-echoed password entry:

`wrap a aEncrypted`

To decrypt the encrypted file with non-echoed password entry:

`unwrap aEncrypted aDecrypted`

Please note that non-echoed passwords work under the Windows `cmd` shell and 
Linux `bash`.  Alternate environments such as cygwin may fail to hide the password.

Using the -blk parameter causes the `wrap` output file name to be the input file name with 
a ".blk" added while -blk removes the ".blk" during `unwrap`:

`wrap -blk input.txt` yields input.txt.blk
`unwrap -blk input.txt.blk` yields input.txt

Neither command will overwrite an existing file unless -o is specified.

Requirements
------------

`secure` is a golang project.  Access golang at golang.org.

`secure` uses the following go packages from sub-repositories not included in the base `go` development environment.  They can be accessed with `go get`:

* "golang.org/x/crypto/pbkdf2"
* "golang.org/x/crypto/hkdf"
* "github.com/howeyc/gopass" - only needed by the `wrap` and `unwrap` commands

`secure` has only been tested on linux and Windows.  

To Do
-----

* Test `secure` on OS X.  `secure` functions on Windows and linux.
* Host binary versions for all environments.  Currently only Win64 binaries are hosted.
