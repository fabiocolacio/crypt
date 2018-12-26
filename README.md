Crypt
=====

Easily encrypt and decrypt files from the command line or from scripts. 

Install
-------

You must have a Go compiler installed in your system to compile this program.
You can then compile crypt from the root directory of this project with the
following command:

    $ go build

You may optionally install the man page and binary to your system by running
install script with root privileges:

    # ./install.sh

Usage
-----

You can easily encrypt or decrypt files by calling crypt and supplying a
file to encrypt or decrypt, and a password to encrypt or decrypt it with.

To encrypt the file named `secrets.txt`, with the password
`supersecretpassword`, issue the following command:

    $ crypt -f secrets.txt -p "supersecretpassword"

The file `secrets.txt` will be encrypted, producing the file
`secrets.txt.gobbledygook`.

To decrypt the output file, run `crypt` with the `-d` file using the same
password.

    $ crypt -f secrets.txt.gobbledygook -p "supersecretpassword" -d

The cleartext file will be produced as the file `secrets.txt.gobbledygook.txt`

The original file can be deleted upon successful encryption or decryption by
specifying the `--no-preserve` flag.

For detailed usage information, see the man page:

    $ man crypt
