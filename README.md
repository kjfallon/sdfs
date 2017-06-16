# Project Requirements
A concrete and specific execution of the protocol as below: Initially, a server stores a single file.  Two clients userA and userB can interact with the server in the following sequence:

```
user_login("userA", "pwd123");
user_login("userB", "pwd456");
file_permission_set("userA");
file_access("userA"); //success
file_access("userB"); //failure
file_delegate("userA", "userB");
file_access("userB"); //success
user_logout("userA");
user_logout("userB");
```

# About
This project implements two binaries authored in C, a client, and a server.  Both accept command-line parameters as well as use a configuration file.  The client and server use the OpenSSL Libcrypto API to implement TLS and PKI validation.  When the client is provided with a hostname it will perfrom DNS resolution and establish a TLS 1.2 session using the AES256-GCM-SHA384 ciphersuite to the server.  The client validates that the certificate presented by the server was issued to the hostname.  The client authenticates to the server with a username/password pair.  The server validates the credentials against the local shadow password database of system users.  A simple message protocol is used to exchange commands and data  within the TLS session between  the client and server.  The server simulates providing data (files) to the client in a manner restricted by permissions.

The AES256-GCM-SHA384 ciphersuite combines encryption and integrity validation in one algorithm.  This is called an “authenticated encryption with associated data” (AEAD) cipher.This scheme incorporates both MAC authentication and AES Galois/Counter Mode (GCM) block mode encryption in an encrypt-then-MAC sequence.  AEAD ciphersuites are recommended by organizations including the Open Web Application Security Project (OWASP) as a secure ciphersuite to use with TLS.  

# Build

Cmake is used to create the Makefile.

$ /usr/bin/cmake .

$ /usr/bin/cmake --build . --target all -- -j 1

# Requirements:

CMake https://cmake.org/

OpenSSL https://www.openssl.org/

GLib-2.0 https://developer.gnome.org/glib/ 

libConfuse https://github.com/martinh/libconfuse

Ubuntu command to install required packages:
```
$ sudo apt-get install cmake g++ libssl-dev pkg-config libglib2.0-dev libconfuse-dev
```
# Client Execution Example

```
$ ./sdfs-client

********************
SDFS Client Launched
********************

Parsing configuration file "config/sdfs-client.conf"
---------------------------------------------------
--default port used by SDFS Server: 44444
--default remote server: sdfs-server
--default client cert name: certs/sdfs-client.crt
--default client priv key name: certs/sdfs-client.key
--default ca cert name: certs/cacert.pem

Parsing parameters specified on command line
--------------------------------------------
Command line parameters are optional and will override
configuration file parameters listed above.
No command line parameters were specified.

Loaded and validated this host's x509 certificate and key.
DNS lookup for sdfs-server is 127.0.1.1
CLIENT: connecting to server 127.0.1.1
CLIENT: Ready to use tcp transport to server 127.0.1.1
TLS: channel established using TLSv1/SSLv3 AES256-GCM-SHA384
TLS: SERVER AUTH OK, server DNS hostname (sdfs-server) matches cert CN (sdfs-server)
user_login("userA", "pwd123");
CLIENT: wrote message LOGIN 13 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
user_login("userB", "pwd456");
CLIENT: wrote message LOGIN 13 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
file_permission_set("userA");
CLIENT: wrote message SET_PERM 6 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
file_access("userA"); //success
CLIENT: wrote message GET_FILE 6 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
file_access("userB"); //failure
CLIENT: wrote message GET_FILE 6 bytes
TLS: read 2 bytes from channel: 0a7f
CLIENT: received message BAD_COMMAND
file_delegate("userA", "userB");
CLIENT: wrote message DELEGATE_PERM 12 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
file_access("userB"); //success
CLIENT: wrote message GET_FILE 6 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
user_logout("userA");
CLIENT: wrote message LOGOUT 6 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
user_logout("userB");
CLIENT: wrote message LOGOUT 6 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
^C
 Resetting file permissions...

Erasing keys...
TLS: closed
SDFS Client exit.
$
```

# Server Execution Example
```
Note: Server process accesses the shadow password database and must run as root.
# ./sdfs-server

********************
SDFS Server Launched
********************

Parsing configuration file "config/sdfs-server.conf"
---------------------------------------------------
--default SDFS server port: 44444
--default host cert name: certs/sdfs-server.crt
--default host priv key name: certs/sdfs-server.key
--default ca cert name: certs/cacert.pem

Parsing parameters specified on command line
--------------------------------------------
Command line parameters are optional and will override
configuration file parameters listed above.
--No command line parameters were specified

Loaded and validated this host's x509 certificate and key.
Listening for client TLS connections on 0.0.0.0:44444
Client connected from 127.0.0.1
TLS: channel established using TLSv1/SSLv3 AES256-GCM-SHA384
TLS: read 13 bytes from channel: 0475736572417f707764313233
SERVER: received message LOGIN
SERVER: received client auth username: userA
SERVER: received client auth password: pwd123
SERVER: CLIENT AUTH OK, client credentials match local OS user
SERVER: wrote message OK 2 bytes
TLS: read 13 bytes from channel: 0475736572427f707764343536
SERVER: received message LOGIN
SERVER: received client auth username: userB
SERVER: received client auth password: pwd456
SERVER: CLIENT AUTH OK, client credentials match local OS user
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 067573657241
SERVER: received message SET_PERM
SERVER: userA given read permission for fileX 
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 087573657241
SERVER: received message GET_FILE
SERVER: userA requests read permission for fileX 
User has permission to read
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 087573657242
SERVER: received message GET_FILE
SERVER: userB requests read permission for fileX 
TLS: User does not have permission to read
SERVER: wrote message BAD_COMMAND 2 bytes
TLS: read 12 bytes from channel: 0775736572417f7573657242
SERVER: received message DELEGATE_PERM
SERVER: received delegate command from username: userA
SERVER: received delegate command to username: userB
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 087573657242
SERVER: received message GET_FILE
SERVER: userB requests read permission for fileX 
User has permission to read
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 057573657241
SERVER: received message LOGOUT
SERVER: received logout request for username: userA
SERVER: userA logged out
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 057573657242
SERVER: received message LOGOUT
SERVER: received logout request for username: userB
TLS: userB logged out
SERVER: wrote message OK 2 bytes

Erasing keys...
TLS: closed
SDFS Server exit.
#
```
