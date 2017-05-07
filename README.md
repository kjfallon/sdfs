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
file_access("userA");
CLIENT: wrote message GET_FILE 6 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
file_access("userB");
CLIENT: wrote message GET_FILE 6 bytes
TLS: read 2 bytes from channel: 0a7f
CLIENT: received message BAD_COMMAND
file_delegate("userA", "userB");
CLIENT: wrote message DELEGATE_PERM 12 bytes
TLS: read 2 bytes from channel: 027f
CLIENT: received message OK
file_access("userB");
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
Erasing keys...
TLS: closed
SDFS Client exit.
$
```

# Server Execution Example
```
Note the server accesses the shadow password database so it must run as root
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
SERVER: received file_permission_set for username: userA
SERVER: added userA as file owner
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 087573657241
SERVER: received message GET_FILE
SERVER: received file access for username: userA
SERVER: userA is a file owner
SERVER: file access was successful for userA
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 087573657242
SERVER: received message GET_FILE
SERVER: received file access for username: userB
SERVER: file access was rejected for userB
SERVER: wrote message BAD_COMMAND 2 bytes
TLS: read 12 bytes from channel: 0775736572417f7573657242
SERVER: received message DELEGATE_PERM
SERVER: received delegator: userA
SERVER: received delegatee: userB
SERVER: delegated permissions to userB
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 087573657242
SERVER: received message GET_FILE
SERVER: received file access for username: userB
SERVER: userB was delegated access
SERVER: file access was successful for userB
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 057573657241
SERVER: received message LOGOUT
SERVER: received logout request for username: userA
SERVER: userA logged out
SERVER: wrote message OK 2 bytes
TLS: read 6 bytes from channel: 057573657242
SERVER: received message LOGOUT
SERVER: received logout request for username: userB
SEVER: userB logged out
SERVER: wrote message OK 2 bytes

Erasing keys...
TLS: closed
SDFS Server exit.
#
```