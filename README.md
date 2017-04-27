# Project Requirements
A concrete and specific execution of the protocol as below: Initially, a server stores a single file.  Two clients userA and userB can interact with the server in the following sequence:

```user_login("userA", "pwd123");
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

/usr/bin/cmake .

/usr/bin/cmake --build . --target all -- -j 1

# Requirements:

CMake https://cmake.org/

GLib-2.0 https://developer.gnome.org/glib/ 

libConfuse https://github.com/martinh/libconfuse

# Client Execution Example

``` $ ./sdfs-client
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
Command line parameters are optional and will override configuration file parameters listed above.
No command line parameters were specified.

Loaded and validated this host's x509 certificate and key.
DNS lookup for sdfs-server is 127.0.1.1
CLIENT: connecting to server 127.0.1.1
CLIENT: Ready to use tcp transport to server 127.0.1.1
TLS: channel established using TLSv1/SSLv3 AES256-SHA
TLS: SERVER AUTH OK, server hostname sdfs-server matches cert hostname sdfs-server
TLS: sending client authentication to server (12 bytes total)
TLS: wrote 12 bytes

Erasing keys...
TLS: closed
SDFS Client exit.
$
```

# Server Execution Example
```$ sudo ./sdfs-server

   ********************
   SDFS Server Launched
   ********************

   Parsing configuration file "config/sdfs-server.conf"
   ---------------------------------------------
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
   TLS: channel established using TLSv1/SSLv3 AES256-SHA
   TLS: read 12 bytes: 75736572417f707764313233
   TLS: received client auth username: userA
   TLS: received client auth password: pwd123
   TLS: CLIENT AUTH OK, client credentials match local user
   ^C
   Erasing keys...
   TLS: closed
   SDFS Server exit.
   $
   ```