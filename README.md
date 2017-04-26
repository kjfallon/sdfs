# Secure Distributed File System
A simple demonstration of:

user_login("userA", "pwd123");

user_login("userB", "pwd456");

file_permission_set("userA");

file_access("userA"); //success

file_access("userB"); //failure

file_delegate("userA", "userB");

file_access("userB"); //success

user_logout("userA");

user_logout("userB");

#Build

/usr/bin/cmake .

/usr/bin/cmake --build . --target all -- -j 1

#Requirements:

CMake https://cmake.org/

GLib-2.0 https://developer.gnome.org/glib/ 

libConfuse https://github.com/martinh/libconfuse