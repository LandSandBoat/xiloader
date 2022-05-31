# xiloader

FFXI Server Emulator Boot Loader -- Launches client without PlayOnline.

## Build

```sh
mkdir build
cmake -S . -B build -A Win32
cmake --build build
```

## xi_checker

Verifies DirectPlay and POL are installed and connect to a server using xiloader (installed in POL folder).

Usage:

```sh
xi_checker $server_ip
```
