# xiloader

FFXI Server Emulator Boot Loader -- Launches client without PlayOnline.

## Build

```sh
mkdir build
cmake -S . -B build -A Win32
cmake --build build
```

## Release notes

#Windows:
Requires VC2022 redist, included in https://aka.ms/vs/17/release/vc_redist.x86.exe

#Linux (through Wine):
Requires `winetricks vcrun2022`
