# xiloader

FFXI Server Emulator Boot Loader -- Launches client without PlayOnline.

## Build

```sh
mkdir build
cmake -S . -B build -A Win32
cmake --build build
```

## Usage

```sh
xiloader --server example.com --user name --pass secret
```

Run `xiloader --help` for every option. Without `--user` and `--pass` the loader shows a menu to log in, create an account, change a password or manage 2FA.

Options can also come from a json file passed with `--json`:

```json
{
    "server": "example.com",
    "username": "name",
    "password": "secret",
    "language": "US",
    "hide": true
}
```

The keys are `server`, `username`, `password`, `otp`, `dataport`, `viewport`, `authport`, `profileport`, `language`, `hairpin`, `hide`, `plain` and `trust_this_computer`. An option given on the command line overrides the same option in the file.

`--plain` replaces the interactive menus with line-based prompts. It is always on under Wine.

## Checks

```sh
cmake --build build --target xiloader_check
```

`xiloader_check` exercises the parts that run without the game: the plain menus, option loading and the lobby data connection. It exits non-zero on the first failed assertion.

## Release notes

### Windows

Requires VC2022 redist, included in https://aka.ms/vs/17/release/vc_redist.x86.exe

### Linux (through Wine)

Requires `winetricks vcrun2022`
