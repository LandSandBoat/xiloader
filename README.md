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

Run `xiloader --help` for all options. Without `--user` and `--pass` the loader shows a menu.

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

Keys: `server`, `username`, `password`, `otp`, `dataport`, `viewport`, `authport`, `profileport`, `language`, `hairpin`, `hide`, `plain`, `fingerprint`, `trust_this_computer`. Command line options override the file.

`--plain` uses plain text menus. Always on under Wine.

## Server keys

The loader remembers each server's key, like ssh does. On the first connection it prints the key fingerprint and asks whether to trust it. If the key changes later, the loader refuses to connect.

Keys are saved in `%APPDATA%\xiloader\known_servers.json`. Servers on 127.x.x.x are never prompted for.

```sh
xiloader --server example.com --fingerprint SHA256:SsZ/oJuyOzk59TZicWuiA/F8xIW8lTkrTXaqFpod/Mw
```

`--fingerprint` (or `fingerprint` in the json file) skips the prompt: the server is accepted if its key matches and refused otherwise. `--diagnose` prints a server's fingerprint.

"Trust this computer" tokens are tied to the server key and dropped if it changes.

## Troubleshooting

```sh
xiloader --diagnose --server example.com
```

`--diagnose` checks the PlayOnline install and the server, prints the results and exits. It does not log in.

Logs are saved in `%APPDATA%\xiloader\logs` (last ten runs).

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Bad command line or json file |
| 2 | Winsock, COM or the socket hooks failed to start |
| 3 | Server unreachable |
| 4 | Lost connection to the login server |
| 5 | PlayOnline or FFXI not installed for the chosen language |
| 6 | Unsupported PlayOnline version |
| 7 | Profile server unreachable |
| 8 | Failed to start the game |
| 9 | Server key not trusted |

## Checks

```sh
cmake --build build --target xiloader_check
```

`xiloader_check` tests the parts that run without the game.

## Release notes

### Windows

Requires VC2022 redist, included in https://aka.ms/vs/17/release/vc_redist.x86.exe

### Linux (through Wine)

Requires `winetricks vcrun2022`

## Credits

Thanks to [atom0s](https://github.com/atom0s) for starting this project, and for the FFXI research he has shared publicly over the years.

Thanks to the LandSandBoat contributors, and to those of the projects it descends from.

## License

GPLv3. See [LICENSE](LICENSE).
