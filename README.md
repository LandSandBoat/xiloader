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

The keys are `server`, `username`, `password`, `otp`, `dataport`, `viewport`, `authport`, `profileport`, `language`, `hairpin`, `hide`, `plain`, `fingerprint` and `trust_this_computer`. An option given on the command line overrides the same option in the file.

`--plain` replaces the interactive menus with line-based prompts. It is always on under Wine.

## Server keys

Servers mostly use self-signed certificates, so the loader treats them the way ssh treats hosts. The first time it connects to a server it shows the fingerprint of the server's key and asks whether to trust it. The answer is kept in `%APPDATA%\xiloader\known_servers.json`, and later connections go ahead without asking as long as the key is the same.

If the key is different from the one on record the loader stops before sending anything, since that is what an intercepted connection looks like. A server on this machine (127.x.x.x) is never asked about or refused.

```sh
xiloader --server example.com --fingerprint SHA256:SsZ/oJuyOzk59TZicWuiA/F8xIW8lTkrTXaqFpod/Mw
```

`--fingerprint`, or `fingerprint` in the json file, names the key to insist on. The server is trusted without a question if it matches and refused if it does not, whatever is on record, and a match replaces the record. A server's operator can publish the fingerprint, or ship it in a launcher config, so players never have to judge an unknown key. `--diagnose` prints it.

A "trust this computer" token is bound to the key of the server that issued it. If that server's key changes, the token is discarded instead of being sent, and the next login asks for the OTP code again.

## Troubleshooting

Before asking for a password the loader checks that PlayOnline and the game are installed for the chosen language, and says what to do when they are not. If `--lang` is not given and PlayOnline is only installed for another language, that one is used.

```sh
xiloader --diagnose --server example.com
```

`--diagnose` prints a report and exits without logging in or starting the game: the Windows version and privileges, the PlayOnline and game install, whether this PlayOnline version is one the loader supports, and whether the server's ports and TLS answer. It contains no credentials, so it can be shared when asking for help.

Every run is also saved under `%APPDATA%\xiloader\logs`, with the newest ten kept. When a run fails in a window that was opened just for the loader, the window stays open until a key is pressed.

The exit code says what went wrong:

| Code | Meaning |
| --- | --- |
| 0 | The game ran, or Exit was chosen from the menu |
| 1 | Bad command line or json file |
| 2 | Winsock, COM or the socket hooks failed to start |
| 3 | The server could not be reached |
| 4 | The login server stopped answering |
| 5 | PlayOnline or the game is not installed for the chosen language |
| 6 | This PlayOnline version is not supported |
| 7 | The PlayOnline profile server could not be reached |
| 8 | The game could not be started |
| 9 | The server's key was not trusted |

## Checks

```sh
cmake --build build --target xiloader_check
```

`xiloader_check` exercises the parts that run without the game: the plain menus, option loading, the lobby data connection, the pattern scan, the install checks, the known servers record and trust tokens. It exits non-zero on the first failed assertion.

## Release notes

### Windows

Requires VC2022 redist, included in https://aka.ms/vs/17/release/vc_redist.x86.exe

### Linux (through Wine)

Requires `winetricks vcrun2022`
