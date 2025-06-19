# MFKey Desktop: MIFARE Classic Key Recovery

Desktop tool for recovering MIFARE Classic keys, modified to match Flipper Zero mfkey behavior.

## Usage

```bash
./mfkey_desktop <nested.log> [keys.txt] [dict_dir]
```

- `nested.log`: Input nonce file (required)
- `keys.txt`: Output for direct keys (default: found_keys.txt)  
- `dict_dir`: Directory for candidate dictionaries (default: current dir)

## Build

```bash
make
```