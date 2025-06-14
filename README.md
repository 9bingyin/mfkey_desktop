# MFKey Desktop: MIFARE Classic Key Recovery

A simple C tool for recovering MIFARE Classic keys on desktop, ported from the FlipperZero mfkey plugin.

## Usage
```bash
./mfkey_desktop <input_file> [output_file]
```
- `input_file`: Path to `.nested.log` file
- `output_file`: (optional) Output file for keys (default: `found_keys.txt`)