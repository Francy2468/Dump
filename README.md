# Dump

A Lua script dumper/deobfuscator for Roblox scripts.

## Output

Every dump produced by this tool includes a watermark comment at the top of the output file:

```
-- generated with catmio | https://discord.gg/cq9GkRKX2V
```

## Usage

```
lua envlogger.lua <input_file.lua> [output_file.lua] [key]
```

## Features

- Extracts global variables and their values from executed scripts
- Captures upvalues (closures) from all captured functions, including those defined as globals
- Decodes and emits the full WeAreDevs obfuscator string pool
- Detects and dumps remote calls, string constants, and deferred hooks
