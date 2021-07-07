# ENC Decrypter

Python script for decrypting enc and data files in apple hardware diagnostics

__Required Python Modules:__
```
numpy
pycryptodome
```

__Usage:__
```
decrypt.py file_to_decrypt output_file round_option
Example 1: decrypt.py Mac-9F18E312C5C2BF0B.enc dump.lua -r
Example 2: decrypt.py diags.enc dump.bin -d
Example 3: decrypt.py data Devices.json -r
```
There are only two round options, '-r' and '-d'. '-r' = Regular, and is used for almost everything. '-d' = diags.enc, and is specifically for 
'diags.enc', as it requires it's own round calculation of '0x7E'.

Note: SMART is another file that doesn't decompress properly. It's 83kb and doesn't exactly follow the same process, as it exceeds the current function.
Storage.efi also has its own decrypt / decode functions that handle this (go figure). But the file can be expanded with some tweeking. Manually set filesize 
and rounds to 0x142FB and disable terminator bit. Then run the script with '-r'. Watch the output size of the dumped file. Once it reaches 83kb, you can 
ctrl + c to kill the process. I'll work on a better implementation that will handle all this.

__AST2 Diagnostics URL:__

The diagnostics URL is stored in the diags.enc file located in the Support folder of the diagnostics. Once decrypted, the URL address can be altered.
It requires a DNS compatible address. It doesn't like numerical IP's. If running locally, use something like nmap or check under the sharing settings 
on your mac to acquire your local DNS name.

Example:
```
Billys-MacBook-Air.local
billybobsMacBookPro.lan
```

Once diags.enc has been altered, make sure it retains its original name 'diags.enc', and replace the original encrypted diags.enc with the newly
decrypted and altered diags.enc.

It appreas that the diags.efi application uses the same EFI protocols to load all files. It just does a header scan to check for encryption. All
encrypted files follow the same format. All begin with ABBACDDCEFFE1221 Followed by the filsize of the enc file minus the header. If this is detected, 
it initiates the decryption and then decoding processes. But if no decryption is detected, it appears to load files normally. So you are able to modify 
the 'diagnostics-url' field to any value without size restrictions as was involved in the hardcoded url patch. Modification of the url in diags.enc
