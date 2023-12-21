# genpatch
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/sterrasec/genpatch/blob/master/LICENSE)

genpatch is IDA plugin that generates a python script for patching binary from `Patched Byte` on IDA Pro.
genpatch is confirmed to work on IDA Pro 7.4 and above

## Motivation
During reverse engineering, we often apply the same patch to another binary. For example, when applying patch for bypassing SSL pinning. Launching IDA Pro just to patch is cumbersome, but patching from the CUI is more convenient, it's easy to share with others who are not familiar with IDA Pro.

# Installation
Copy file `genpatch.py`, `patch_script_template.txt` to IDA Plugin folder, then restart IDA Pro to use genpatch.

- On Windows, the folder is at C:\Program Files\IDA 8.x\plugins
- On MacOS, the folder is at /Applications/IDA Pro 8.x/idaq.app/Contents/MacOS/plugins
- On Linux, the folder may be at /opt/IDA/plugins/

# How to Use
## Generate Patch Script
After applying the patch using IDA Pro, click `Edit -> Plugins -> genpatch` button.

![usage](./screenshots/usage.png)

If patch script is successfully generated, a dialog similar to following appears:

![dialog](./screenshots/dialog.png)

A Patch script is generated in the directory where the binary read on IDA Pro is located.
The name of the Patch script will be the binary you are reading with the suffix `_patch.py`.
For example, if the binary name is `a.out`, the patch script name will be `a.out_patch.py`.

## Run the generated patch script
Specify the path to the binary you wish to patch as a command line argument.

```bash
$ python foo_patch.py <target_binary_path>
```

## Patching Script Example

```python
#!/usr/bin/env python
# coding: UTF-8

import binascii
import os
import re
import sys

target_path = sys.argv[1]
target_data = None
with open(target_path, 'rb') as target_file:
    target_data = binascii.hexlify(target_file.read()).decode('utf-8')

# address: 0x100000ecb
# function name: __text: _main
# comment: Keypatch modified this from:   jz loc_100000EF6 Keypatch padded NOP to next boundary: 4 bytes
matches = re.findall('0f8425000000', target_data)
if len(matches) == 1:
    target_data = target_data.replace('0f8425000000', '752990909090')
else:
    print("Patch pattern isn't unique")
    sys.exit()

result_path = f'{target_path}_patched'
with open(result_path, 'wb') as result_file:
    if sys.version_info[0] >= 3:
        result_file.write(bytes.fromhex(target_data))
    else:
        result_file.write(target_data.decode('hex'))

print("Successfully generated patched binary to '%s'" % result_path)
```

# License
MIT License
