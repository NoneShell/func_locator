# func_locator
A simple script that helps to identify the dynamic link library to which a program's import function belongs.

## interface
```
usage: locator.py [-h] -f FUNCTION -r ROOTFS [-b BINARY]

options:
  -h, --help            show this help message and exit
  -f FUNCTION, --function FUNCTION
                        function name
  -r ROOTFS, --rootfs ROOTFS
                        rootfs path
  -b BINARY, --binary BINARY
                        binary path
```

## required
- r2pipe: testd on 1.8.4

## how it works
Use r2pipe to call Radare2 to analyze the dynamic link libraries in rootfs and obtain all exported functions, and then compare it with the given function.