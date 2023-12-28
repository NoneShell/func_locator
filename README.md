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

```
python3 locator.py -f rut_getIfinfo -r ./squash-rootfs -b ./squash-rootfs/bin/httpd
  [*]: Checking httpd
  [+]: Found 22 libraries in rootfs
  [*]: Checking 22 / 22 libnanoxml.so                 

  [+]: Done
      [+]: Found rut_getIfinfo in libcms_core.so

python3 locator.py -f rut_getIfinfo -r ./squash-rootfs                             
  [!]: Binary is not provided, checking all libraries in rootfs
  [+]: Found 54 libraries in rootfs
  [*]: Checking 54 / 54 libebt_mark_m.so              

  [+]: Done
      [+]: Found rut_getIfinfo in libcms_core.so
```

## required
- r2pipe: testd on 1.8.4

```
pip install r2pipe
```
## how it works
Use r2pipe to call Radare2 to analyze the dynamic link libraries in rootfs and obtain all exported functions, and then compare it with the given function.