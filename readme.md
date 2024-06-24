# Trojan.Win64.Callisto

Callisto is a basic demonstration of a true shellcode. It is a program written in MASM64/UASM assembly implementing a reverse shell over TCP.

## Building

First, [install UASM64](https://www.terraspace.co.uk/uasm256_x64.zip) and add it to your path. Next, ensure you have `nmake` or `make` installed, and then:

```
# For nmake
nmake -f makefile

# For make
make all
```

This repo includes the Windows SDK `.lib` files for linking, but they may become out-of-date over time. If encountering linking or runtime errors, please try linking against latest copies from the Windows SDK.
