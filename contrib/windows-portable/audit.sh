#!/usr/bin/env bash
set -euo pipefail
root=${1:?directory required}
for binary in PEPEPOW_qt PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do
    file="$root/$binary.exe"
    test -f "$file"
    x86_64-w64-mingw32-objdump -f "$file" | grep -q 'architecture: i386:x86-64'
    echo "PE imports: $binary.exe"
    while IFS= read -r dll; do
        echo "  $dll"
        case "${dll,,}" in
            advapi32.dll|bcrypt.dll|comctl32.dll|comdlg32.dll|crypt32.dll|dwmapi.dll|gdi32.dll|imm32.dll|iphlpapi.dll|kernel32.dll|msvcrt.dll|ntdll.dll|ole32.dll|oleaut32.dll|rpcrt4.dll|secur32.dll|setupapi.dll|shell32.dll|shlwapi.dll|user32.dll|userenv.dll|uxtheme.dll|version.dll|winmm.dll|winspool.drv|ws2_32.dll|wtsapi32.dll|dnsapi.dll|cryptbase.dll|normaliz.dll|d3d11.dll|dxgi.dll|opengl32.dll) ;;
            *) echo "Unexpected DLL: $dll" >&2; exit 1 ;;
        esac
    done < <(x86_64-w64-mingw32-objdump -p "$file" | sed -n 's/^[[:space:]]*DLL Name: //p')
done
