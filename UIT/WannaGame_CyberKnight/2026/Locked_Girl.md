# WannaGame_2026 - Locked Girl

## Description
`Deep inside the forbidden library, two workstations were constantly communicating with each other in secret. At some point, we managed to intercept their network traffic. Can you analyze the captured communication and uncover the hidden data these two machines were trying to keep locked away?`


Bài toán cung cấp 2 file:

<img width="733" height="67" alt="image" src="https://github.com/user-attachments/assets/c0236aaa-6d73-444a-b3cf-86b590025214" />

`sslkey.log` được sử dụng để giải mã các gói tin đã bị mã hóa bởi TLS. 
Cách sử dụng: chọn `Edit > Preferences > TLS protocol` trong file pcap, browse path của file `sslkey.log`

Sau khi giải mã, sử dụng filter `http`, một trong số các `HTTP Get Request` khả nghi là `GET /qhlqpibkd1amckbb/client.zip`

<img width="1878" height="713" alt="image" src="https://github.com/user-attachments/assets/b320318a-c507-462e-903b-f630ac9883f8" />

Dựa vào HTTP response 302 (URL redirect), URL `client.zip` chuyển hướng sang `storage.filebin.net/filebin/29b1.......`

Sau khi download `client.zip` và giải nén, thu được `client_cs.dll`, `instruction.txt`.

Theo `instruction.txt`, client `192.168.247.152` mà đã gửi HTTP request khả nghi nhận được yêu cầu `contact me at 192.168.247.1:9000`. 
Qua đó thu hẹp được phạm vi mà ta cần điều tra xuống cuộc hội thoại giữa `192.168.247.1` và `192.168.247.152`

Tiếp tục phân tích `client_cs.dll` bằng `dnspy`, có được script C# sử dụng để quy định cách giao tiếp TCP từ client sang server, 
trong trường hợp này server là `192.168.247.1`

<img width="1895" height="834" alt="image" src="https://github.com/user-attachments/assets/d7eb9baa-3252-41a6-93c4-ac8452e572f6" />

Dựa vào đoạn code dưới, 2 host đã trao đổi `array` và `array2` với nhau (chưa qua mã hóa) để tạo ra `seed` phục vụ cho việc tạo `SessionKey`- được sử dụng chung giữa 2 host trong việc mã hóa gói tin.
`SessionKey` vừa đóng vai trò mã hóa vừa giải mã gói tin (bởi vì đây là thuật toán AES mã hóa đối xứng)

```C#
byte[] array = new byte[8];
RandomNumberGenerator.Fill(array);
CS$<>8__locals1.stream.Write(array, 0, array.Length);
byte[] array2 = new byte[8];
Program.ReadFull(CS$<>8__locals1.stream, array2);
byte[] array3 = new byte[8];
for (int i = 0; i < 8; i++)
{
  array3[i] = (array[i] ^ array2[i]);
}
if (BitConverter.IsLittleEndian)
{
  Array.Reverse<byte>(array3);
}
ulong seed = BitConverter.ToUInt64(array3, 0);
byte[] array4 = new byte[32];
RandomNumberGenerator.Fill(array4);
CS$<>8__locals1.sessionKey = SHA256.HashData(array4);
byte[] data = Program.EncryptECB(Program.GenerateECBKey(seed), CS$<>8__locals1.sessionKey);
Program.WriteMessage(CS$<>8__locals1.stream, data);
byte[] bytes = Program.ReadMessage(CS$<>8__locals1.stream);
```

TCP stream giữa 2 host
<img width="989" height="125" alt="Screenshot 2026-11-17 214154" src="https://github.com/user-attachments/assets/804b51d8-b4ce-4532-aa7b-62fa80a15ba9" />
<img width="40%" alt="image" src="https://github.com/user-attachments/assets/9da3a594-f8eb-48df-9588-3361122f6293" />

Ta có thể có giá trị của `SessionKey` (bằng cách giải mã bằng `AES_ECB`) để có thể giải mã đoạn giao tiếp sau đó. Đoạn code sau để lấy giá trị `SessionKey`

```python
from Crypto.Cipher import AES
import base64

def GenerateECBKey(seed: int) -> bytearray:
    num = seed
    num2 = 1103515245
    num3 = 12345
    num4 = 2**31
    array = bytearray(16)

    for i in range(16):
        num = (num2 * num + num3) % num4
        array[i] = (num >> 16) & 0xFF
    return array

def decrypt_ecb(key: bytearray, ciphertext: bytearray) -> bytearray:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

array = bytearray.fromhex("44ad838a9c5b6a8e")
array2 = bytearray.fromhex("15f4c24b7bb9a73f")
array3 = bytearray(array[i] ^ array2[i] for i in range(8))


seed = int.from_bytes(array3, byteorder="big") # big endian
data = bytearray.fromhex("9738cd8617b997255230ef47b7b4aa5af3cb4c0c31052f8ff11cdd930315d1fb") # encrypted_session_key
session_key = decrypt_ecb(GenerateECBKey(seed), data)
```

Sau khi quá trình trên hoàn tất, 2 host trao đổi thông tin bị mã hóa `AES_GCM` với nhau, gói tin lúc này có dạng `nonce|ciphertext|tag`. Ta cần giải mã `ciphertext`. Sử dụng `tshark` để bắt các gói tin này

<img width="984" height="234" alt="image" src="https://github.com/user-attachments/assets/bf0e6577-c3bc-4179-b344-dfbb253f1be8" />


```bash
$ tshark -r challenge.pcapng -Y "ip.addr=192.168.247.1&&ip.addr == 192.168.247.152&&frame.len>=91&&frame.len<=123" -T field -e data.data
```

```python
def decrypt_gcm(key: bytearray, payload: bytearray) -> bytearray:
    nonce = payload[:12]
    ciphertext = payload[12:-16]
    tag = payload[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

Ciphertext sau khi giải mã:
```bash
54n43: hi
r31mu: hi
54n43: anything interesting?
r31mu: yeah
r31mu: hang on let me send ya
54n43: okay
54n43: wow what is this?
r31mu: decode base64 and read it yourself
r31mu: the password I have told ya before
54n43: okay
54n43: yeah you remind me
54n43: gotta learn windows internal soon
54n43: oops gotta go
54n43: see ya
r31mu: bye
```
File gửi đi thường chia ra thành các packet có số lượng byte lớn. Dựa vào cuộc hội thoại trên, ta biết được packet thuộc File Zip cần decrypt `AES_GCM`, sau đó base64 decode.

Bắt các gói tin của FIle Zip đó:

```bash
$ tshark -r challenge.pcapng -Y "ip.addr==192.168.247.1&&ip.addr == 192.168.247.152&&frame.len>=598" -T fields -e data.data > conv.txt
```

```python
with open("conv.txt", "r") as f:
    data = "".join(f.read().splitlines()).strip()
with open("secret.zip", "wb") as f:
    f.write(base64.b64decode(decrypt_gcm(session_key, bytearray.fromhex(data)).decode("utf-8")))
```

Khi thử giải nén `secret.zip`, nó yêu cầu password. Vậy kiếm đâu ra :))?
Ta thấy được nó đã bị mã hóa `ZipCrypto Store`, có cách để bẻ khóa?

Tìm hiểu bài viết này để nắm cách crack [ZipCrypto plaintext attack](https://wiki.anter.dev/misc/plaintext-attack-zipcrypto/#the-problem-with-zipcrypto-deflate)

Làm như hướng dẫn với plain.bin:
`00000000: 8950 4e47 0d0a 1a0a 0000 000d            .PNG........`

Thu được flag:

<img width="30%" alt="hello" src="https://github.com/user-attachments/assets/c5c5d23b-2dfa-459b-bc5e-011cb4bd8898" />











