Statement: [here](https://drive.google.com/drive/folders/1jKuvDrzLHvQ_wgcKewByXHO6Aas1OkTy)

The `description.txt` shows below: 
```bash
- Category: Forensics
- Challenge Name: Free Flag on Network
- Author: KetSoSad
- Score: 100
- Difficult: Easy
- Description:
Reverse free flag!
Reverse free flag!
Reverse free flag!
```

After we open `challenge.pcap`, we can examine some files transferred in the `export objects` menu. We download all of them.

<img width="852" height="632" alt="image" src="https://github.com/user-attachments/assets/62139bb7-6d01-4b2d-a31a-e7111568a4e6" />

When we try opening `flag0.txt`, we'll see on the third line that it's a Base64 string; then we try decoding it.
```bash
--e37ba8dcb728de3ae6d9f51b583984e5
Content-Disposition: form-data; name="file"; filename="flag0.txt"

AEAE5IAAAAAgAnJAAAAAEAE5IAAAAAgAnJAAAAAEAEXIAAAAAB/xP/akAAAAAM+f/kln61rbLa7PZye08Zrr7dLf/Xd4+5VuftRvmFgYGB8LCwsDAwMLCwMD4WFZYGBgSXmZgTO8lgYWFhYGFhYWF+A32zbcsC/d7V54VEFESRdTAAB4H2beAXQSAAB0EgAAc1lIcAkAAAAFYfwLj7EAAEFNQWcEAAAA6RzOrgBCR1JzAQAAADGtRKEAAAAGCOICAACABAAAUkRISQ0AAAAKGgoNR05QiQ==
--e37ba8dcb728de3ae6d9f51b583984e5--

```
As we can see, at the end of the hexdump of that decoded base64 string, it's a PNG signature, but it's reversed.

<img width="782" height="376" alt="image" src="https://github.com/user-attachments/assets/8ce8bcdb-269c-4d25-96f8-5a620b09c330" />

Finally, we decode the base64 string in each flag file, reverse each of them, and concatenate them to get a PNG flag file. Using below code to do that.

```python
import base64

with open("ans.png", "wb") as f:
    res = b''
    for i in range(100):
        with open(f"flag{i}.txt", "r") as g:
            tmp = base64.b64decode(g.read().splitlines()[3].strip())
            res = res + tmp[::-1]

    f.write(res)
```
Flag: 
<img width="1152" height="738" alt="image" src="https://github.com/user-attachments/assets/03bf27a1-e0f5-4077-99c3-603a0db42656" />

