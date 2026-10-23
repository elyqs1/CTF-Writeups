## Forensics - What is it

Task: [Here](https://drive.google.com/drive/folders/1jKuvDrzLHvQ_wgcKewByXHO6Aas1OkTy)

We're given a `chall.wav` file. After we try listening to that file, it appears to be Morse code.
Then, we decode them into message by Morse decoder. The result is `passwordisgoodluck`.
It seems to be a passphrase for decrypting embedded files in `chall.wav` with `steghide` tool.

`steghide extract -sf chall.wav -p "passwordisgoodluck"`

After decrypting the embedded file in WAV successfully, we have `hidden.zip`. Then we extract it.

<img width="120" height="62" alt="image" src="https://github.com/user-attachments/assets/88e8f86e-99cc-4aae-8bf3-028b9ae2032b" />

The `part1.txt` is `W1{s0m3_7h1ng5_1n`, we have one part of the flag. But if we try to extract `next2.zip`, it announces the following: <img width="358" height="160" alt="image" src="https://github.com/user-attachments/assets/e13a086a-c36a-4c95-a354-1d507a0aba47" />

So what happened? We have to try opening Hexdump of `next2.zip`. It's weird.

<img width="590" height="125" alt="image" src="https://github.com/user-attachments/assets/22dba5cc-2449-439a-92f4-d3482f82e64c" />

It looks like the hexdump is modified by swapping each pair of bytes. Because the `ZIP` file has magic bytes of `50 4B 03 04`, but in the Hexdump of `next2.zip`, it is `4B 50 04 03`.

Therefore, we need to recover that file by swapping each pair of bytes again. Below code help us to do that work.

```python
with open("next2.zip", "rb") as f:
    data = f.read()

data = bytearray(data)
for i in range(0, len(data), 2):
    data[i], data[i + 1] = data[i + 1], data[i]

with open("next2_m.zip", "wb") as f:
    f.write(data)
```
Now we extract `next2_m.zip` and we have part 2 of flag <img width="161" height="51" alt="part2" src="https://github.com/user-attachments/assets/2bd28962-59d1-4019-87a4-4474bf044b47" />



