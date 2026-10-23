## Forensics - What is it

Task: [Here](https://drive.google.com/drive/folders/1jKuvDrzLHvQ_wgcKewByXHO6Aas1OkTy)

We're given a `chall.wav` file. After we try listening to that file, it appears to be Morse code.
Then, we decode them into message by Morse decoder. The result is `passwordisgoodluck`.
It seems to be a passphrase for decrypting embedded files in `chall.wav` with `steghide` tool.

`steghide extract -sf chall.wav -p "passwordisgoodluck"`
