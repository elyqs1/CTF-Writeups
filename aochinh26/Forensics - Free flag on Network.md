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

When we try opening `flag0.txt`, we'll see on the third line that it's a Base64 string; then we try decoding it, 

