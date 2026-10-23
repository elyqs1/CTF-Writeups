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

<img width="782" height="376" alt="image" src="https://github.com/user-attachments/assets/8ce8bcdb-269c-4d25-96f8-5a620b09c330" />

As we can see, at the end of the hexdump of that decoded base64 string, it's a PNG signature, but it's reversed.

Finally, we decode the base64 string in each flag file and concatenate them to get a PNG flag file. Using below code to do that.

