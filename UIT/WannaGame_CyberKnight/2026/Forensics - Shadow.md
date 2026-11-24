# WannaGame_Cyberknight - Shadow

## Description
```
Given a disk image file. Answer all questions to gain the flag.
```

## Q1. What is the chat application used to communicate with the attacker? (telegram/discord/…)

Answer: `Pidgin`

Go to the path `evidence.ad1/root [AD1]/Users/t0mmy/AppData/Local/Microsoft/Edge/User Data/Default/History`

View URL that user accessed using `DB Browser (SQLite)`

<img width="1288" height="410" alt="image" src="https://github.com/user-attachments/assets/5305323c-07b7-4d38-b6ef-9e8fd786a694" />

User used Outlook, Thunderbird, and Pidgin. The first two applications seem to be nothing out of the ordinary. 
With the instruction https://developer.pidgin.im/wiki/ConfigurationFiles.html with storing in `./AppData/Roaming`, we examine Pidgin conversations at that place; the conversations do not look ordinary.

## Q2. At what timestamp (UTC) was Windows Defender Real-Time Protection disabled? (format: YYYY-MM-DD HH:MM:SS)

Answer: `2026-08-27 10:30:28`

Go to the path `evidence.ad1/root [AD1]/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx`.
User `Event View` on your local device to open Microsoft-Windows-Windows Defender%4Operational.evtx

After accessing https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-power-of-data-collection-rules-detect-disabling-windows-defender-real-time-p/4236540
, we know the event ID of Real-time protection being disabled is `5001`

<img width="1395" height="214" alt="yes" src="https://github.com/user-attachments/assets/49f4e5b2-cfdb-4a32-950a-c9c258f96465" />

## Q3. The first suspicious file that was executed on the machine — through which URL was it downloaded?

Answer: https://drive.google.com/file/d/1e2vVL6L9oBwoAVsaxhF_tRJE_s6_WriY/view?usp=sharing

<img width="1310" height="517" alt="image" src="https://github.com/user-attachments/assets/f0aa27c0-67e9-4d84-ab07-a76a76ac4b7f" />

## Q4. What is the attacker's real XMPP account (the one posing as "tech support")?

Answer: `supporter111@conversations.im`

<img width="1862" height="432" alt="image" src="https://github.com/user-attachments/assets/5be0c05f-7a9e-4829-af38-e167125c1c14" />

## Q5. Which remote-control tool did the attacker use to connect to the victim's machine, and what is the attacker's AnyDesk ID? (format: Tool:ID)

Answer: `AnyDesk:1355533822`

Refering to article https://medium.com/@nandakumarp/anydesk-forensics-63b43200f8ae.

## Q6. What is the full filename of the last malicious file that was executed on the machine? (format: filename.exe)

Answer: `b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe`

<img width="1898" height="554" alt="image" src="https://github.com/user-attachments/assets/5bfa3aaf-f8d6-4e85-a98a-edb3239e3c9e" />

This indicates that `b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe` was downloaded from the attacker's machine to the victim's machine
using ClipBoard

<img width="1920" height="535" alt="image" src="https://github.com/user-attachments/assets/e4df8f54-63c9-4efa-8390-13d54aed9d33" />

Examine `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` in `NTUSER.DAT` stored at `/Users/t0mmy/`. It's apparent that it's the last malicious file executed on the machine.

## Q7. Where is the persistence mechanism of that malware located? (Full file path)

Answer: `C:\Users\t0mmy\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.lnk`

Examine `/Users/t0mmy/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup` (one of the most common Windows persistence mechanisms): 

<img width="1267" height="131" alt="image" src="https://github.com/user-attachments/assets/ebc31048-66ba-407a-a192-a8ae9e32ffed" />

`b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.lnk` is a shortcut file, check what is inside

```
p$ strings b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.lnk
B6296B~1.EXE
]tr.
C:\Users\t0mmy\Desktop\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe
desktop-r9i8mf7
1SPS
```

That shortcut called `C:\Users\t0mmy\Desktop\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe` to execute. 

When we check this path on disk, it was disappear. What happened? That file was deleted? Let's check at `$Recycled Bin`

<img width="1780" height="355" alt="image" src="https://github.com/user-attachments/assets/a843efba-e987-4c27-a519-b23dc6acccd1" />

Every deleted item in Windows creates a pair with the exact same 6-character random suffix (e.g., $IXXXXXX.exe for metadata and $RXXXXXX.exe for the binary content).

Check all visible `$RXXXXXX.exe` with `VirusTotal`

Examine `$RMGB4MQ.exe`

<img width="1892" height="360" alt="image" src="https://github.com/user-attachments/assets/bb347fb9-0568-4d09-9cca-f2dd54e4c9b7" />

`$RMGB4MQ.exe` is malware, the others is not, and we know `$RMGB4MQ.exe` correspond to `C:\Users\t0mmy\Desktop\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe` because of `$IMGB4MQ.exe` content.

```
$ cat '$IMGB4MQ.exe'
�;��^�6�\C:\Users\t0mmy\Desktop\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe
```

Therefore, `C:\Users\t0mmy\Desktop\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe` is malware.

## Q8. At what timestamp (UTC) did the AnyDesk session end? (format: YYYY-MM-DD HH:MM:SS)

Answer: `2026-08-28 14:26:10`

<img width="1310" height="862" alt="image" src="https://github.com/user-attachments/assets/c64c238b-e1fe-465d-b68a-24ce17c246db" />

Final flag : `All questions answered. Well done!
W1{s1mpl3_w1nd0ws_4n6_chall3nge_hah!!!}`














