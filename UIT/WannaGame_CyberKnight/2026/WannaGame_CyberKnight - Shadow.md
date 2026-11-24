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









