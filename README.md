# dns-warden — Ubuntu DNS Tester & Resolver Switcher (TUI)

`dns-warden` یک ابزار Bash تولیدی برای Ubuntu است که:
- DNS ها را از `dns-list.txt` می‌خواند
- برای هر DNS تست ping انجام می‌دهد و بر اساس packet loss و avg latency رتبه‌بندی می‌کند
- با یک TUI حرفه‌ای (whiptail) اجازه انتخاب و اعمال DNS را می‌دهد
- با `systemd-resolved` سازگار است (تشخیص symlink /etc/resolv.conf)
- از `/etc/resolv.conf` بکاپ می‌گیرد و قابلیت restore دارد

## پیش‌نیازها
- Ubuntu 20.04+
- دسترسی root (اسکریپت در صورت امکان خودکار با sudo re-run می‌شود)
- `whiptail`
- `ping` (iputils-ping) و `getent` (libc-bin)

## اجرا (لوکال)
```bash
chmod +x dns-warden.sh
sudo ./dns-warden.sh
