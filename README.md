# dns-warden — Ubuntu DNS Tester & Resolver Switcher (TUI)

<!-- repo-badges:start -->
<p align="center">
  <a href="https://hits.sh/github.com/power0matin/dns-warden/"><img src="https://hits.sh/github.com/power0matin/dns-warden.svg?style=flat-square&amp;label=Views&amp;labelColor=18181B&amp;color=0EA5E9&amp;logo=github" alt="Repository Views"/></a>
  <a href="https://github.com/power0matin/dns-warden/stargazers"><img src="https://img.shields.io/github/stars/power0matin/dns-warden?style=flat-square&amp;label=Stars&amp;labelColor=18181B&amp;color=F59E0B&amp;logo=github&amp;logoColor=white" alt="GitHub Stars"/></a>
  <a href="https://github.com/power0matin/dns-warden/forks"><img src="https://img.shields.io/github/forks/power0matin/dns-warden?style=flat-square&amp;label=Forks&amp;labelColor=18181B&amp;color=6366F1&amp;logo=github&amp;logoColor=white" alt="GitHub Forks"/></a>
  <a href="https://github.com/power0matin/dns-warden/issues"><img src="https://img.shields.io/github/issues/power0matin/dns-warden?style=flat-square&amp;label=Issues&amp;labelColor=18181B&amp;color=22C55E&amp;logo=github&amp;logoColor=white" alt="GitHub Issues"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/power0matin/dns-warden?style=flat-square&amp;label=License&amp;labelColor=18181B&amp;color=EF4444&amp;logo=github&amp;logoColor=white" alt="GitHub License"/></a>
</p>
<!-- repo-badges:end -->

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
