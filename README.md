<h1 align="center">dns-warden — Ubuntu DNS Tester &amp; Resolver Switcher (TUI)</h1>

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
```

## Contact

**Matin Shahabadi**

- Website: [matinshahabadi.ir](https://matinshahabadi.ir)
- Email: [me@matinshahabadi.ir](mailto:me@matinshahabadi.ir)
- GitHub: [power0matin](https://github.com/power0matin)
- LinkedIn: [matin-shahabadi](https://www.linkedin.com/in/matin-shahabadi)

<p align="center">
  <b>If this helped you, consider giving it a star!</b><br>
  <sub>Your support keeps the project alive and helps others find it.</sub>
</p>

<!-- Copy-paste in your Readme.md file -->
<p align="center">
  <a href="https://next.ossinsight.io/widgets/official/analyze-repo-stars-history?repo_id=1152254615" target="_blank" style="display: block" align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://next.ossinsight.io/widgets/official/analyze-repo-stars-history/thumbnail.png?repo_id=1152254615&amp;image_size=auto&amp;color_scheme=dark" width="721" height="auto">
      <img alt="Star History of power0matin/dns-warden" src="https://next.ossinsight.io/widgets/official/analyze-repo-stars-history/thumbnail.png?repo_id=1152254615&amp;image_size=auto&amp;color_scheme=light" width="721" height="auto">
    </picture>
  </a>
</p>

<!-- Made with [OSS Insight](https://ossinsight.io/) -->

<p align="center">
  Created by <a href="https://github.com/power0matin">power0matin</a>
</p>
