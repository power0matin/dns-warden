<div dir="rtl" align="right">

<h1 align="center">dns-warden</h1>

<p align="center">
  تست واقعی DNS رزولورها و تعویض امن آن‌ها روی Ubuntu
</p>

<p align="center"><a href="README.md">English</a></p>

## معرفی

`dns-warden` یک ابزار Bash تک‌فایلی با منوی تعاملی و خط فرمان است. هر رزولور موجود در لیست را مستقیم با کوئری واقعی DNS تست می‌کند، موارد سالم را رتبه‌بندی می‌کند و انتخاب شما را همراه با بکاپ خودکار اعمال می‌کند؛ بکاپ را هم می‌توانید برگردانید.

از ping (ICMP) استفاده نمی‌شود، چون بسیاری از رزولورها ping را می‌بندند ولی به DNS پاسخ می‌دهند. رتبه‌بندی بر پایهٔ پاسخ واقعی DNS است.

## امکانات

- **کوئری مستقیم DNS** روی UDP با مجموعهٔ ثابتی از دامنه‌ها؛ نرخ موفقیت و میانگین تأخیر گزارش می‌شود.
- **تست TCP:** رزولوری که روی TCP پاسخ نمی‌دهد در رتبه‌بندی جریمه می‌شود.
- **بررسی DNSSEC** با نتیجه‌های `VALIDATES`، `LIKELY_VALIDATES`، `DOES_NOT_VALIDATE`، `INCONSISTENT` و `INCONCLUSIVE` به‌همراه سیگنال جداگانهٔ AD.
- **اثرانگشت اختیاری `version.bind`** و فیلتر `--bind-only`.
- **اعمال امن:** بکاپ از `/etc/resolv.conf`، پشتیبانی از `systemd-resolved` و بازگردانی از منو.
- **گزارش جزئیات** برای هر کوئری (RCODE، پاسخ‌ها، تأخیر، فلگ AD).
- **لیست قابل‌ویرایش** شامل رزولورهای ایرانی، ISP-محور و عمومی بین‌المللی.

## پیش‌نیازها

- Ubuntu نسخهٔ ۲۰.۰۴ یا بالاتر
- `bash`، `dig` (بستهٔ `dnsutils`) و `getent`
- دسترسی root (در صورت نیاز اسکریپت خودش با `sudo` اجرا می‌شود)

</div>

```bash
sudo apt-get update && sudo apt-get install -y dnsutils
```

<div dir="rtl" align="right">

## نصب

با یک دستور، `dns-warden` نصب می‌شود و منو باز می‌شود:

</div>

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/power0matin/dns-warden/main/install.sh)
```

<div dir="rtl" align="right">

نصب‌کننده آخرین ریلیز را دانلود می‌کند، checksum از نوع SHA-256 را بررسی می‌کند، در صورت نبود `dnsutils` آن را نصب می‌کند و دستور `dns-warden` را اضافه می‌کند. بعد از آن فقط `sudo dns-warden` را اجرا کنید.

گزینه‌های نصب‌کننده بعد از دستور می‌آیند، مثلاً `--no-run`:

| گزینه | توضیح |
| --- | --- |
| `--version vX.Y.Z` | نصب یک ریلیز مشخص به‌جای آخرین ریلیز |
| `--no-run` | فقط نصب، بدون باز کردن منو |
| `--uninstall` | حذف dns-warden؛ بکاپ‌ها و گزارش‌ها حفظ می‌شوند |

### نصب دستی

آخرین ریلیز را دانلود، بررسی و اجرا کنید:

</div>

```bash
curl -fsSLO https://github.com/power0matin/dns-warden/releases/latest/download/dns-warden.sh
curl -fsSLO https://github.com/power0matin/dns-warden/releases/latest/download/dns-list.txt
curl -fsSLO https://github.com/power0matin/dns-warden/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

<div dir="rtl" align="right">

یا مخزن را کلون کنید:

</div>

```bash
git clone https://github.com/power0matin/dns-warden.git && cd dns-warden
```

<div dir="rtl" align="right">

## استفاده

</div>

```bash
sudo dns-warden                            # منوی تعاملی
sudo dns-warden --test                     # فقط تست، بدون تغییر
sudo dns-warden --test --count 2 --timeout 2
sudo dns-warden --test --bind-only
sudo dns-warden --apply 1.1.1.1 --method auto --yes
```

<div dir="rtl" align="right">

در نصب دستی یا کلون، به‌جای `sudo dns-warden` از `sudo bash dns-warden.sh` استفاده کنید.

| گزینه | توضیح |
| --- | --- |
| `--test` | اجرای تست و چاپ گزارش رتبه‌بندی‌شده |
| `--apply <ip\|host>` | اعمال یک رزولور؛ نیازمند `--yes`. نام هاست ابتدا به IP تبدیل می‌شود |
| `--method auto\|resolved\|force` | `auto` در صورت مدیریت `resolv.conf` توسط `systemd-resolved` از آن استفاده می‌کند؛ `force` فایل را بازنویسی می‌کند |
| `--count <1-5>` | تعداد کوئری برای هر دامنه (پیش‌فرض ۱) |
| `--timeout <1-10>` | مهلت هر کوئری به ثانیه (پیش‌فرض ۱) |
| `--list <path>` | استفاده از لیست رزولور دیگر |
| `--bind-only` | نمایش فقط رزولورهای دارای اثرانگشت شبیه BIND |
| `-V`، `--version` | نمایش نسخه |

بکاپ‌ها در `/var/backups/dns-warden` و گزارش‌ها در `/var/log/dns-warden` ذخیره می‌شوند. هنگام بازگردانی بکاپ از منو، حذف فایل drop-in مربوط به `systemd-resolved` که همین ابزار ساخته هم پیشنهاد می‌شود.

## لیست رزولورها

فایل `dns-list.txt` را ویرایش کنید: هر خط یک IP یا نام هاست و `#` برای کامنت. موارد لیست پیشنهادهای جامعه هستند و **تأیید یا تضمین نشده‌اند**. آدرس‌های خصوصی ISP فقط داخل شبکهٔ همان ISP کار می‌کنند. هر موردی که به آن اعتماد ندارید را حذف کنید.

## نکات

- تست، نام دامنه‌های کوئری‌شده را به اپراتور هر رزولور نشان می‌دهد.
- نتیجه به مسیر شبکهٔ همان ماشین بستگی دارد؛ سرور خارج از ایران نتیجهٔ ISPهای ایرانی را بازتولید نمی‌کند.
- پروب‌های DNSSEC و اثرانگشت نشانگرند و ممیزی امنیتی نیستند.
- DNS آی‌پی عمومی شما را عوض نمی‌کند و محدودیت‌های مبتنی بر IP را دور نمی‌زند.
- `--test` هرگز تنظیمات DNS را تغییر نمی‌دهد.

## توسعه

</div>

```bash
bash -n dns-warden.sh install.sh
shellcheck -S warning dns-warden.sh install.sh tests/*.sh
bash tests/test-dnssec-classification.sh
bash tests/test-apply-target.sh
```

<div dir="rtl" align="right">

## مجوز

[MIT](LICENSE) © [Matin Shahabadi](https://github.com/power0matin)

</div>
