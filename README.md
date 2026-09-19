# Samet-akkaya

PC acilinca PowerShell penceresi geliyorsa, bu repo icindeki tarama scripti kaynagi listeler.

## Neden olur?

Windows kendi basina bos bir PowerShell acmaz. Acilista bir yerden `powershell.exe` / `pwsh.exe` / `.ps1` cagiriliyordur. En sik yerler:

1. `Win + R` → `shell:startup` (kullanici Startup klasoru)
2. `Win + R` → `shell:common startup` (tum kullanicilar)
3. Kayit defteri `Run` / `RunOnce` anahtarlari
4. Gorev Zamanlayici (logon / startup trigger)
5. PowerShell profil dosyasi (`Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`)
6. WMI event subscription veya servis

Pencere bir saniye gorunup kapanıyorsa genelde hatali bir logon scriptidir: komut patlar, pencere kalir veya flash yapar.

`EncodedCommand`, `-WindowStyle Hidden`, `DownloadString`, `Add-MpPreference -ExclusionPath` gorursen bunu normal bir uygulama guncellemesi sayma; once Defender ile tam tarama yap.

## Nasil tararsin?

Abi'nin Windows PC'sinde:

1. Bu klasordeki `scripts\Find-PowerShellStartup.cmd` dosyasina cift tikla.
2. Istersen PowerShell'i **Yonetici** olarak acip sunu calistir (Gorev Zamanlayici ve WMI daha dolu gelir):

```powershell
Set-Location <bu-repo>\scripts
.\Find-PowerShellStartup.ps1
```

3. Rapor masaustune `powershell-startup-rapor-...txt` olarak yazilir.

Script **sadece okur**; kayit silmez, gorev kapatmaz.

## Kaydi bulunca

- Startup klasorundeki `.lnk` / `.ps1` / `.bat`: tanimiyorsan sil.
- Gorev Zamanlayici: tetikleyici "At log on" / "At startup" ve eylem `powershell.exe` ise gorevi Disable et.
- Registry Run: `regedit` ile ilgili degeri silmeden once degerin tam komutunu kopyala.
- Profil dosyasi: conda / oh-my-posh / nvm satirlarini yoruma alip reboot ile dene.

Hala bulunamazsa Microsoft **Autoruns** (`Logon`, `Scheduled Tasks`, `WMI`, `Services` sekmeleri, `powershell` filtresi) en net aractir.

## Bu cloud agent ne yapabilir / yapamaz?

Bu ortam Linux. Abi'nin Windows makinesine ag uzerinden baglanilamiyor; acilis kayitlarina buradan bakmak mumkun degil. Tarama Windows'ta calismali, rapor metni paylasilirsa kayit satir satir yorumlanabilir.
