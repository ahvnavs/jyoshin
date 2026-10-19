# Installation on Each Linux Distribution

Kazeshini runs everywhere without installation: `./kazeshini`.
If you want persistent background execution supervised by systemd:

---

## 1. Debian & Ubuntu (`.deb`)
```bash
sudo dpkg -i kazeshini_0.1.0_amd64.deb
```
Or via APT repository:
```bash
curl -fsSL https://<STATIC_HOST>/apt/kazeshini.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/kazeshini.gpg
echo "deb [signed-by=/etc/apt/keyrings/kazeshini.gpg] https://<STATIC_HOST>/apt stable main" | sudo tee /etc/apt/sources.list.d/kazeshini.list
sudo apt update && sudo apt install -y kazeshini
```

---

## 2. RHEL, Rocky, Alma, CentOS & Fedora (`.rpm`)
```bash
sudo rpm -ivh kazeshini-0.1.0.x86_64.rpm
```
Or via DNF:
```bash
sudo dnf install -y kazeshini
```

---

## 3. Alpine Linux (`.apk`)
```bash
apk add --allow-untrusted kazeshini-0.1.0.apk
```

---

## 4. Arch Linux (`PKGBUILD`)
```bash
cd packaging/arch
makepkg -si
```

---

## 5. Built-in Safe Installer
Any binary can inspect and install itself with interactive approval:
```bash
sudo kazeshini install
```
And uninstall cleanly leaving nothing behind:
```bash
sudo kazeshini uninstall
```

