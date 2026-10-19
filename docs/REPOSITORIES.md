# Static Package Repositories Guide (APT & RPM)

Kazeshini packages can be hosted on any static HTTP host, AWS S3, Cloudflare Pages, or local web server with signed GPG repository metadata.

---

## 1. Hosting Requirements
- A static file host serving over HTTPS.
- An exportable GPG signing key pair:
  - Private key for signing `Release` (APT) and `repomd.xml` (RPM).
  - Public key (`kazeshini.gpg` or `RPM-GPG-KEY-kazeshini`) published at the repository root.

---

## 2. Generating the Debian/Ubuntu APT Repository

Run the generator script with your build output:
```bash
./scripts/build-apt-repo.sh ./dist/apt <GPG_KEY_ID>
```

This creates the standard Debian repository directory tree:
```
dist/apt/
├── dists/
│   └── stable/
│       ├── InRelease          # Clearsigned repository metadata
│       ├── Release            # Unsigned metadata
│       ├── Release.gpg        # Detached GPG signature
│       └── main/
│           ├── binary-amd64/
│           │   ├── Packages
│           │   └── Packages.gz
│           └── binary-arm64/
│               ├── Packages
│               └── Packages.gz
└── pool/
    └── main/
        └── *.deb
```

### Client Installation (Debian/Ubuntu):
```bash
curl -fsSL https://<YOUR_STATIC_HOST>/apt/kazeshini.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/kazeshini.gpg
echo "deb [signed-by=/etc/apt/keyrings/kazeshini.gpg] https://<YOUR_STATIC_HOST>/apt stable main" | sudo tee /etc/apt/sources.list.d/kazeshini.list
sudo apt update && sudo apt install -y kazeshini
```

---

## 3. Generating the RHEL/Fedora/Rocky RPM Repository

Run the generator script:
```bash
./scripts/build-rpm-repo.sh ./dist/rpm <GPG_KEY_ID>
```

This creates the standard RPM repository layout:
```
dist/rpm/
├── RPM-GPG-KEY-kazeshini
├── x86_64/
│   ├── repodata/
│   │   ├── repomd.xml
│   │   └── repomd.xml.asc
│   └── *.rpm
└── aarch64/
    ├── repodata/
    │   ├── repomd.xml
    │   └── repomd.xml.asc
    └── *.rpm
```

### Client Installation (RHEL/Fedora/CentOS):
```bash
sudo cat << EOF > /etc/yum.repos.d/kazeshini.repo
[kazeshini]
name=Kazeshini Server Truth Engine
baseurl=https://<YOUR_STATIC_HOST>/rpm/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://<YOUR_STATIC_HOST>/rpm/RPM-GPG-KEY-kazeshini
EOF
sudo dnf install -y kazeshini
```

