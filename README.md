### INSTALL SCRIPT 
<pre><code>apt update && apt install -y curl wget xz-utils screen && apt install -y wget && apt install -y xz-utils && apt update && apt install -y curl wget xz-utils screen && apt install -y wget && apt install -y xz-utils && apt install -y shc && mkdir -p /etc/xdtmp && wget -q https://raw.githubusercontent.com/snaydersonly/autoscript/main/premi.sh && chmod +x premi.sh && screen -S install ./premi.sh
</code></pre>

### PERINTAH UPDATE 
<pre><code>if [[ ! -d /etc/xdtmp ]]; then mkdir -p /etc/xdtmp; fi && wget -q https://raw.githubusercontent.com/snaydersonly/autoscript/main/update.sh && chmod +x update.sh && ./update.sh</code></pre>

### OS SUPPORT
- UBUNTU 20++
- DEBIAN 10++

### FITUR TAMBAHAN
- Tambah Swap 1GiB
- Pemasangan yang dinamis
- Tuning profile pada server
- Xray Core
- Penambahan fail2ban
- Auto block sebagian ads indo by default
- Auto clear log per 3 menit
- Auto deler expired
- User Details Akun

### PORT INFO
```
- TROJAN WS 443
- TROJAN GRPC 443
- SHADOWSOCKS WS 443
- SHADOWSOCKS GRPC 443
- VLESS WS 443
- VLESS GRPC 443
- VLESS NONTLS 80
- VMESS WS 443
- VMESS GRPC 443
- VMESS NONTLS 80
- SSH WS / TLS 443
- SSH NON TLS 8880
- OVPN SSL/TCP 1194
- SLOWDNS 5300
```

### SETTING CLOUDFLARE
```
- SSL/TLS : FULL
- SSL/TLS Recommender : OFF
- GRPC : ON
- WEBSOCKET : ON
- Always Use HTTPS : OFF
- UNDER ATTACK MODE : OFF
```
