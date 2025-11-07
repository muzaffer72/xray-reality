#!/bin/bash

# Update package index and install dependencies
rm /var/lib/dpkg/updates/*
dpkg --configure -a
apt install -f


# --- 1. SİSTEM GÜNCELLEME VE BAĞIMLILIKLAR ---
echo "Sistem güncelleniyor ve gerekli araçlar kuruluyor..."
# Temel sistem araçlarının kurulumu
sudo apt-get update
apt install -y jq openssl qrencode curl wget git

# --- 2. AYAR DOSYASINI İNDİRME VE TEMEL DEĞERLERİ TANIMLAMA ---
# Dış JSON dosyası yerine, varsayılan değerleri tanımlayarak tek bir betikte çalışmayı sağlıyoruz.
CONFIG_URL="https://raw.githubusercontent.com/muzaffer72/xray-reality/refs/heads/master/config.json"
JSON_CONFIG=$(curl -sL "$CONFIG_URL")

# Eğer dış JSON çekilemezse, varsayılan bir JSON yapısı kullanacağız.
if [ $? -ne 0 ] || [ -z "$JSON_CONFIG" ]; then
    echo "UYARI: Harici config.json çekilemedi. Varsayılan (minimal) REALITY JSON yapısı kullanılıyor."
    JSON_CONFIG='{
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    { "id": "", "flow": "", "email": "user@example.com" }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "",
                    "xver": 0,
                    "serverNames": [""],
                    "privateKey": "",
                    "shortIds": [""]
                }
            }
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }'
fi

# Değişkenleri tanımlama veya JSON'dan okuma
name=$(echo "$JSON_CONFIG" | jq -r '.name // "Reality_Vision_uTLS_VPN"')
email=$(echo "$JSON_CONFIG" | jq -r '.email // "user@example.com"')

# === PORT DEĞİŞİKLİĞİ (SABİT PORT YERİNE RASTGELE) ===
# Orijinal satır (port=$(echo "$JSON_CONFIG" | jq -r '.port // 443')) yerine,
# 30000-62767 arası rastgele bir port atıyoruz.
port=$(( RANDOM + 30000 ))
echo "Rastgele Yüksek Port Atandı: $port"
# =======================================================

sni=$(echo "$JSON_CONFIG" | jq -r '.sni // "www.googletagmanager.com"')
flow="xtls-rprx-vision" # XTLS Vision Akışı
fingerprint="chrome"   # uTLS için en yaygın parmak izi

# --- 3. XRAY KURULUMU VE GEREKLİ ANAHTARLARI OLUŞTURMA ---
echo "Xray çekirdeği indiriliyor ve kuruluyor (v1.8.23)..."
# Xray'in başarılı kurulduğundan emin olmak için güncel versiyon kontrolü
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version v1.8.23

echo "REALITY anahtarları oluşturuluyor..."
keys=$(/usr/local/bin/xray x25519)
pk=$(echo "$keys" | grep 'Private key:' | awk '{print $3}')
pub=$(echo "$keys" | grep 'Public key:' | awk '{print $3}')
serverIp=$(curl -s4 https://api.ipify.org) # Güvenilir IP servisi
uuid=$(/usr/local/bin/xray uuid)
shortId=$(openssl rand -hex 8)

# --- 4. JSON YAPILANDIRMASINI GÜNCELLEME (JQ KULLANARAK) ---
echo "Xray yapılandırma dosyası güncelleniyor: VLESS-XTLS-uTLS-REALITY ayarları ekleniyor..."

NEW_JSON=$(echo "$JSON_CONFIG" | jq \
    --arg pk "$pk" \
    --arg uuid "$uuid" \
    --arg port "$port" \
    --arg sni "$sni" \
    --arg email "$email" \
    --arg shortId "$shortId" \
    --arg flow "$flow" \
    '.inbounds[0].port = ($port | tonumber) |
     .inbounds[0].settings.clients[0].email = $email |
     .inbounds[0].settings.clients[0].id = $uuid |
     .inbounds[0].settings.clients[0].flow = $flow |  # <-- XTLS-Vision Flow
     .inbouds[0].streamSettings.realitySettings.dest = ($sni + ":443") |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$sni, ("www." + $sni)] |
     .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortId]')

echo "$NEW_JSON" | sudo tee /usr/local/etc/xray/config.json >/dev/null

# --- 5. XRAY'İ BAŞLATMA VE BAĞLANTI DİZESİNİ OLUŞTURMA ---
echo "Xray hizmeti yeniden başlatılıyor..."
sudo systemctl daemon-reload
sudo systemctl enable xray
sudo systemctl restart xray

# VLESS URI oluşturulması (VLESS-XTLS-uTLS-REALITY)
# uTLS kısmı URI'deki 'fp' (fingerprint) parametresi ile sağlanır.
URL="vless://$uuid@$serverIp:$port?security=reality&encryption=none&flow=$flow&pbk=$pub&fp=$fingerprint&sni=$sni&sid=$shortId&type=tcp#$name"

echo "--------------------------------------------------------"
echo "✅ Kurulum Tamamlandı! (VLESS-XTLS-uTLS-REALITY)"
echo "--------------------------------------------------------"
echo "📡 Sunucu IP: $serverIp"
echo "Port: $port"
echo "🔑 Public Key (pbk): $pub"
echo "🔗 VLESS REALITY Bağlantı URL'si:"
echo "$URL"
echo "--------------------------------------------------------"

# QR Kod üretimi
qrencode -s 2 -t ANSIUTF8 "$URL"
echo "QR Kod görüntüsü (qr.png) oluşturuldu."
qrencode -s 50 -o qr.png "$URL"

exit 0
