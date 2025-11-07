#!/bin/bash

# Gerekli güncellemeler ve araçlar
rm /var/lib/dpkg/updates/*
dpkg --configure -a
apt install -f

# --- 1. SİSTEM GÜNCELLEME VE BAĞIMLILIKLAR ---
echo "Sistem güncelleniyor ve gerekli araçlar kuruluyor..."
sudo apt-get update
# ufw (firewall) paketini de ekliyoruz
apt install -y jq openssl qrencode curl wget git ufw

# --- 2. AYAR DOSYASINI İNDİRME VE TEMEL DEĞERLERİ TANIMLAMA ---
CONFIG_URL="https://raw.githubusercontent.com/muzaffer72/xray-reality/refs/heads/master/config.json"
JSON_CONFIG=$(curl -sL "$CONFIG_URL")

if [ $? -ne 0 ] || [ -z "$JSON_CONFIG" ]; then
    echo "UYARI: Harici config.json çekilemedi. Betik içi varsayılanlar kullanılıyor."
    JSON_CONFIG='{
        "inbounds": [{
            "listen": "0.0.0.0", "port": 443, "protocol": "vless",
            "settings": { "clients": [ { "id": "", "flow": "", "email": "user@example.com" } ], "decryption": "none" },
            "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "dest": "", "xver": 0, "serverNames": [""], "privateKey": "", "shortIds": [""] } }
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }'
fi

name=$(echo "$JSON_CONFIG" | jq -r '.name // "Reality_Vision_uTLS_VPN"')
email=$(echo "$JSON_CONFIG" | jq -r '.email // "user@example.com"')

# === KRİTİK İYİLEŞTİRME 1: RASTGELE YÜKSEK PORT ===
port=$(( RANDOM + 30000 ))
echo "Rastgele Yüksek Port Atandı: $port"

sni=$(echo "$JSON_CONFIG" | jq -r '.sni // "www.googletagmanager.com"')
flow="xtls-rprx-vision"
fingerprint="chrome"

# --- 3. XRAY KURULUMU (OTOMATİK - GITHUB ÜZERİNDEN) ---
echo "Xray çekirdeğinin EN SON SÜRÜMÜ GitHub'dan indiriliyor ve kuruluyor..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

XRAY_BIN="/usr/local/bin/xray"
if [ ! -f "$XRAY_BIN" ]; then
    echo "HATA: Xray binary dosyası ($XRAY_BIN) bulunamadı. Kurulum başarısız."
    exit 1
fi

echo "REALITY anahtarları oluşturuluyor..."
keys=$($XRAY_BIN x25519)
pk=$(echo "$keys" | grep 'Private key:' | awk '{print $3}')
pub=$(echo "$keys" | grep 'Public key:' | awk '{print $3}')
serverIp=$(curl -s4 https://api.ipify.org)
uuid=$($XRAY_BIN uuid)
shortId=$(openssl rand -hex 8)

# --- 4. JSON YAPILANDIRMASINI GÜNCELLEME ---
echo "Xray yapılandırma dosyası güncelleniyor..."

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
     .inbounds[0].settings.clients[0].flow = $flow |
     .inbounds[0].streamSettings.realitySettings.dest = ($sni + ":433") |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$sni, ("www." + $sni)] |
     .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortId]')

echo "$NEW_JSON" | sudo tee /usr/local/etc/xray/config.json >/dev/null

# === YENİ EKLENEN BÖLÜM: GÜVENLİK DUVARI (FIREWALL) AYARLARI ===
echo "Güvenlik duvarı (UFW) ayarlanıyor..."
ufw allow ssh # SSH'a izin ver (BAĞLANTI KESİLMEMESİ İÇİN KRİTİK)
ufw allow $port/tcp # Xray portuna izin ver
ufw --force enable # Güvenlik duvarını etkinleştir
ufw reload # Ayarları yeniden yükle
echo "Güvenlik duvarı $port portuna izin verecek şekilde ayarlandı."
# ==============================================================

# --- 5. XRAY'İ BAŞLATMA VE BAĞLANTI DİZESİNİ OLUŞTURMA ---
echo "Xray hizmeti yeniden başlatılıyor..."
sudo systemctl daemon-reload
sudo systemctl enable xray
sudo systemctl restart xray

if systemctl is-active --quiet xray; then
    echo "✅ Xray servisi başarıyla başlatıldı."
else
    echo "❌ HATA: Xray servisi başlatılamadı. Durumu kontrol edin: systemctl status xray"
    exit 1
fi

URL="vless://$uuid@$serverIp:$port?security=reality&encryption=none&flow=$flow&pbk=$pub&fp=$fingerprint&sni=$sni&sid=$shortId&type=tcp#$name"

echo "--------------------------------------------------------"
echo "✅ Kurulum Tamamlandı! (En Güncel Xray - Yüksek Port - Firewall Aktif)"
echo "--------------------------------GEREKLİ BİLGİLER-----------------"
echo "🔗 VLESS REALITY Bağlantı URL'si:"
echo "$URL"
echo "--------------------------------------------------------"
echo "QR Kod:"
qrencode -s 2 -t ANSIUTF8 "$URL"
echo "QR Kod görüntüsü (qr.png) oluşturuldu."
qrencode -s 50 -o qr.png "$URL"

exit 0
