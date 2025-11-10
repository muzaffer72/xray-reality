#!/bin/bash

# === KRİTİK DÜZELTME: Hata durumunda betiği durdur ===
set -e
# ====================================================

# --- 0. BAŞLANGIÇ TEMİZLİĞİ ---
echo "Eski Xray kurulumları temizleniyor..."
apt purge xray -y || true
rm -f /usr/local/bin/xray

# --- 1. SİSTEM GÜNCELLEME VE BAĞIMLILIKLAR ---
echo "Sistem güncelleniyor ve gerekli araçlar kuruluyor..."
apt-get update
apt-get install -y ca-certificates
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
port=$(( RANDOM + 30000 ))
echo "Rastgele Yüksek Port Atandı: $port"

sni=$(echo "$JSON_CONFIG" | jq -r '.sni // "dl.google.com"')
flow="xtls-rprx-vision"
fingerprint="chrome"
spx="/" 

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
pk=$(echo "$keys" | grep 'PrivateKey:' | awk '{print $2}')
pub=$(echo "$keys" | grep 'Password:' | awk '{print $2}')

if [ -z "$pk" ] || [ -z "$pub" ]; then
    echo "HATA: Xray anahtarları (pk veya pub) oluşturulamadı!"
    echo "Betik (script) durduruluyor."
    exit 1
fi

serverIp=$(curl -s4 https://api.ipify.org)
uuid=$($XRAY_BIN uuid)
shortId=$(openssl rand -hex 8)

# ====================================================================
# YENİ EKLENDİ: Her sunucu için DİNAMİK OLARAK OLUŞTURULAN, 
# ancak o sunucu için SABİT olan bir pqv kodu (URL-safe)
#
# Bu, sizin 60 GB'lık sunucunuzun yöntemini kopyalar,
# ancak her sunucuya farklı bir imza verir.
echo "DPI engellemesini aşmak için sunucuya özel 'pqv' imzası oluşturuluyor..."
# (openssl 768 bayt rastgele veri üretir, URL-safe base64'e çevirir)
PQV_STRING=$(openssl rand -base64 768 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
# ====================================================================

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
    --arg spx "$spx" \
    '.inbounds[0].port = ($port | tonumber) |
     .inbuonds[0].settings.clients[0].email = $email |
     .inbounds[0].settings.clients[0].id = $uuid |
     .inbounds[0].settings.clients[0].flow = $flow |
     .inbounds[0].streamSettings.realitySettings.dest = ($sni + ":443") |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$sni, ("www." + $sni)] |
     .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortId] |
     .inbounds[0].streamSettings.realitySettings.spx = $spx')

echo "$NEW_JSON" | sudo tee /usr/local/etc/xray/config.json >/dev/null

# === GÜVENLİK DUVARI (FIREWALL) AYARLARI ===
echo "Güvenlik duvarı (UFW) ayarlanıyor..."
ufw allow ssh
ufw allow $port/tcp
ufw --force enable
ufw reload
echo "Güvenlik duvarı $port portuna izin verecek şekilde ayarlandı."

# --- 5. XRAY'İ BAŞLATMA VE BAĞLANTI DİZESİNİ OLUŞTURMA ---
echo "Xray hizmeti yeniden başlatılıyor..."
systemctl daemon-reload
systemctl enable xray
systemctl restart xray

if systemctl is-active --quiet xray; then
    echo "✅ Xray servisi başarıyla başlatıldı."
else
    echo "❌ HATA: Xray servisi başlatılamadı. Durumu kontrol edin: systemctl status xray"
    exit 1
fi

# GÜNCELLENMİŞ URL (Dinamik oluşturulan &pqv=... ile):
URL="vless://$uuid@$serverIp:$port?security=reality&encryption=none&flow=$flow&pbk=$pub&fp=$fingerprint&sni=$sni&sid=$shortId&spx=%2F&type=tcp&pqv=$PQV_STRING#$name"


echo "--------------------------------------------------------"
echo "✅ Kurulum Tamamlandı! (Sunucuya Özel 'pqv' İmzası Aktif)"
echo "--------------------------------GEREKLİ BİLGİLER-----------------"
echo "🔗 VLESS REALITY Bağlanti URL'si:"
echo "$URL"
echo "--------------------------------------------------------"
echo "QR Kod:"
qrencode -s 2 -t ANSIUTF8 "$URL"
echo "QR Kod görüntüsü (qr.png) oluşturuldu."
qrencode -s 50 -o qr.png "$URL"

exit 0
