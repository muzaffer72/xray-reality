#!/bin/bash

# === KRİTİK DÜZELTME: Hata durumunda betiği durdur ===
set -e
# ====================================================

# --- !!! KULLANICI AYARLARI: VERİTABANI BİLGİLERİ !!! ---
DB_HOST="109.71.252.34"
DB_USER="onvao_vpnkurulum"
DB_PASS="005434677197"
DB_NAME="onvao_vpnkurulum"
# =======================================================


# --- 0. BAŞLANGIÇ TEMİZLİĞİ ---
echo "Eski Xray kurulumları temizleniyor..."
(apt purge xray -y || true) >/dev/null 2>&1
rm -f /usr/local/bin/xray

# --- 1. SİSTEM GÜNCELLEME VE BAĞIMLILIKLAR ---
echo "Sistem güncelleniyor ve gerekli araçlar kuruluyor..."
apt-get update
apt-get install -y ca-certificates
apt install -y jq openssl qrencode curl wget git ufw mysql-client

# --- 2. AYAR DOSYASINI İNDİRME VE TEMEL DEĞERLERİ TANIMLAMA ---
TEMPLATE_CONFIG_URL="https://raw.githubusercontent.com/muzaffer72/xray-reality/refs/heads/master/config.json"
SETTINGS_URL="https://raw.githubusercontent.com/muzaffer72/xray-reality/refs/heads/master/default.json"
CURL_TIMEOUT=15

echo "Xray TEMPLATE yapılandırması ($TEMPLATE_CONFIG_URL) indiriliyor..."
JSON_CONFIG=$(curl -sL --max-time $CURL_TIMEOUT "$TEMPLATE_CONFIG_URL")

# [Hata kontrolü ve varsayılan JSON şablonu...]
if [ $? -ne 0 ] || [ -z "$JSON_CONFIG" ]; then
    echo "UYARI: Harici config.json (şablon) çekilemedi. Betik içi varsayılan şablon kullanılıyor."
    JSON_CONFIG='{
        "inbounds": [{
            "listen": "0.0.0.0", "port": 443, "protocol": "vless",
            "settings": { "clients": [ { "id": "", "flow": "", "email": "user@example.com" } ], "decryption": "none" },
            "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "dest": "", "xver": 0, "serverNames": [""], "privateKey": "", "shortIds": [""] } }
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }'
fi

echo "ÖZEL AYARLAR ($SETTINGS_URL) indiriliyor..."
JSON_SETTINGS=$(curl -sL --max-time $CURL_TIMEOUT "$SETTINGS_URL")

if [ $? -ne 0 ] || [ -z "$JSON_SETTINGS" ]; then
    echo "UYARI: Harici default.json (özel ayarlar) çekilemedi veya boş. Varsayılan değerler kullanılacak."
    JSON_SETTINGS="{}" 
fi

# Ayarları Çekme
name=$(echo "$JSON_SETTINGS" | jq -r '.name // "Reality_Vision_uTLS_VPN"')
email=$(echo "$JSON_SETTINGS" | jq -r '.email // "user@example.com"')
port_setting=$(echo "$JSON_SETTINGS" | jq -r '.port // "null"')

if [ "$port_setting" != "null" ] && [ ! -z "$port_setting" ]; then
    port=$port_setting
    echo "Özel Ayar Portu (default.json) bulundu: $port"
else
    port=$(echo "$JSON_CONFIG" | jq -r '.inbounds[0].port')
    if [ -z "$port" ] || [ "$port" == "null" ]; then
        echo "UYARI: default.json ve config.json'da port okunamadı, varsayılan 443 kullanılıyor."
        port=443
    else
        echo "Şablon Portu (config.json) kullanılıyor: $port"
    fi
fi

# Rastgele SNI Seçimi
sni_setting=$(echo "$JSON_SETTINGS" | jq '.sni')
if [ -z "$sni_setting" ] || [ "$sni_setting" == "null" ]; then
    echo "UYARI: default.json'da SNI bulunamadı. Varsayılan 'dl.google.com' kullanılıyor."
    sni="dl.google.com"
elif [[ $(echo "$sni_setting" | jq -r 'type') == "array" ]]; then
    echo "SNI dizisi algılandı. Rastgele bir tane seçiliyor..."
    sni=$(echo "$sni_setting" | jq -r '.[]' | shuf -n 1)
    if [ -z "$sni" ]; then 
        echo "UYARI: SNI dizisi boş. Varsayılan 'dl.google.com' kullanılıyor."
        sni="dl.google.com"
    else
        echo "Rastgele Seçilen SNI: $sni"
    fi
else
    sni=$(echo "$sni_setting" | jq -r '.')
    echo "Tekli SNI (default.json) algılandı: $sni"
fi

flow="xtls-rprx-vision"
fingerprint="chrome"

# --- 3. XRAY KURULUMU ---
echo "Xray çekirdeğinin EN SON SÜRÜMÜ GitHub'dan indiriliyor ve kuruluyor..."
bash -c "$(curl -L --max-time 300 https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

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
    exit 1
fi
echo "Anahtarlar başarıyla oluşturuldu."

serverIp=$(curl -s4 https://api.ipify.org)
uuid=$($XRAY_BIN uuid)
shortId=$(openssl rand -hex 8)

# SUNUCU KONUM BİLGİSİ ALMA
echo "Sunucu konum (ülke kodu) bilgisi alınıyor..."
countryCode=$(curl -sL "http://ip-api.com/json/$serverIp?fields=countryCode" | jq -r '.countryCode')
if [ -z "$countryCode" ] || [ "$countryCode" == "null" ]; then
    echo "UYARI: Ülke kodu alınamadı. 'XX' olarak ayarlandı."
    countryCode="XX"
fi
dbLocationTag="${countryCode}-${serverIp}"
echo "Konum Etiketi (server_name) oluşturuldu: $dbLocationTag"

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
     .inbounds[0].streamSettings.realitySettings.dest = ($sni + ":443") |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$sni, ("www." + $sni)] |
     .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortId]')

echo "$NEW_JSON" | sudo tee /usr/local/etc/xray/config.json >/dev/null

# --- 4.5. YENİ: SSH PORT DEĞİŞİKLİĞİ ---
# UYARI: Bu işlemden sonra sunucuya 22 yerine 7221 portundan bağlanmanız gerekecek!
echo "SSH portu /etc/ssh/sshd_config dosyasında 7221 olarak ayarlanıyor..."
# Port 22 veya #Port 22 yazan satırı bul ve Port 7221 olarak değiştir
sed -i 's/^#?Port 22/Port 7221/' /etc/ssh/sshd_config

# Servisi yeniden başlat
echo "SSH servisi yeni port (7221) için yeniden başlatılıyor..."
systemctl restart ssh
echo "SSH servisi yeniden başlatıldı (artık 7221 portunu dinliyor olmalı)."
# ==================================

# === GÜVENLİK DUVARI (FIREWALL) AYARLARI (GÜÇLENDİRİLMİŞ) ===
echo "Güvenlik duvarı (UFW) ayarlanıyor..."

# 1. Varsayılan olarak TÜM gelen trafiği engelle (Port 80 dahil)
ufw default deny incoming
# 2. Giden trafiğe izin ver
ufw default allow outgoing

# 3. Sadece İKİ porta izin ver:
echo "UFW: Port 7221 (Yeni SSH) için izin ayarlanıyor..."
ufw allow 7221/tcp
echo "UFW: Port $port (Xray) için izin ayarlanıyor..."
ufw allow $port/tcp

# 4. Eski SSH portunu (22) temizle (Hata vermemesi için '|| true' eklendi)
ufw delete allow ssh || true
ufw delete allow 22/tcp || true

# 5. UFW'yi etkinleştir ve kuralları uygula
echo "UFW etkinleştiriliyor ve kurallar uygulanıyor..."
ufw --force enable
ufw reload
echo "✅ Güvenlik duvarı SIKILAŞTIRILDI: Sadece $port/tcp ve 7221/tcp portlarına izin verildi."
# =========================================================

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

URL="vless://$uuid@$serverIp:$port?security=reality&encryption=none&flow=$flow&pbk=$pub&fp=$fingerprint&sni=$sni&sid=$shortId&type=tcp#$dbLocationTag"

# === VERİTABANINA KAYIT (server_pool) ===
echo "--------------------------------------------------------"
echo "Sonuçlar veritabanına ('$DB_NAME') kaydediliyor..."
(mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "INSERT INTO server_pool (server_url, server_name, is_active, order_index, include_in_main_app, subscription_id, category) VALUES ('$URL', '$dbLocationTag', 1, 0, 0, NULL, 2);" && \
echo "✅ Veritabanı kaydı başarılı.") || \
echo "❌ UYARI: Veritabanına kayıt yapılamadı. (Bağlantı/SQL Hatası)"
# ========================================================


echo "--------------------------------------------------------"
echo "✅ Kurulum Tamamlandı! (SSH Port: 7221, Güvenlik Duvarı Aktif)"
echo "-------------------YENİ BAĞLANTI BİLGİLERİ----------------"
echo "UYARI: Sunucu SSH Portunuz 7221 olarak değişti!"
echo "--------------------------------GEREKLİ BİLGİLER-----------------"
echo "🔗 VLESS REALITY Bağlantı URL'si (Veritabanına da eklendi):"
echo "$URL"
echo "--------------------------------------------------------"
echo "QR Kod:"
qrencode -s 2 -t ANSIUTF8 "$URL"
echo "QR Kod görüntüsü (qr.png) oluşturuldu."
qrencode -s 50 -o qr.png "$URL"

exit 0
