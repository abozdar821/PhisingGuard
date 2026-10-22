"""Render realistic phone screenshots of text messages / emails for OCR tests."""
import textwrap
from PIL import Image, ImageDraw, ImageFont
F = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
def sms(path, sender, body, dark=False, w=1170):
    bg, fg, bub, sub = ((0, 0, 0), (235, 235, 240), (38, 38, 41), (140, 140, 150)) if dark else ((255, 255, 255), (20, 20, 25), (233, 233, 235), (130, 130, 140))
    lines = []
    for para in body.split("\n"):
        lines += textwrap.wrap(para, 34) or [""]
    h = 520 + 62 * len(lines) + 400
    img = Image.new("RGB", (w, h), bg); d = ImageDraw.Draw(img)
    f, fb, fs = ImageFont.truetype(F, 46), ImageFont.truetype(FB, 50), ImageFont.truetype(F, 34)
    d.text((60, 40), "9:41", font=fb, fill=fg)
    d.text((w // 2, 200), sender, font=fb, fill=fg, anchor="mm")
    d.text((w // 2, 330), "Text Message", font=fs, fill=sub, anchor="mm")
    d.text((w // 2, 375), "Today 9:41 AM", font=fs, fill=sub, anchor="mm")
    y0 = 430
    d.rounded_rectangle((50, y0, 50 + 900, y0 + 60 + 62 * len(lines)), radius=40, fill=bub)
    for i, ln in enumerate(lines):
        d.text((90, y0 + 30 + 62 * i), ln, font=f, fill=fg)
    d.text((w // 2, h - 120), "iMessage", font=fs, fill=sub, anchor="mm")
    img.save(path)
def email(path, frm, subject, body, w=1170):
    img = Image.new("RGB", (w, 1700), (255, 255, 255)); d = ImageDraw.Draw(img)
    f, fb = ImageFont.truetype(F, 42), ImageFont.truetype(FB, 46)
    y = 80
    d.text((60, y), "Inbox", font=f, fill=(0, 110, 230)); y += 120
    d.text((60, y), subject, font=fb, fill=(20, 20, 25)); y += 110
    d.text((60, y), f"From: {frm}", font=f, fill=(60, 60, 70)); y += 70
    d.text((60, y), "To: me", font=f, fill=(120, 120, 130)); y += 110
    for ln in textwrap.wrap(body, 44):
        d.text((60, y), ln, font=f, fill=(20, 20, 25)); y += 62
    img.save(path)
if __name__ == "__main__":
    sms("toll_light.png", "+1 (626) 555-0187", "E-ZPass: You have an unpaid toll balance of $6.99. Pay by 10/09 to avoid a $50 late fee: https://ezpass-tollpay.xyz/pay")
    sms("harris_dark.png", "69534", "Ebony, Harris&Harris-collects for STATE OF MARYLAND, CCU. Balance: $36.01 To Pay: https://harriscollect.payweb360.com/login or call 855-336-5124 Reply STOP to stop", dark=True)
    sms("lunch.png", "(703) 555-0111", "Hey! Are we still on for lunch Friday at noon? Let me know.")
    email("netflix_email.png", "Netflix <billing@netflix-account-update.com>", "Your membership is on hold",
          "We couldn't process your payment. Update your payment details within 24 hours to keep watching: http://netflix-account-update.com/billing")
    print("ok")
