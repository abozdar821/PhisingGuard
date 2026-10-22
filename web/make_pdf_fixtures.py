"""Build Gmail-style 'Print' PDFs (Chromium, like Gmail's own print) for the PDF-reading tests. Fake identity only."""
import os, sys
from playwright.sync_api import sync_playwright
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "files")
CSS = """body{font-family:'DejaVu Sans',sans-serif;font-size:13px;margin:24px;width:740px}
.logo{font-size:20px;color:#666}.subj{font-size:17px;font-weight:bold;margin-top:18px;width:560px}.cnt{font-size:11px;color:#777}
.from{display:flex;justify-content:space-between;margin-top:14px}.mono{font-family:'DejaVu Sans Mono',monospace}
.box{margin:18px 60px}.btn{display:inline-block;background:#1a73e8;color:#fff;padding:8px 18px;border-radius:4px;text-decoration:none}"""
def page(subject, sender_html, date, extra_hdr, body_html):
    return f"""<!doctype html><meta charset=utf-8><style>{CSS}</style><div class=logo>Gmail</div>
<div class=subj>{subject}</div><div class=cnt>1 message</div>
<div class=from><span>{sender_html}</span><span>{date}</span></div>{extra_hdr}<div>To: jlee4817.mail@gmail.com</div>
<div class=box>{body_html}</div>"""
CLOUD = page("jlee4817.mail, Your Cloud Account has been locked on 10-20-2026. Your photos and videos will be removed! .",
  "<b>𝗣aym<span class=mono>𝗲</span>nt_Declin𝗲d</b> &lt;jlee4817.mail.5804@ycmoggbfves.event-manager.hiartomaro.my.id&gt;",
  "Tue, Oct 20, 2026 at 19:46", "",
  """<h3>Payment Issue - Cloud Storage</h3><p>Dear User,</p><p>We encountered an issue while attempting to renew your Cloud Storage subscription.</p>
  <p>Unfortunately, your payment method has expired. To ensure your Cloud continues without interruption, please update your payment details.</p>
  <p>96% Storage Used</p><p>Your ﬁles are safe for now, but may be deleted if the cloud is not refreshed. Always use our oﬃcial website.</p>
  <p>This special oﬀer expires in 4 minutes et 39 seconds</p>
  <p><a class=btn href="https://storage.googleapis.com/betweenthemiseasy/trustedbycommunities.html#4qgMnm253932bPIU">Update Payment Details</a></p>
  <p><a href="https://storage.googleapis.com/betweenthemiseasy/trustedbycommunities.html#5DjrLE253932VjyD">Unsubscribe</a></p>""")
RECEIPT = page("Trailhead Biosystems Form Submission", "<b>Trailhead Biosystems</b> &lt;hello@trailbio.com&gt;", "Mon, Oct 19, 2026 at 14:51",
  "<div>Reply-to: hello@trailbio.com</div>",
  """<p>Hello Jordan,</p><p>Thank you for ﬁlling out the Trailhead Biosystems online contact form.</p>
  <p>You can log into the system at the link below:</p><p><a href="https://go.trailbio.com/e3t/Ctc/I9+113/d4GKvt04/MWrs--Qk764VMNdXh6grZXRW5g6HvJ5WkyLHN7dHCv23lYM-W6N1vHY6lZ3pXW58c3983l-9jBW97Y2k55dWQFMW1zrR_g1kS5T7W8Cpj308JnxQtW2QrTbg7TBYMRW27JXQv3yzX52W1TJh-b2TQlbHW7lwTmG3hzdGvW8Q_HM87txfXPW19GX5S8x">https://go.trailbio.com/tickets-view</a></p>
  <p>Best,<br>The Trailhead Team</p><p><a href="https://go.trailbio.com/hs/preferences-center/en/direct?data=W2nXS-N30h-MwW4rFt_L34yL58W3VP8KQ4r72fwW4klYB73Fd1dDW45QpFs24-nXVW2KFfrs2RMl0fW3S-pzx3JRpd9W1VytzP1QjfkvW2HDGkk38cS9jW4tzx2Y2YPHGBW2v-yJh3D_dBmW1QCWFZ2vCZrbW2t7z7g2qQ">Unsubscribe</a></p>""")
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page()
    for name, html in (("gmail_cloud_scam.pdf", CLOUD), ("gmail_trailhead_receipt.pdf", RECEIPT)):
        pg.set_content(html)
        pg.pdf(path=os.path.join(OUT, name), format="Letter", print_background=True)
        print("wrote", name)
    b.close()
