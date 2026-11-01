"""Builds the document fixtures in tests/files (run once; the outputs are committed).
Needs: pillow, matplotlib, reportlab, python-docx."""
import io, os
from PIL import Image, ImageDraw, ImageFont
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
MSG = ["USPS: Your package is on hold due to", "an unpaid shipping fee of $1.99.", "Pay now to avoid return:",
       "https://usps-redelivery-fee.top/pay"]

def message_png(w=900):
    f = ImageFont.truetype(FONT, 34); h = 120 + 56 * len(MSG)
    im = Image.new("RGB", (w, h), "white"); d = ImageDraw.Draw(im)
    d.rounded_rectangle((30, 40, w - 30, h - 30), 28, fill=(233, 233, 235))
    for i, ln in enumerate(MSG): d.text((60, 70 + 56 * i), ln, fill="black", font=f)
    b = io.BytesIO(); im.save(b, "PNG"); return b.getvalue()

def chart_png():
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 3.2), dpi=110)
    ax.bar(["Jan", "Feb", "Mar", "Apr", "May", "Jun"], [20, 35, 30, 50, 45, 60], color="#4c72b0")
    ax.set_yticks([0, 20, 40, 60]); ax.set_title("Monthly deliveries")
    b = io.BytesIO(); fig.savefig(b, format="png", bbox_inches="tight"); plt.close(fig); return b.getvalue()

def chart_and_message_png():
    c = Image.open(io.BytesIO(chart_png())).convert("RGB"); m = Image.open(io.BytesIO(message_png(c.width))).convert("RGB")
    im = Image.new("RGB", (c.width, c.height + m.height), "white"); im.paste(c, (0, 0)); im.paste(m, (0, c.height))
    b = io.BytesIO(); im.save(b, "PNG"); return b.getvalue()

def write(name, data):
    open(os.path.join(HERE, name), "wb").write(data); print(name, len(data))

write("chart_and_message.png", chart_and_message_png())
# scanned PDF: one page that is only a picture
b = io.BytesIO(); Image.open(io.BytesIO(message_png())).convert("RGB").save(b, "PDF", resolution=110); write("scanned_message.pdf", b.getvalue())
# PDF with text plus a pasted screenshot, a chart and a tiny logo
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
b = io.BytesIO(); c = canvas.Canvas(b, pagesize=A4)
c.setFont("Helvetica", 12); c.drawString(60, 790, "Hi, my mum forwarded me this text. Is it real?"); c.drawString(60, 772, "Thanks, Sam")
c.drawImage(ImageReader(io.BytesIO(chart_png())), 60, 520, width=420, height=190)
c.drawImage(ImageReader(io.BytesIO(message_png())), 60, 300, width=450, height=150)
logo = Image.new("RGB", (40, 40), (200, 30, 30)); lb = io.BytesIO(); logo.save(lb, "PNG"); c.drawImage(ImageReader(lb), 500, 780, width=30, height=30)
c.showPage(); c.save(); write("pasted_screenshot.pdf", b.getvalue())
# Word document: text, a link whose address is hidden, a pasted screenshot and a chart
import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
d = docx.Document(); d.add_paragraph("Dear customer, your account needs attention. Please review the message below and click here to confirm your details.")
p = d.add_paragraph(); rid = d.part.relate_to("https://paypal-konto-verifizierung.net/login", RT.HYPERLINK, is_external=True)
h = OxmlElement("w:hyperlink"); h.set(qn("r:id"), rid); r = OxmlElement("w:r"); t = OxmlElement("w:t"); t.text = "Confirm now"; r.append(t); h.append(r); p._p.append(h)
d.add_picture(io.BytesIO(message_png()), width=docx.shared.Inches(5)); d.add_picture(io.BytesIO(chart_png()), width=docx.shared.Inches(5))
b = io.BytesIO(); d.save(b); write("account_notice.docx", b.getvalue())
