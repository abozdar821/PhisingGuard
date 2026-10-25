// The phone version's WhatsApp chat-export reader (.txt and iPhone .zip), run in Node 18+.
const fs = require("fs"), path = require("path"), zlib = require("zlib");
global.window = global;
global.document = { createElement() { return {}; }, head: { appendChild() {} } };
eval(fs.readFileSync(path.join(__dirname, "filetext.js"), "utf8"));
const FT = global.FileText;
let bad = 0;
const check = (name, ok, info) => { console.log((ok ? "PASS " : "FAIL ") + name + (ok ? "" : " " + JSON.stringify(info).slice(0, 300))); if (!ok) bad++; };
const CHAT = "[10/20/26, 3:41:02 PM] Jordan Lee: ‎Messages and calls are end-to-end encrypted.\n" +
  "[10/20/26, 3:41:05 PM] +1 (213) 555-0187: Hello dear, I am Linda from the recruitment team\n" +
  "[10/20/26, 3:42:10 PM] Jordan Lee: who is this?\n[10/20/26, 3:43:00 PM] +1 (213) 555-0187: ‎image omitted\n" +
  "[10/20/26, 3:44:00 PM] +1 (213) 555-0187: Contact our receptionist on Telegram: https://t.me/amz_task_hr\nSend your name and age\n";
// a minimal .zip (one deflated entry plus a stored photo), the way an iPhone export looks
function zip(entries) {
  const parts = [], central = []; let off = 0;
  for (const [name, data, deflate] of entries) {
    const raw = Buffer.from(data), comp = deflate ? zlib.deflateRawSync(raw) : raw, nm = Buffer.from(name);
    const crc = zlib.crc32 ? zlib.crc32(raw) : 0;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(deflate ? 8 : 0, 8);
    lh.writeUInt32LE(crc >>> 0, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(deflate ? 8 : 0, 10);
    ch.writeUInt32LE(crc >>> 0, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    parts.push(lh, nm, comp); central.push(ch, nm); off += 30 + nm.length + comp.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}
(async () => {
  check("recognises an export", FT.looksLikeWhatsApp(CHAT) && !FT.looksLikeWhatsApp("Meeting at 3:30 PM: bring slides\nThanks"));
  const x = FT.parseWhatsApp(CHAT, "WhatsApp Chat with +1 (213) 555-0187.txt");
  check("sender is the other person; only their messages", x.sender === "+1 (213) 555-0187" && !x.body.includes("who is this") && !x.body.includes("omitted")
        && x.body.includes("Send your name and age") && x.chat.count === 2, x);
  const z = zip([["_chat.txt", CHAT, true], ["00000003-PHOTO.jpg", "\xff\xd8\xff", false]]);
  const c = await FT.unzipChat(z.buffer.slice(z.byteOffset, z.byteOffset + z.length));
  check("iPhone .zip export unzipped in the browser", c && c.name === "_chat.txt" && c.text === CHAT, c && c.name);
  const none = zip([["photo.jpg", "x", false]]);
  check(".zip without a chat → null", (await FT.unzipChat(none.buffer.slice(none.byteOffset, none.byteOffset + none.length))) === null);
  console.log(bad ? `${bad} chat check(s) failed` : "phone WhatsApp reader: all checks passed");
  process.exit(bad ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
