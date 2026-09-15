# -*- coding: utf-8 -*-
r"""
微信 4.x (Windows) 单联系人聊天记录导出
自动完成: 定位账号目录 -> HMAC 校验密钥 -> 解密 message/contact/session 库 ->
定位联系人会话 (Msg_<MD5(wxid)>) -> ZSTD 解压 -> 生成 HTML/CSV/TXT。

用法示例:
  python export_chat.py ^
      --data-root "%USERPROFILE%\Documents\xwechat_files" ^
      --key-hex c8bfa3a5... (64位hex) ^
      --target 某人 ^
      --out-dir .\outputs

依赖: pip install pycryptodome zstandard
"""
import argparse, datetime, hashlib, hmac as hmac_mod, html, os, re, sqlite3, struct, sys, tempfile, collections, csv, glob
try:
    from Crypto.Cipher import AES
except Exception:
    raise SystemExit('需要 pycryptodome: pip install pycryptodome')
try:
    import zstandard
except Exception:
    raise SystemExit('需要 zstandard: pip install zstandard')

PAGE_SZ = 4096
RESERVE = 80
TZ = datetime.timezone(datetime.timedelta(hours=8))
dctx = zstandard.ZstdDecompressor()
DATA_ROOT_CANDIDATES = [
    os.path.expandvars(r'%USERPROFILE%\Documents\xwechat_files'),
    os.path.expandvars(r'%USERPROFILE%\Documents\WeChat Files'),
    os.path.expandvars(r'%APPDATA%\Tencent\xwechat_files'),
]
DEFAULT_OUT = os.path.join(os.getcwd(), 'outputs')

# ---------------- 文件读取 (微信运行中也允许共享读) ----------------
def shared_read(path):
    import ctypes, ctypes.wintypes as w
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    h = k32.CreateFileW(path, 0x80000000, 7, None, 3, 0, None)
    if h in (-1, 0xFFFFFFFFFFFFFFFF):
        raise OSError('无法打开(被独占?): %s err=%d' % (path, ctypes.get_last_error()))
    total = ctypes.c_longlong(0)
    k32.GetFileSizeEx(h, ctypes.byref(total))
    out = bytearray()
    buf = ctypes.create_string_buffer(1 << 20)
    got = w.DWORD(0)
    while True:
        if not k32.ReadFile(h, buf, len(buf), ctypes.byref(got), None) or got.value == 0:
            break
        out += buf.raw[:got.value]
        if len(out) >= total.value:
            break
    k32.CloseHandle(h)
    return bytes(out)

# ---------------- SQLCipher 4 解密 ----------------
def derive_enc_key(key, salt):
    return hashlib.pbkdf2_hmac('sha512', key, salt, 256000, 32)

def derive_mac_key(ek, salt):
    return hashlib.pbkdf2_hmac('sha512', ek, bytes(b ^ 0x3a for b in salt), 2, 32)

def page1_hmac_ok(key, page1):
    salt = page1[:16]
    ek = derive_enc_key(key, salt)
    mk = derive_mac_key(ek, salt)
    h = hmac_mod.new(mk, page1[16:4032], hashlib.sha512)
    h.update(struct.pack('<I', 1))
    return h.digest() == page1[4032:4096]

def hmac_ok_file(key, path):
    d = shared_read(path)
    if len(d) < PAGE_SZ:
        return False
    return page1_hmac_ok(key, d[:PAGE_SZ])

def decrypt_page(ek, data, pgno):
    iv = data[PAGE_SZ - RESERVE:PAGE_SZ - RESERVE + 16]
    if pgno == 1:
        enc = data[16:PAGE_SZ - RESERVE]
        return b'SQLite format 3\x00' + AES.new(ek, AES.MODE_CBC, iv).decrypt(enc) + b'\x00' * RESERVE
    enc = data[:PAGE_SZ - RESERVE]
    return AES.new(ek, AES.MODE_CBC, iv).decrypt(enc) + b'\x00' * RESERVE

def decrypt_file(key, src, dst):
    data = shared_read(src)
    salt = data[:16]
    ek = derive_enc_key(key, salt)
    if not page1_hmac_ok(key, data[:PAGE_SZ]):
        raise ValueError('HMAC 失败(密钥不对或文件损坏): ' + src)
    n = (len(data) + PAGE_SZ - 1) // PAGE_SZ
    with open(dst, 'wb') as fo:
        for i in range(n):
            chunk = data[i * PAGE_SZ:(i + 1) * PAGE_SZ]
            if len(chunk) < PAGE_SZ:
                chunk += b'\x00' * (PAGE_SZ - len(chunk))
            fo.write(decrypt_page(ek, chunk, i + 1))

# ---------------- 内容解码 ----------------
def zdec(v):
    if isinstance(v, str):
        return v
    try:
        if v[:4] == b'\x28\xb5\x2f\xfd':
            return dctx.decompress(v)
    except Exception:
        pass
    return v

def as_text(v):
    d = zdec(v)
    if d is None:
        return ''
    if isinstance(d, bytes):
        try:
            return d.decode('utf-8', 'replace')
        except Exception:
            return ''
    return d

def strip_tags(s):
    s = re.sub(r'<[^>]*>', '', s)
    for a, b in (('&nbsp;', ' '), ('&lt;', '<'), ('&gt;', '>'), ('&amp;', '&'), ('&quot;', '"'), ('&#39;', "'")):
        s = s.replace(a, b)
    return s.strip()

def render_row(row):
    _db, lid, lt, sseq, sid, ct, mc = row
    t16 = lt & 0xFFFF
    raw = as_text(mc)
    if t16 == 1:
        return '文本', raw or ''
    if t16 == 3:
        return '图片', '[图片]'
    if t16 == 34:
        m = re.search(r'voicelength="(\d+)"', raw)
        return ('语音', '[语音 %.1f 秒]' % (float(m.group(1)) / 1000)) if m else ('语音', '[语音]')
    if t16 == 43:
        m = re.search(r'duration="?(\d+)"?', raw) or re.search(r'length="?(\d+)"?', raw)
        return ('视频', '[视频 %.1f 秒]' % (float(m.group(1)) / 1000)) if m else ('视频', '[视频]')
    if t16 == 47:
        m = re.search(r'alias="([^"]*)"', raw)
        if m and m.group(1).strip():
            return '表情', '[表情：%s]' % strip_tags(m.group(1))
        if raw and not raw.startswith('<') and len(raw) < 40:
            return '表情', raw
        return '表情', '[表情]'
    if t16 == 49:
        title = des = ''
        m = re.search(r'<title><!\[CDATA\[(.*?)\]\]></title>', raw, re.S); title = m.group(1) if m else ''
        m = re.search(r'<des><!\[CDATA\[(.*?)\]\]></des>', raw, re.S); des = m.group(1) if m else ''
        m = re.search(r'<title>([^<]*)</title>', raw, re.S); title = m.group(1).strip() if (not title and m) else title
        m = re.search(r'<des>([^<]*)</des>', raw, re.S); des = m.group(1).strip() if (not des and m) else des
        title = strip_tags(title); des = strip_tags(des)
        if '转账' in title or '收到转账' in des:
            return '转账', ('[转账] ' + des if '收到转账' in des else title)
        shown = title
        if des and des not in shown and '请点此升级' not in des and not des.startswith('如需'):
            shown = (shown + ' - ' + des) if shown else des
        return '链接/卡片', shown or '[消息卡片]'
    if t16 == 50:
        return '通话', ('[视频通话]' if ('视频' in raw or 'video' in raw.lower()) else '[语音通话]')
    if t16 == 10000:
        return '系统', strip_tags(raw) or '系统消息'
    return '其它', raw[:200] or ('[类型%d]' % t16)

HTML_TPL = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>@@TITLE@@</title><style>
body{font-family:"Microsoft YaHei",system-ui,sans-serif;max-width:860px;margin:0 auto;padding:16px;background:#f7f7f7;color:#191919}
h1{font-size:20px}.meta{color:#666;font-size:13px;line-height:1.8;margin:6px 0 4px}
.stats{background:#eef4fb;border-radius:8px;padding:8px 12px;margin:10px 0;font-size:13px;color:#2a4a6a;line-height:1.6}
.dayhead{text-align:center;color:#999;font-size:12px;margin:18px 0 8px}
.row{display:flex;flex-direction:column;margin:7px 0;align-items:flex-start}.row.right{align-items:flex-end}
.meta2{font-size:11px;color:#aaa;margin:0 4px}
.bubble{max-width:72%;padding:8px 12px;border-radius:9px;font-size:15px;line-height:1.5;word-break:break-word}
.row.left .bubble{background:#fff;border:1px solid #e4e4e4}.row.right .bubble{background:#95ec69}
.sys{text-align:center;color:#999;font-size:12px;margin:8px 0}
.footer{color:#999;text-align:center;font-size:12px;margin:28px 0 12px}
</style></head><body>
<h1>@@TITLE@@</h1><div class="meta">@@META@@</div><div class="stats">类型分布：@@STATS@@</div>
@@BODY@@<div class="footer">由本地微信数据库解密导出 · @@DATE@@ · 数据为微信本地保留的记录</div>
</body></html>"""

def build_export(rows, self_wxid, self_name, other_wxid, other_remark, other_nick, out_dir, date_tag):
    by_type = collections.Counter(); by_year = collections.Counter()
    txt_lines = []; csv_rows = []; snippets = []
    rows.sort(key=lambda x: (x[4], x[2]))  # (create_time, local_id)
    cur_day = None; day_html = ''
    for row in rows:
        _db, lid, lt, sseq, sid, ct, mc = row
        kind, content = render_row(row)
        is_self = (sid == self_wxid)
        by_type[kind] += 1
        by_year[datetime.datetime.fromtimestamp(ct, TZ).strftime('%Y')] += 1
        ts = datetime.datetime.fromtimestamp(ct, TZ).strftime('%Y-%m-%d %H:%M:%S')
        who = '我' if is_self else other_remark
        disp = content if content else ('系统消息' if kind == '系统' else '')
        txt_lines.append('%s\t%s\t%s\t%s' % (ts, who, kind, disp))
        csv_rows.append([ts, who, kind, disp])
        dstr = ts[:10]
        if cur_day != dstr:
            if day_html:
                snippets.append((cur_day, day_html))
            cur_day = dstr; day_html = ''
        bubble = html.escape(disp).replace('\n', '<br/>')
        tstr = ts[11:16]
        if kind == '系统':
            day_html += '<div class="sys">%s</div>\n' % bubble
        else:
            side = 'right' if is_self else 'left'
            day_html += ('<div class="row %s"><div class="meta2">%s %s</div>'
                         '<div class="bubble %s">%s</div></div>\n') % (side, who, tstr, side, bubble)
    if day_html:
        snippets.append((cur_day, day_html))
    total = len(rows)
    os.makedirs(out_dir, exist_ok=True)
    name = other_remark or other_nick or other_wxid
    base = os.path.join(out_dir, '%s-微信聊天记录-%s' % (name, date_tag))
    body_days = ''.join('<div class="day"><div class="dayhead">%s</div>%s</div>\n' % (d, h) for d, h in snippets)
    first = datetime.datetime.fromtimestamp(rows[0][4], TZ).strftime('%Y-%m-%d %H:%M:%S') if rows else ''
    last = datetime.datetime.fromtimestamp(rows[-1][4], TZ).strftime('%Y-%m-%d %H:%M:%S') if rows else ''
    stats = '、'.join('%s %d 条' % (k, by_type[k]) for k in sorted(by_type, key=lambda x: -by_type[x]))
    meta = ('对方：%s（昵称 %s）　本人：%s　共 %d 条消息 · %d 天<br/>'
            '时间范围：%s 至 %s') % (other_remark or other_wxid, other_nick or '-', self_name or self_wxid,
                                     total, len(snippets), first, last)
    page = (HTML_TPL.replace('@@TITLE@@', '与「%s」的微信聊天记录' % (other_remark or other_wxid))
            .replace('@@META@@', meta).replace('@@STATS@@', stats)
            .replace('@@BODY@@', body_days).replace('@@DATE@@', date_tag))
    open(base + '.html', 'w', encoding='utf-8').write(page)
    open(base + '.txt', 'w', encoding='utf-8').write('\n'.join(txt_lines) + '\n')
    with open(base + '.csv', 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f); w.writerow(['时间', '发送人', '类型', '内容']); w.writerows(csv_rows)
    return base, total

def query(sql, path, args=()):
    con = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
    try:
        cur = con.cursor(); cur.execute(sql, args)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        return cols, rows
    finally:
        con.close()

def find_account_dirs(data_root):
    out = []
    for name in os.listdir(data_root):
        p = os.path.join(data_root, name)
        if os.path.isdir(p) and os.path.isdir(os.path.join(p, 'db_storage')):
            out.append(p)
    return out

def main():
    ap = argparse.ArgumentParser(description='导出微信4.x本地某联系人的聊天记录')
    ap.add_argument('--data-root', help='微信数据根目录(包含 wxid_xxx_24bb 账号文件夹)。缺省时自动搜索常用位置')
    ap.add_argument('--key-hex', help='64位hex数据库密钥; 或 --key-file 指定含密钥的文本文件')
    ap.add_argument('--key-file')
    ap.add_argument('--target', help='联系人备注/昵称, 例如 某人')
    ap.add_argument('--target-wxid', help='或直接给联系人 wxid')
    ap.add_argument('--self-wxid', help='本人wxid(缺省从账号目录名推导)')
    ap.add_argument('--self-name', default='我')
    ap.add_argument('--out-dir', default=DEFAULT_OUT)
    ap.add_argument('--date', default=datetime.datetime.now().strftime('%Y-%m-%d'))
    args = ap.parse_args()

    if not args.target and not args.target_wxid:
        raise SystemExit('需要 --target(联系人备注/昵称) 或 --target-wxid 之一')

    if args.key_file:
        key = open(args.key_file, encoding='ascii').read().strip()
    elif args.key_hex:
        key = args.key_hex.strip()
    else:
        raise SystemExit('需要 --key-hex 或 --key-file')
    key = key.lower()
    if not re.fullmatch(r'[0-9a-f]{64}', key):
        raise SystemExit('密钥应为64位hex')
    key = bytes.fromhex(key)

    data_root = args.data_root
    if not data_root:
        for c in DATA_ROOT_CANDIDATES:
            if os.path.isdir(c):
                data_root = c; break
    if not data_root or not os.path.isdir(data_root):
        raise SystemExit('找不到数据根目录, 请用 --data-root 指定(含 wxid_xxx 账号文件夹的那一层)')

    tmp = tempfile.mkdtemp(prefix='wxexport_')
    try:
        account_dir = None
        for d in find_account_dirs(data_root):
            probe = os.path.join(d, 'db_storage', 'message', 'message_0.db')
            if not os.path.exists(probe):
                probe = os.path.join(d, 'db_storage', 'contact', 'contact.db')
            if os.path.exists(probe) and hmac_ok_file(key, probe):
                account_dir = d
                break
        if not account_dir:
            # 允许用户给定账号目录
            raise SystemExit('密钥未能解锁 %s 下任何账号目录(可能是旧账号密钥或数据根目录给错)' % data_root)
        print('使用账号目录:', account_dir)
        acct_name = os.path.basename(account_dir)
        self_wxid = args.self_wxid
        if not self_wxid:
            m = re.match(r'^(.*)_[0-9a-fA-F]{2,8}$', acct_name)
            if m:
                self_wxid = m.group(1)
        storage = os.path.join(account_dir, 'db_storage')

        contact_path = os.path.join(storage, 'contact', 'contact.db')
        contact_d = os.path.join(tmp, 'contact.db')
        decrypt_file(key, contact_path, contact_d)
        cols, rows = query('SELECT username, remark, nick_name, alias FROM contact', contact_d)
        if args.target_wxid:
            target_wxid = args.target_wxid
        else:
            hits = [r for r in rows if args.target in (r[1] or '') or args.target in (r[2] or '') or args.target in (r[3] or '')]
            if len(hits) == 0:
                raise SystemExit('在通讯录中找不到: ' + args.target)
            if len(hits) > 1:
                print('找到多个匹配:')
                for r in hits:
                    print(' ', r[0], '备注=%s 昵称=%s' % (r[1], r[2]))
                raise SystemExit('请用 --target-wxid 精确指定')
            target_wxid = hits[0][0]
        cinfo = next((r for r in rows if r[0] == target_wxid), None)
        other_remark = cinfo[1] or (args.target if args.target else '')
        other_nick = cinfo[2] or ''
        print('目标:', target_wxid, '备注:', other_remark, '昵称:', other_nick, '本人:', self_wxid)

        table = 'Msg_' + hashlib.md5(target_wxid.encode()).hexdigest()
        print('会话表:', table)
        msg_dir = os.path.join(storage, 'message')
        db_files = [f for f in os.listdir(msg_dir)
                    if re.match(r'message_\d+\.db$', f)]
        db_files.sort()
        all_rows = []
        for f in db_files:
            p = os.path.join(msg_dir, f)
            if not hmac_ok_file(key, p):
                continue
            dst = os.path.join(tmp, f)
            decrypt_file(key, p, dst)
            try:
                cols, tables = query("SELECT name FROM sqlite_master WHERE type='table'", dst)
            except Exception:
                continue
            if not any(t[0] == table for t in tables):
                continue
            idcols, idmap = query('SELECT rowid, user_name FROM Name2Id', dst)
            idmap = dict(idmap)
            if self_wxid not in idmap.values():
                # 若推导的self不对, 尝试取该库中另一个非目标wxid作为self
                others = {v for v in idmap.values() if v != target_wxid and not v.endswith('@chatroom') and not v.startswith('gh_') and v}
                if len(others) == 1:
                    self_wxid = others.pop()
                    print('从 %s 推断本人 wxid = %s' % (f, self_wxid))
            colsn, rs = query('SELECT local_id, local_type, COALESCE(sort_seq, create_time*1000), real_sender_id, create_time, message_content FROM "%s"' % table, dst)
            for r in rs:
                lid, lt, sseq, sid, ct, mc = r
                who = idmap.get(sid)
                if who not in (self_wxid, target_wxid):
                    continue
                all_rows.append((f, lid, lt, sseq, sid, ct, mc))
            print('%s: +%d 条' % (f, len(rs)))
        if not all_rows:
            raise SystemExit('未找到该联系人的消息(可能聊天在另一个账号/另一把密钥下)')
        print('合计消息:', len(all_rows))
        base, total = build_export(all_rows, self_wxid, args.self_name, target_wxid, other_remark, other_nick, args.out_dir, args.date)
        print('导出完成:')
        for s in (base + '.html', base + '.csv', base + '.txt'):
            print(' ', s, os.path.getsize(s))

        # 交叉核对: 会话表最后时间 vs 导出最后时间
        try:
            sess_d = os.path.join(tmp, 'session.db')
            sess_path = os.path.join(storage, 'session', 'session.db')
            if os.path.exists(sess_path):
                decrypt_file(key, sess_path, sess_d)
                colsn, rs = query('SELECT last_timestamp FROM SessionTable WHERE username=?', sess_d, (target_wxid,))
                if rs and rs[0][0]:
                    st = rs[0][0]
                    emax = max(r[5] for r in all_rows)
                    if st > emax:
                        print('注意: 会话表最后时间 %s 晚于主库导出最后时间 %s;'
                              ' 差额消息可能仍在 -wal 未合并(本方法以主库为准)' %
                              (datetime.datetime.fromtimestamp(st, TZ), datetime.datetime.fromtimestamp(emax, TZ)))
                    else:
                        print('交叉核对通过: 最后消息 =', datetime.datetime.fromtimestamp(emax, TZ))
        except Exception as e:
            print('交叉核对跳过:', e)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == '__main__':
    main()
