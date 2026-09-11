# -*- coding: utf-8 -*-
r"""
微信 4.x (Windows) 数据库密钥捕获
原理: 微信重启后在登录阶段 Hook SetDBKey, 登录时微信自动调用并写入数据库密钥。
需要用户配合: 重启微信后在手机上确认登录 (或扫码)。
用法:
  python capture_key.py --wechat-exe "D:\WeiXin\Weixin.exe" --out <目录>
可选:
  --close-first      自动结束当前运行的微信 (需先征得用户同意)
  --poll-seconds 240 捕获等待秒数
  --dll <path>       wx_key.dll 路径 (默认: 自动查找, 找不到则自动下载)
成功时在 --out 写入 key.txt (64位hex, 小写)。
"""
import argparse, ctypes, ctypes.wintypes as w, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request, zipfile

# 密钥捕获组件 wx_key.dll 的自动获取来源 (微信导出工具 WXexport-tool 的 GitHub 发布包)
_RELEASE_API = 'https://api.github.com/repos/Ray0612/WeChat-Export-Tool/releases/latest'
_FALLBACK_ZIP = 'https://github.com/Ray0612/WeChat-Export-Tool/releases/download/v1.2.0/WXexport-tool-v1.2.0.zip'
_USER_AGENT = 'wx-key-auto-download'


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def find_weixin_pids():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV', '/NH'],
                         capture_output=True, text=True, timeout=10).stdout
    pids = []
    for line in out.splitlines():
        if 'Weixin.exe' in line:
            m = re.search(r'"(\d+)"', line)
            if m:
                pids.append(int(m.group(1)))
    return pids


def wait_exit(pids, seconds=25):
    end = time.time() + seconds
    while time.time() < end:
        cur = find_weixin_pids()
        if not cur:
            return True
        time.sleep(0.5)
    return False


def get_wechat_version(wechat_exe):
    """尽力读取微信版本号 (仅用于提示, 不影响流程)。"""
    # 先读文件版本信息
    try:
        esc = wechat_exe.replace("'", "''")
        ps = "(Get-Item -LiteralPath '%s').VersionInfo.FileVersion" % esc
        out = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                             capture_output=True, text=True, timeout=30).stdout
        m = re.search(r'4\.\d+\.\d+\.\d+', out or '')
        if m:
            return m.group(0)
    except Exception:
        pass
    # 回退: 扫描安装目录下形如 4.x.x.x 的子目录
    try:
        install_dir = os.path.dirname(wechat_exe)
        for name in os.listdir(install_dir):
            if re.fullmatch(r'4\.\d+\.\d+\.\d+', name):
                return name
    except Exception:
        pass
    return None


def bundled_dll_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'bin', 'wx_key.dll')


def find_local_dll(wechat_exe):
    """在常见本机位置找现成的 wx_key.dll (避免重复下载)。"""
    candidates = []
    for base in [os.environ.get('LOCALAPPDATA', ''), os.environ.get('PROGRAMFILES', ''),
                 os.environ.get('PROGRAMFILES(X86)', '')]:
        if base:
            candidates.append(os.path.join(base, 'Programs', 'WeFlow', 'resources',
                                           'resources', 'key', 'win32', 'x64', 'wx_key.dll'))
    install_dir = os.path.dirname(os.path.abspath(wechat_exe))
    candidates.append(os.path.join(install_dir, 'wx_key.dll'))
    for c in candidates:
        try:
            if os.path.isfile(c) and os.path.getsize(c) > 1024:
                return c
        except Exception:
            continue
    return None


def _download(url, dest):
    req = urllib.request.Request(url, headers={'User-Agent': _USER_AGENT})
    last_pct = -1
    with urllib.request.urlopen(req, timeout=120) as r:
        total = int(r.headers.get('Content-Length') or 0)
        done = 0
        with open(dest, 'wb') as f:
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    if pct != last_pct and pct % 10 == 0:
                        last_pct = pct
                        log('    已下载 %d%% (%.0f / %.0f MB)' % (
                            pct, done / 1024 / 1024, total / 1024 / 1024))


def acquire_dll(dest_path):
    """从公开来源下载第三方密钥捕获工具并解出 wx_key.dll, 写入 dest_path。返回实际落地路径。"""
    log('未找到密钥捕获组件, 现在自动下载所需的第三方密钥捕获工具 (仅需一次)。')

    # 1) 解析下载地址: 优先查最新发布, 失败则用固定 v1.2.0
    url = None
    try:
        req = urllib.request.Request(_RELEASE_API, headers={'User-Agent': _USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode('utf-8'))
        for a in data.get('assets', []):
            name = (a.get('name') or '').lower()
            if name.endswith('.zip'):
                url = a.get('browser_download_url')
                break
    except Exception:
        url = None
    if not url:
        url = _FALLBACK_ZIP
        log('  使用固定版本下载地址。')

    # 2) 下载压缩包 (缓存到临时目录, 已下载过则跳过)
    zip_path = os.path.join(tempfile.gettempdir(), 'WXexport-tool.zip')
    if os.path.isfile(zip_path) and os.path.getsize(zip_path) > 1024 * 1024:
        log('  检测到已下载的组件, 跳过重复下载。')
    else:
        log('  正在下载 (请耐心等待, 进度如下)...')
        _download(url, zip_path)

    # 3) 解出 wx_key.dll (取名字以 wx_key.dll 结尾、体积最大的那份)
    log('  正在安装组件 ...')
    target = None
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if info.filename.lower().endswith('wx_key.dll') and not info.is_dir():
                if target is None or info.file_size > target.file_size:
                    target = info
    if target is None:
        raise SystemExit('压缩包中未找到 wx_key.dll, 下载源可能已变化。请手动获取后放到 bin/ 目录再运行。')

    # 落地: 优先技能 bin/, 不可写则退回临时目录
    try:
        out_dir = os.path.dirname(dest_path)
        os.makedirs(out_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path) as z, z.open(target) as src, open(dest_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
    except OSError:
        dest_path = os.path.join(tempfile.gettempdir(), 'wx_key.dll')
        with zipfile.ZipFile(zip_path) as z, z.open(target) as src, open(dest_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)

    if not (os.path.isfile(dest_path) and os.path.getsize(dest_path) > 1024):
        raise SystemExit('解出的 wx_key.dll 无效 (可能下载损坏), 请删除临时压缩包后重试。')
    log('  组件已就绪。')
    return dest_path


def resolve_dll(args):
    """按优先级确定 wx_key.dll 路径: 显式路径 -> 技能自带 -> 本机现成 -> 自动下载。"""
    if args.dll:
        if os.path.isfile(args.dll):
            return os.path.abspath(args.dll)
        raise SystemExit('指定的 --dll 不存在: ' + args.dll)

    bundled = bundled_dll_path()
    if os.path.isfile(bundled):
        return bundled

    local = find_local_dll(args.wechat_exe)
    if local:
        log('已在电脑上找到现成的 wx_key.dll (无需下载): %s' % local)
        return local

    return acquire_dll(bundled)


def load_api(dll_path):
    if not os.path.exists(dll_path):
        raise SystemExit('找不到 wx_key.dll: ' + dll_path)
    lib = ctypes.CDLL(dll_path)
    api = {}
    try:
        api['InitializeHook'] = lib.InitializeHook
        api['InitializeHook'].argtypes = [w.DWORD]
        api['InitializeHook'].restype = ctypes.c_bool
        api['PollKeyData'] = lib.PollKeyData
        api['PollKeyData'].argtypes = [ctypes.c_char_p, ctypes.c_int]
        api['PollKeyData'].restype = ctypes.c_bool
        api['GetStatusMessage'] = lib.GetStatusMessage
        api['GetStatusMessage'].argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
        api['GetStatusMessage'].restype = ctypes.c_bool
        api['CleanupHook'] = lib.CleanupHook
        api['CleanupHook'].restype = ctypes.c_bool
    except AttributeError as e:
        raise SystemExit('wx_key.dll 缺少导出函数: %s (该 dll 可能不支持当前版本)' % e)
    lib.GetLastErrorMsg.restype = ctypes.c_char_p
    api['_lib'] = lib
    return api


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wechat-exe', required=True, help='微信主程序路径, 例如 D:\\WeiXin\\Weixin.exe')
    ap.add_argument('--out', required=True, help='输出目录, 密钥写入该目录的 key.txt')
    ap.add_argument('--close-first', action='store_true', help='先自动结束已运行的微信 (使用前请先获得用户同意)')
    ap.add_argument('--poll-seconds', type=int, default=240)
    ap.add_argument('--dll', default=None, help='wx_key.dll 路径 (默认: 自动查找/下载)')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    ver = get_wechat_version(args.wechat_exe)
    if ver:
        log('检测到微信版本:', ver)

    dll_path = resolve_dll(args)
    api = load_api(dll_path)

    existing = find_weixin_pids()
    if existing:
        if args.close_first:
            log('结束现有微信进程', existing)
            subprocess.run(['taskkill', '/PID'] + [str(p) for p in existing], check=False)
            if not wait_exit(existing, 25):
                raise SystemExit('等待微信退出超时, 请手动关闭后重试')
        else:
            raise SystemExit('微信正在运行。本流程需要重启微信: 请先关闭微信, 或加 --close-first 由脚本关闭。')

    log('启动微信:', args.wechat_exe)
    subprocess.Popen([args.wechat_exe])
    pid = None
    for _ in range(120):
        pids = find_weixin_pids()
        if pids:
            pid = pids[0]
            break
        time.sleep(0.5)
    if not pid:
        raise SystemExit('等待微信启动超时')

    log('注入 Hook 到 PID', pid)
    ok = api['InitializeHook'](pid)
    log('InitializeHook =', ok)
    if not ok:
        err = api['_lib'].GetLastErrorMsg()
        raise SystemExit('Hook 注入失败: %s' % (err.decode('utf-8', 'replace') if err else '未知错误'))

    def drain_status():
        buf = ctypes.create_string_buffer(1024)
        lvl = ctypes.c_int(0)
        while api['GetStatusMessage'](buf, len(buf), ctypes.byref(lvl)):
            m = buf.value.decode('utf-8', 'replace').strip()
            if m:
                log('  [%d] %s' % (lvl.value, m))

    drain_status()
    log('请现在完成微信登录 (手机确认或扫码)。等待捕获密钥最多 %d 秒...' % args.poll_seconds)
    key_buf = ctypes.create_string_buffer(128)
    start = time.time()
    while time.time() - start < args.poll_seconds:
        if api['PollKeyData'](key_buf, len(key_buf)):
            key = key_buf.value.decode('ascii', 'ignore').strip()
            if re.fullmatch(r'[0-9a-fA-F]{64}', key):
                key = key.lower()
                open(os.path.join(args.out, 'key.txt'), 'w', encoding='ascii').write(key)
                log('捕获成功 -> %s' % os.path.join(args.out, 'key.txt'))
                api['CleanupHook']()
                return
        drain_status()
        time.sleep(0.2)
    log('超时未捕获。常见原因: 登录发生在 Hook 安装之前。请关闭微信重试 (先开脚本再登录)。')
    api['CleanupHook']()
    raise SystemExit('timeout')


if __name__ == '__main__':
    main()
