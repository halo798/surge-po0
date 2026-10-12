/**
 * Po0 流量面板 + 防火墙自动白名单（Surge iOS）
 *
 * mode=panel    : 登录 console.po0.io，读取 productInfo.php，显示 上行 / 下行 / 剩余流量
 * mode=firewall : 网络切换时请求防火墙 add 链接，把当前出口 /24 网段加入白名单
 *
 * 数据来源：/modules/servers/penguin/api/productInfo.php?serviceId=<id>
 *   totalTransfer / usedTransfer / remainingTransfer / txTransfer / rxTransfer，单位 KB
 */

const BASE = 'https://console.po0.io';
const FW_BASE = 'https://124.221.69.228/api/firewall';
const UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';

const KEY_COOKIE = 'po0_cookie';
const KEY_CACHE = 'po0_cache';
const KEY_FW_LAST = 'po0_fw_last';

const args = parseArgs(typeof $argument !== 'undefined' ? $argument : '');
const MODE = args.mode || 'panel';

(MODE === 'firewall' ? runFirewall() : runPanel()).catch((e) => {
  console.log('[Po0] 未捕获错误: ' + (e && e.stack ? e.stack : e));
  $done({});
});

/* ------------------------------------------------------------------ */
/* 面板                                                                 */
/* ------------------------------------------------------------------ */

async function runPanel() {
  const sid = args.sid || '4040';
  const user = args.user;
  const pass = args.pass;
  const name = args.name || 'Po0';

  try {
    if (!user || !pass) throw new Error('请在模块参数中填写账号和密码');

    let jar = loadJson(KEY_COOKIE) || {};
    let info = null;

    // 1) 先用保存的会话直接取数据（WHMCS 会话绑定 IP，换网络后会失效）
    if (Object.keys(jar).length) {
      try {
        info = await fetchInfo(sid, jar);
        if (!info || info.error || typeof info.totalTransfer !== 'number') info = null;
      } catch (e) {
        console.log('[Po0] 旧会话不可用: ' + e.message);
        info = null;
      }
    }

    // 2) 会话失效 → 重新登录
    if (!info) {
      jar = await login(user, pass);
      info = await fetchInfo(sid, jar);
    }

    if (info.error) throw new Error(info.error);
    if (typeof info.totalTransfer !== 'number') throw new Error('接口数据格式已变化');

    delete info.password; // 不保存 root 密码
    saveJson(KEY_COOKIE, jar);
    saveJson(KEY_CACHE, { ts: Date.now(), info: info });

    $done(render(name, info, null));
  } catch (e) {
    console.log('[Po0] 获取失败: ' + e.message);
    const cache = loadJson(KEY_CACHE);
    if (cache && cache.info) {
      $done(render(name, cache.info, { msg: e.message, ts: cache.ts }));
    } else {
      $done({
        title: name + ' 流量',
        content: '获取失败：' + e.message,
        icon: 'exclamationmark.triangle.fill',
        'icon-color': '#FF3B30',
      });
    }
  }
}

function render(name, info, stale) {
  const total = info.totalTransfer || 0;
  const remain = Math.max(0, info.remainingTransfer || 0);
  const used = info.usedTransfer || 0;
  const tx = info.txTransfer || 0;
  const rx = info.rxTransfer || 0;
  const pct = total > 0 ? (remain / total) * 100 : 0;

  const billing =
    info.stopMode === 'STOP_DUPLEX_TRANSFER' ? '双向计费' : info.stopMode === 'STOP_SIMPLEX_TRANSFER' ? '单向计费' : '';

  const state =
    { RUNNING: '运行中', STOPPED: '已关机', STOPPING: '关机中', STARTING: '开机中', REBOOTING: '重启中' }[
      info.instanceState
    ] || info.instanceState || '';

  const reset = nextReset(info.createdAt);

  const lines = [
    '剩余 ' + fmtKB(remain) + ' / ' + fmtKB(total) + '（' + pct.toFixed(0) + '%）',
    '上行 ' + fmtKB(tx) + '　下行 ' + fmtKB(rx),
    (billing ? billing + '　' : '') + '已用 ' + fmtKB(used),
  ];
  if (reset) lines.push('重置 ' + (reset.date.getMonth() + 1) + '月' + reset.date.getDate() + '日（' + reset.rel + '）');
  if (stale) {
    lines.push('⚠️ ' + stale.msg + '（缓存 ' + hhmm(new Date(stale.ts)) + '）');
  } else {
    lines.push('更新于 ' + hhmm(new Date()));
  }

  const color = stale ? '#8E8E93' : pct > 30 ? '#34C759' : pct > 10 ? '#FF9500' : '#FF3B30';

  return {
    title: name + (state ? ' · ' + state : ''),
    content: lines.join('\n'),
    icon: 'arrow.up.arrow.down.circle.fill',
    'icon-color': color,
  };
}

/* ------------------------------------------------------------------ */
/* 登录 & 接口                                                          */
/* ------------------------------------------------------------------ */

async function login(user, pass) {
  const jar = {};
  const r1 = await request('get', {
    url: BASE + '/login',
    headers: baseHeaders({ Accept: 'text/html' }),
  });
  mergeSetCookie(jar, r1.headers);

  const m =
    r1.body.match(/name="token"\s+value="([0-9a-fA-F]+)"/) || r1.body.match(/csrfToken\s*=\s*'([0-9a-fA-F]+)'/);
  if (!m) {
    if (r1.status === 403 || /cf-chl|challenge-platform/i.test(r1.body)) throw new Error('被 Cloudflare 拦截，请稍后再试');
    throw new Error('登录页解析失败（HTTP ' + r1.status + '）');
  }
  if (/g-recaptcha|cf-turnstile|h-captcha/i.test(r1.body)) throw new Error('登录页出现验证码，脚本无法自动登录');

  const body =
    'token=' + enc(m[1]) + '&username=' + enc(user) + '&password=' + enc(pass);

  const r2 = await request('post', {
    url: BASE + '/login',
    headers: baseHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'text/html',
      Origin: BASE,
      Referer: BASE + '/login',
      Cookie: cookieString(jar),
    }),
    body: body,
  });
  mergeSetCookie(jar, r2.headers);

  const loc = String(getHeader(r2.headers, 'location') || '');
  if (r2.status >= 300 && r2.status < 400 && loc && !/login/i.test(loc)) return jar;
  if (/challenge|two-?factor|2fa/i.test(loc)) throw new Error('账号开启了二次验证，脚本无法自动登录');
  throw new Error('登录失败，请检查账号密码');
}

async function fetchInfo(sid, jar) {
  const r = await request('get', {
    url: BASE + '/modules/servers/penguin/api/productInfo.php?serviceId=' + enc(sid),
    headers: baseHeaders({
      Accept: 'application/json',
      Referer: BASE + '/clientarea.php?action=productdetails&id=' + enc(sid),
      Cookie: cookieString(jar),
    }),
  });
  mergeSetCookie(jar, r.headers);
  try {
    return JSON.parse(r.body);
  } catch (e) {
    throw new Error('接口返回异常（HTTP ' + r.status + '）');
  }
}

/* ------------------------------------------------------------------ */
/* 防火墙：切换网络时加入白名单                                          */
/* ------------------------------------------------------------------ */

async function runFirewall() {
  const token = args.token;
  const enabled = !/^(0|false|off|no)$/i.test(args.enable || '1');
  const quiet = /^(0|false|off|no)$/i.test(args.notify || '1');

  if (!enabled || !token) return $done();

  // 防抖：网络抖动时短时间内会连续触发
  const now = Date.now();
  const last = parseInt($persistentStore.read(KEY_FW_LAST) || '0', 10);
  if (now - last < 15000) return $done();
  $persistentStore.write(String(now), KEY_FW_LAST);

  // 断网时不请求
  if (typeof $network !== 'undefined' && $network) {
    const v4 = $network.v4 && $network.v4.primaryAddress;
    const v6 = $network.v6 && $network.v6.primaryAddress;
    if (!v4 && !v6) return $done();
  }

  const netName =
    (typeof $network !== 'undefined' && $network && $network.wifi && $network.wifi.ssid) || '蜂窝网络';

  await sleep(2500); // 等新网络稳定

  const url = FW_BASE + '/' + token + '/add';
  let lastErr = null;

  for (let i = 0; i < 3; i++) {
    try {
      let r;
      const opts = { url: url, policy: 'DIRECT', timeout: 10, headers: baseHeaders({ Accept: '*/*' }) };
      try {
        r = await request('get', opts);
      } catch (e) {
        // 若是 IP 证书校验失败，退回不校验证书再试一次
        if (!/certif|ssl|tls|trust/i.test(e.message)) throw e;
        opts.insecure = true;
        r = await request('get', opts);
      }

      if (r.status >= 200 && r.status < 300) {
        if (!quiet) notify('Po0 防火墙', '已放行当前网段（' + netName + '）', summarize(r.body), 4);
        return $done();
      }
      lastErr = new Error('HTTP ' + r.status + ' ' + summarize(r.body));
      if (r.status >= 400 && r.status < 500) break; // token 失效等，重试无意义
    } catch (e) {
      lastErr = e;
    }
    await sleep(3000);
  }

  notify('Po0 防火墙', '加入白名单失败（' + netName + '）', lastErr ? lastErr.message : '未知错误', 0);
  $done();
}

/* ------------------------------------------------------------------ */
/* 工具函数                                                             */
/* ------------------------------------------------------------------ */

function request(method, opts) {
  const o = Object.assign({ timeout: 15, 'auto-cookie': false, 'auto-redirect': false }, opts);
  return new Promise((resolve, reject) => {
    $httpClient[method](o, (err, resp, data) => {
      if (err) return reject(new Error(typeof err === 'string' ? err : err.message || JSON.stringify(err)));
      resolve({ status: resp.status || resp.statusCode || 0, headers: resp.headers || {}, body: data || '' });
    });
  });
}

function baseHeaders(extra) {
  return Object.assign({ 'User-Agent': UA, 'Accept-Language': 'zh-CN,zh;q=0.9' }, extra || {});
}

function getHeader(headers, name) {
  const lower = name.toLowerCase();
  for (const k in headers) if (k.toLowerCase() === lower) return headers[k];
  return undefined;
}

function mergeSetCookie(jar, headers) {
  let raw = getHeader(headers, 'set-cookie');
  if (!raw) return jar;
  if (Array.isArray(raw)) raw = raw.join('\n');
  // 多个 Set-Cookie 可能被合并为一个逗号分隔的字符串；按 “, name=” 切分，避开 Expires 里的逗号
  String(raw)
    .split(/\n|,(?=\s*[^;,=\s]+=)/)
    .forEach((part) => {
      const first = part.split(';')[0].trim();
      const i = first.indexOf('=');
      if (i <= 0) return;
      const k = first.slice(0, i).trim();
      const v = first.slice(i + 1).trim();
      if (/^(expires|path|domain|max-age|samesite|secure|httponly)$/i.test(k)) return;
      if (!v || v === 'deleted') delete jar[k];
      else jar[k] = v;
    });
  return jar;
}

function cookieString(jar) {
  return Object.keys(jar)
    .map((k) => k + '=' + jar[k])
    .join('; ');
}

// 与控制台前端一致：以开通时间为锚点，每月同日同时刻重置（按 UTC 计算）
function nextReset(createdAt) {
  if (!createdAt) return null;
  const s = new Date(createdAt);
  const now = new Date();
  if (isNaN(s.getTime())) return null;
  const startA = Date.UTC(s.getUTCFullYear(), s.getUTCMonth() + 1, 1);
  const startB = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
  const o = new Date(Math.max(startA, startB));
  for (let l = 0; l < 13; l++) {
    const y = o.getUTCFullYear();
    const mth = o.getUTCMonth() + l;
    const dim = new Date(Date.UTC(y, mth + 1, 0)).getUTCDate();
    const d = Math.min(s.getUTCDate(), dim);
    const t = new Date(Date.UTC(y, mth, d, s.getUTCHours(), s.getUTCMinutes(), s.getUTCSeconds()));
    if (t.getTime() > now.getTime()) {
      const ms = t.getTime() - now.getTime();
      const H = 3600e3, D = 24 * H;
      const rel = ms < H ? Math.max(1, Math.ceil(ms / 60e3)) + ' 分钟后' : ms < D ? Math.ceil(ms / H) + ' 小时后' : Math.ceil(ms / D) + ' 天后';
      return { date: t, rel: rel };
    }
  }
  return null;
}

// 接口单位为 KB（1024 进制），与控制台显示一致
function fmtKB(kb) {
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = Math.abs(kb || 0);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  let s = v.toFixed(v >= 10 ? 1 : 2);
  if (s.indexOf('.') >= 0) s = s.replace(/0+$/, '').replace(/\.$/, '');
  return s + ' ' + units[i];
}

function hhmm(d) {
  return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
}

function summarize(body) {
  if (!body) return '';
  try {
    const j = JSON.parse(body);
    const msg = j.message || j.msg || (j.data && (j.data.message || j.data.ip)) || j.ip || j.cidr;
    if (msg) return String(msg).slice(0, 120);
    return JSON.stringify(j).slice(0, 120);
  } catch (e) {
    return String(body).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
  }
}

function notify(title, subtitle, body, autoDismiss) {
  const opts = autoDismiss ? { 'auto-dismiss': autoDismiss } : undefined;
  $notification.post(title, subtitle, body || '', opts);
}

function parseArgs(arg) {
  const out = {};
  if (!arg) return out;
  if (typeof arg === 'object') {
    for (const k in arg) out[k] = clean(arg[k]);
    return out;
  }
  let str = String(arg);
  // pass 放在最后，整段取出，允许密码里出现 & 或 =
  const p = str.search(/(^|&)pass=/);
  if (p >= 0) {
    const start = str.indexOf('pass=', p) + 5;
    out.pass = clean(str.slice(start));
    str = str.slice(0, p);
  }
  str.split('&').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i).trim()] = clean(kv.slice(i + 1));
  });
  return out;
}

function clean(v) {
  v = v == null ? '' : String(v).trim();
  // 未替换的模块参数、占位文字视为空
  return /^\{\{\{.*\}\}\}$/.test(v) || /^(必填|选填|null|undefined)$/i.test(v) ? '' : v;
}

function enc(s) {
  return encodeURIComponent(String(s));
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function loadJson(key) {
  try {
    const s = $persistentStore.read(key);
    return s ? JSON.parse(s) : null;
  } catch (e) {
    return null;
  }
}

function saveJson(key, obj) {
  $persistentStore.write(JSON.stringify(obj), key);
}
