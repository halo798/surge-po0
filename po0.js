/**
 * Po0 流量面板 + 防火墙自动白名单（Surge iOS）
 *
 * mode=panel    : 登录 console.po0.io，读取 productInfo.php，显示 上行 / 下行 / 剩余流量
 * mode=firewall : 切换网络时 / 每 10 分钟 / 点面板时，把当前出口 /24 网段加入防火墙白名单
 *                 FW_TOKEN 不写 @ = 不锁定；写 @0–@4 = 锁定白名单第 1–5 个位置
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
const KEY_FW_LAST = 'po0_fw_last'; // 切网事件防抖
const KEY_FW_SRC = 'po0_fw_src'; // 本机加白过的网段来自蜂窝还是 Wi-Fi
const KEY_FW_STATE = 'po0_fw_state'; // 上次加白结果，定时任务只在变化时通知

// 版本号：通知 / 面板 / 日志里都会显示，用来确认 Surge 跑的是不是最新脚本
const FW_VER = '2026.11.16-3';

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
/* 防火墙：自动把当前网段加入白名单                                      */
/* ------------------------------------------------------------------ */

// 触发方式：
//   panel=1  首页“Po0 防火墙”面板：点一下（或面板自动刷新）立即加白，并显示白名单
//   cron=1   每 10 分钟兜底：抓“没切网但出口 IP 变了”的情况，结果有变化才通知
//   其余     network-changed 事件：切换网络后自动加白
async function runFirewall() {
  const panel = args.panel === '1';
  const cron = args.cron === '1';
  const enabled = !/^(0|false|off|no)$/i.test(args.enable || '1');
  const notifyOk = !/^(0|false|off|no)$/i.test(args.notify || '1');

  if (!panel && !enabled) return $done();

  const net = netInfo();
  const parsed = parseFwTokens(args.token || '');

  if (!parsed.items.length) {
    const msg = args.token ? parsed.errors.join('\n') : '模块参数 FW_TOKEN 未填写';
    if (!panel && args.token) fwNotify('❌ FW_TOKEN 填写有误', msg, cron, 'parse|' + msg, true);
    return fwFinish(panel, false, args.token ? '填写有误' : '未配置', [msg]);
  }

  if (!panel && !cron) {
    // 防抖：网络抖动时短时间内会连续触发
    const now = Date.now();
    const last = parseInt($persistentStore.read(KEY_FW_LAST) || '0', 10);
    if (now - last < 15000) return $done();
    $persistentStore.write(String(now), KEY_FW_LAST);
    // 断网时不请求
    if (!net.online) return $done();
    await sleep(2500); // 等新网络稳定
  }

  const results = await Promise.all(parsed.items.map((it) => fwAdd(it.token, it.slot)));

  // 记下本机加白的网段来自蜂窝还是 Wi-Fi，面板据此显示 📶 / 🛜
  const src = loadSrc();
  results.forEach((r) => {
    if (r.ok && r.view && r.view.cur) src[c24(r.view.cur)] = { t: net.type, s: net.ssid || '', ts: Date.now() };
  });
  saveJson(KEY_FW_SRC, src);

  const allOk = results.every((r) => r.ok) && !parsed.errors.length;
  const withView = results.find((r) => r.view && r.view.cur);
  const cur = withView ? withView.view.cur : '';
  const multi = parsed.items.length > 1;

  // 面板：当前网络 + 每台机器的白名单明细
  const lines = ['当前 ' + net.emoji + ' ' + net.label + ' · 出口 ' + (cur || '未知')];
  results.forEach((r, i) => {
    const it = parsed.items[i];
    const head = (multi ? '#' + (i + 1) + ' ' : '') + slotText(it.slot);
    if (r.ok) {
      lines.push('✅ ' + head + ' · 白名单 ' + r.view.list.length + '/' + r.view.limit);
    } else {
      lines.push('❌ ' + head + '：' + r.msg);
    }
    if (r.view) lines.push.apply(lines, listLines(r.view, src));
  });
  parsed.errors.forEach((e) => lines.push('❌ ' + e));
  lines.push('📶蜂窝 🛜Wi-Fi ❔其他设备 📌锁定 ←当前');

  // 通知：只放结论，不放整张白名单
  const brief = results.map((r, i) => {
    const it = parsed.items[i];
    const head = (multi ? '#' + (i + 1) + ' ' : '') + slotText(it.slot);
    return r.ok ? '✅ ' + head + ' · ' + r.view.cur + ' · 白名单 ' + r.view.list.length + '/' + r.view.limit : '❌ ' + head + '：' + r.msg;
  });
  parsed.errors.forEach((e) => brief.push('❌ ' + e));

  if (!panel) {
    const state = cur + '|' + brief.join('|');
    const sub = (allOk ? '✅ 已放行 ' : '❌ 加白失败 ') + net.emoji + ' ' + net.label;
    fwNotify(sub, brief.join('\n'), cron, state, !allOk || notifyOk);
  }
  return fwFinish(panel, allOk, allOk ? '已放行' : '加白失败', lines);
}

// 面板结束（事件 / 定时任务直接结束）
function fwFinish(panel, ok, status, lines) {
  const content = lines.concat('v' + FW_VER + ' · ' + hhmm(new Date())).join('\n');
  console.log('[Po0 FW] ' + status + '\n' + content);
  if (!panel) return $done();
  $done({
    title: 'Po0 防火墙 · ' + status,
    content: content,
    icon: ok ? 'checkmark.shield.fill' : 'exclamationmark.shield.fill',
    'icon-color': ok ? '#34C759' : '#FF3B30',
  });
}

// 每次都记录结果；定时任务只在结果变化时通知，避免每 10 分钟重复提醒同一件事
function fwNotify(subtitle, body, cron, state, want) {
  const prev = $persistentStore.read(KEY_FW_STATE);
  $persistentStore.write(state, KEY_FW_STATE);
  if (!want || (cron && prev === state)) return;
  notify('Po0 防火墙', subtitle, body + '\nv' + FW_VER, 0);
}

function slotText(slot) {
  return slot === null ? '不锁定' : '锁定 @' + slot;
}

// 白名单明细：锁定的按位置排在前面，其余按服务端顺序
function listLines(view, src) {
  const pinned = view.list.filter((e) => e.slot !== null).sort((a, b) => a.slot - b.slot);
  const free = view.list.filter((e) => e.slot === null);
  const rows = pinned.concat(free).map((e) => {
    const s = src[c24(e.ip)];
    const mark = !s ? '❔' : s.t === 'cell' ? '📶' : s.t === 'wifi' ? '🛜' + (s.s ? cut(s.s, 8) : '') : '🌐';
    return '  ' + e.ip + ' ' + mark + (e.slot !== null ? ' 📌@' + e.slot : '') + (sameC24(e.ip, view.cur) ? ' ←' : '');
  });
  return rows.length ? rows : ['  （白名单为空）'];
}

// 当前网络：pdp_ip* = 蜂窝，en* / 有 SSID = Wi-Fi
function netInfo() {
  const n = typeof $network !== 'undefined' && $network ? $network : {};
  const v4 = n.v4 || {};
  const v6 = n.v6 || {};
  const iface = v4.primaryInterface || v6.primaryInterface || '';
  const ssid = (n.wifi && n.wifi.ssid) || '';
  const online = !!(v4.primaryAddress || v6.primaryAddress) || typeof $network === 'undefined';
  if (/^pdp_ip/.test(iface)) return { type: 'cell', emoji: '📶', label: '蜂窝', ssid: '', online: online };
  if (ssid || /^en\d/.test(iface)) {
    return { type: 'wifi', emoji: '🛜', label: 'Wi-Fi' + (ssid ? '「' + cut(ssid, 12) + '」' : ''), ssid: ssid, online: online };
  }
  return { type: 'other', emoji: '🌐', label: iface || '未知网络', ssid: '', online: online };
}

/**
 * 解析 FW_TOKEN（不写 @ = 不锁定；@0–@4 = 锁定白名单第 1–5 个位置）：
 *   pgnfw_xxx            不锁定，白名单满时按写入时间淘汰最旧的
 *   pgnfw_xxx@0          锁定第 1 个位置 …… pgnfw_xxx@4 锁定第 5 个位置
 *   pgnfw_A@0,pgnfw_B    多台机器用英文逗号分隔
 * 也兼容直接粘贴控制台“复制添加脚本”的整段内容或整条链接、全角 ＠ 和数字。
 * token 只含字母、数字、下划线（服务端只认这些字符）。
 */
function parseFwTokens(raw) {
  const s = toHalfWidth(String(raw));
  const re = /pgnfw_[A-Za-z0-9_]+/g;
  const found = [];
  let m;
  while ((m = re.exec(s))) found.push({ token: m[0], start: m.index, end: m.index + m[0].length });

  const items = [];
  const errors = [];
  if (!found.length) {
    if (s.trim()) errors.push('没找到 pgnfw_ 开头的 token（收到：' + cut(s.trim(), 16) + '）');
    return { items: items, errors: errors };
  }
  found.forEach((f, i) => {
    // token 后面到下一个分隔符为止，找 @N 或 ?slot=N
    const tail = s.slice(f.end, i + 1 < found.length ? found[i + 1].start : s.length).split(/[,|;、]/)[0];
    const at = tail.match(/@\s*([^\s/?&#"']*)/);
    const q = tail.match(/[?&]slot=([^\s&#"']*)/);
    const want = at ? at[1] : q ? q[1] : null;
    let slot = null;
    if (want !== null) {
      if (!/^[0-4]$/.test(want)) {
        errors.push(mask(f.token) + '@' + want + '：只能写 @0、@1、@2、@3、@4（不写 @ 表示不锁定），本条未提交');
        return;
      }
      slot = parseInt(want, 10);
    }
    const dup = items.find((x) => x.token === f.token);
    if (dup) {
      if (slot !== null) dup.slot = slot;
      return;
    }
    items.push({ token: f.token, slot: slot });
  });
  return { items: items, errors: errors };
}

// POST /api/firewall/<token>/add[?slot=N]：把请求来源的 /24 网段加入白名单。
// 不带 slot = 不锁定（满了按写入时间淘汰最旧的）；带 slot = 钉在该位置，永不淘汰。
// 返回 {enabled, whitelist:[{ip, slot}], limit, currentIp}；403 = 本网段已锁在别的位置。
async function fwAdd(token, slot) {
  const url = FW_BASE + '/' + token + '/add' + (slot === null ? '' : '?slot=' + slot);
  const tag = mask(token) + (slot === null ? '' : '@' + slot);
  let last = { ok: false, msg: '未知错误' };

  for (let i = 0; i < 3; i++) {
    let r;
    try {
      const opts = {
        url: url,
        policy: 'DIRECT',
        timeout: 10,
        headers: baseHeaders({ Accept: 'application/json', 'Content-Type': 'application/json' }),
        body: '',
      };
      try {
        r = await request('post', opts);
      } catch (e) {
        // 若是 IP 证书校验失败，退回不校验证书再试一次
        if (!/certif|ssl|tls|trust/i.test(e.message)) throw e;
        opts.insecure = true;
        r = await request('post', opts);
      }
    } catch (e) {
      console.log('[Po0 FW] ' + tag + ' 第 ' + (i + 1) + ' 次请求失败：' + e.message);
      last = { ok: false, msg: '网络请求失败：' + e.message };
      await sleep(2000 * (i + 1));
      continue;
    }

    console.log('[Po0 FW] ' + tag + ' HTTP ' + r.status + ' ' + String(r.body).slice(0, 400));
    const res = judgeFw(r.status, r.body, slot);
    if (res.ok || !res.retry) return res;
    last = res;
    await sleep(2000 * (i + 1));
  }
  return last;
}

function judgeFw(status, body, slot) {
  let data = null;
  try {
    data = JSON.parse(body);
  } catch (e) {}
  const view = data && Array.isArray(data.whitelist) ? toView(data) : null;
  const srv = data && (data.message || data.msg) ? String(data.message || data.msg) : '';
  const mine = view ? view.list.find((e) => sameC24(e.ip, view.cur)) : null;

  if (status >= 300 && status < 400) {
    return { ok: false, msg: 'token 无效（HTTP ' + status + '），请到控制台「防火墙 → 复制添加脚本」重新复制 pgnfw_ 开头那段' };
  }
  if (status === 403) {
    const where = mine && mine.slot !== null ? '（现在在 @' + mine.slot + '）' : '';
    return {
      ok: false,
      view: view,
      msg: '当前网段已锁定在别的位置' + where + '，同一网段只能占一个位置：先在控制台防火墙里删掉旧记录' + (srv ? '（' + srv + '）' : ''),
    };
  }
  if (status >= 200 && status < 300) {
    if (!view) return { ok: false, retry: true, msg: '返回内容无法识别：' + summarize(body) };
    if (view.enabled === false) return { ok: false, view: view, msg: '控制台里这台机器的防火墙没有开启' };
    if (!mine) return { ok: false, view: view, msg: '提交成功，但白名单里没有当前网段 ' + view.cur };
    if (slot !== null && mine.slot !== slot) {
      return {
        ok: false,
        view: view,
        msg: '当前网段在' + (mine.slot === null ? '未锁定位置' : ' @' + mine.slot) + '，不是 @' + slot + '：先在控制台删掉旧记录再试',
      };
    }
    return { ok: true, view: view };
  }
  if (/serviceId is required|invalid token|token/i.test(srv)) {
    return { ok: false, view: view, msg: 'token 无效（服务端：' + srv + '），请重新复制 pgnfw_ 开头那段' };
  }
  // 5xx 或裸 “Error” 属于服务端偶发，重试；规范 JSON 错误重试无意义
  return { ok: false, view: view, retry: status >= 500 || !data, msg: 'HTTP ' + status + ' ' + (srv || summarize(body)) };
}

function toView(data) {
  const slotOf = (v) => (v === null || v === undefined || v === '' || isNaN(Number(v)) ? null : Number(v));
  return {
    enabled: data.enabled,
    limit: data.limit || 5,
    cur: data.currentIp ? String(data.currentIp) : '',
    list: data.whitelist.map((e) =>
      e && typeof e === 'object' ? { ip: String(e.ip), slot: slotOf(e.slot) } : { ip: String(e), slot: null }
    ),
  };
}

// 统一成 x.x.x.0/24，作为“网段来源”记录的键
function c24(ip) {
  const p = String(ip).replace(/\/\d+$/, '').split('.');
  return p.length === 4 ? p[0] + '.' + p[1] + '.' + p[2] + '.0/24' : String(ip);
}

// 服务端按 /24 加白：任一侧是 /24 段时比较前三段，否则要求完全相同
function sameC24(a, b) {
  if (!a || !b) return false;
  a = String(a);
  b = String(b);
  if (a === b) return true;
  if (!/\/24$/.test(a) && !/\/24$/.test(b)) return false;
  return c24(a) === c24(b);
}

// 网段来源记录只留 30 天、最多 50 条
function loadSrc() {
  const m = loadJson(KEY_FW_SRC) || {};
  const cutoff = Date.now() - 30 * 24 * 3600e3;
  const keys = Object.keys(m)
    .filter((k) => m[k] && m[k].ts > cutoff)
    .sort((a, b) => m[b].ts - m[a].ts)
    .slice(0, 50);
  const out = {};
  keys.forEach((k) => (out[k] = m[k]));
  return out;
}

function mask(token) {
  return token.length > 10 ? token.slice(0, 10) + '…' : token;
}

function cut(s, n) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// 全角 ＠ ０-９ ，等转半角，中文输入法下也能填对
function toHalfWidth(s) {
  return s.replace(/[！-～]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xfee0)).replace(/　/g, ' ');
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
