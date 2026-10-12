# Surge 模块：Po0 流量面板

在 Surge iOS 首页面板显示 [Po0](https://console.po0.io) 服务器的**上行 / 下行 / 剩余流量**、计费方式和下次重置日期；
可选：手机切换网络时自动请求防火墙“添加网段链接”，把当前出口 /24 网段加入白名单。

## 安装

Surge → 模块 → 安装新模块，填入：

```
https://raw.githubusercontent.com/halo798/surge-po0/main/po0.sgmodule
```

安装后编辑模块参数：

| 参数 | 说明 |
| --- | --- |
| `USER` / `PASS` | po0.io 登录邮箱和密码（必填） |
| `SID` | 服务编号，产品详情页上的 `#xxxx` |
| `NAME` | 面板标题 |
| `FW_TOKEN` | 产品详情页“防火墙 → 复制添加网段链接”中 `pgnfw_` 开头的那一段；不填则不自动加白名单 |
| `AUTO_FW` | `1` 切换网络时自动加白名单，`0` 关闭 |
| `FW_NOTIFY` | `1` 成功也通知，`0` 只在失败时通知 |
| `INTERVAL` | 面板自动刷新间隔（秒） |

账号密码只保存在你手机的 Surge 模块参数里，本仓库不包含任何账号信息。

## 原理

- 登录 `console.po0.io`（WHMCS），调用控制台自带接口
  `/modules/servers/penguin/api/productInfo.php?serviceId=<SID>`，读取
  `txTransfer` / `rxTransfer` / `remainingTransfer` / `totalTransfer`（单位 KB）。
- WHMCS 会话绑定 IP，换网络后会自动重新登录；获取失败时面板显示上一次的缓存数据。
- 防火墙请求强制走 `DIRECT`，保证加入白名单的是手机真实出口 IP。白名单最多 5 条，新网段会顶掉最旧的一条。
