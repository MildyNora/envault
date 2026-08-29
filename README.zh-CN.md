<div align="center">

# Envault

<a href="README.md">English</a> · <b>简体中文</b>

**面向编程 agent 的本地加密密钥库，轻量够用 —— 让 AI 用你的密钥干活，却始终看不到它们。**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![Status](https://img.shields.io/badge/status-beta-yellow)

<br/>

<img src="docs/dashboard.png" alt="envault 的 dashboard：一个交互式的加密密钥库" width="860">

</div>

---

API key、token、密码，只要存一次。之后 agent 只认**名字**，命令统统交给 envault 来跑 —— 明文只在 envault 拉起的那个进程里短暂存在，绝不会进入模型上下文、写进 `.env`，也不会落到你的聊天记录里。

> **你要记的命令只有一个：`envault`。** 它会打开上面那个 dashboard，加密钥、改设置都在里面完成。下面那些 `envault …`（`run`、`link`、`request`……）都是 agent 自己去敲的 —— 它从 envault 装好的 skill 里就学会了，你基本不用亲自动手。

## 安装

**Homebrew（macOS / Linux）：**

```bash
brew install MildyNora/envault/envault
```

**或者用免 Rust 的安装脚本** —— 它还会顺手建好密钥库、配好 skill：

```bash
curl -fsSL https://raw.githubusercontent.com/MildyNora/envault/master/install.sh | bash
```
```powershell
# Windows（PowerShell）
irm https://raw.githubusercontent.com/MildyNora/envault/master/install.ps1 | iex
```

**或者从源码装**（需要 [Rust](https://rustup.rs)）：

```bash
git clone https://github.com/MildyNora/envault.git && cd envault && ./install.sh
```

装好后跑一句 **`envault`** 打开 dashboard（首次启动会问你要不要建密钥库）；`envault skill install` 负责给 agent 配置。macOS、Windows、Linux 都支持。

## 👤 给你：dashboard

跑一句 **`envault`** 就够了。加密钥、改密钥、开关 **Touch ID** 和审计日志、轮换（rotate）密钥对 —— 全在这个 TUI 里点几下搞定，一个命令都不用背。改设置和轮换都要过 Touch ID / Windows Hello 这一关，所以 agent 替不了你。

## 🤖 给 agent：只有密文

agent 从头到尾能看到的，只有**名字**和一串 age 加密后的密文。它把名字接到某个环境变量上，再让 envault 去跑命令 —— 真实的值由 envault 塞进去，并在输出里被抹掉：

```console
$ envault link OPENAI_API_KEY openai
$ envault run -- python app.py      # 注入真实值，输出被屏蔽
```

碰到一个你还没存过的密钥，它不会让你在聊天框里贴出来，而是发起一次 `request`，弹个窗口给你：

<p align="center">
  <img src="docs/request.png" alt="envault 的 request 窗口：你把密钥交给 agent，它却看不到具体的值" width="720">
</p>

你贴一次就好（agent 全程看不到），不想给就直接拒。`envault skill install` 会把这套流程教给 Claude Code、Codex 和 opencode。你也可以自己先把密钥存好，再把名字告诉 agent。

<details>
<summary><b>agent 会用到的命令</b>（你不用管）</summary>

| 命令 | 作用 |
|---|---|
| `envault ls --json` | 列出密钥**名字**（从不显示值） |
| `envault link <VAR> <name>` | 把环境变量绑到某个名字 |
| `envault run -- <cmd>` | 注入密钥跑命令，并抹掉输出里的值 |
| `envault request <name>` | 向你索要它还没有的密钥 |
| `envault fill <name>` | 把密钥填进浏览器输入框（需手动开启） |
| `envault import <.env>` | 把 dotenv 文件加密进密钥库 |

</details>

## 工作原理

<p align="center">
  <img src="docs/architecture.svg" alt="envault 架构：可信区（你 + OS keychain）、不可信的 agent 区，以及经过密钥库的数据流" width="520">
</p>

所有密钥都用 [age](https://age-encryption.org) 加密；私钥一直待在你的 **OS keychain** 里，绝不会以明文写进磁盘。完整的设计与威胁模型见 [`docs/how-it-works.md`](docs/how-it-works.md)。

## 它管什么、不管什么

envault 要防的，是密钥漏进 agent 的上下文、漏进你的文件这类**意外泄漏和 prompt 泄漏**。它**不是运行时沙箱**：真要有个以**你的身份**跑起来的恶意进程，它照样能借 `envault run` 用到密钥（这种情况极少）；机器一旦被彻底拿下，审计日志也可能就此失灵。如果你担心的正是这些，那该上系统级隔离了。细节见 [SECURITY.md](SECURITY.md)。

## 参与贡献

欢迎提 issue 和 PR，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。发现安全漏洞的话，请**别**公开提 issue —— 走 [SECURITY.md](SECURITY.md)。

## 许可证

[MIT](LICENSE) · 目前还是 beta —— keychain 和生物识别这块，建议先在你自己的真机上验一遍。
