<div align="center">

# Envault

<a href="README.md">English</a> · <b>简体中文</b>

**为编程 agent 打造的本地、极简、加密的密钥保险库 —— 让你的 AI 使用你的密钥和机密，却永远看不到它们。**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![Status](https://img.shields.io/badge/status-beta-yellow)

<br/>

<img src="docs/dashboard.png" alt="envault dashboard —— 交互式的加密密钥保险库" width="860">

</div>

---

把你的 API key、token 和密码存一次。你的编程 agent 只通过**名称**来引用它们，并借助 envault 运行命令 —— 明文只存在于 envault 启动的那个进程里，永远不会进入模型的上下文、`.env` 文件或你的聊天记录。

> **你**唯一需要运行的命令就是 **`envault`** —— 它会打开上面的 dashboard，你在里面添加密钥、修改设置。下面其他所有 `envault …` 命令（`run`、`link`、`request` …）都是由你的**编程 agent** 写出来的，它从 envault 安装的 skill 里学会这些用法。你几乎不用自己敲这些命令。

## 安装

**预编译二进制 —— 无需 Rust：**

```bash
curl -fsSL https://raw.githubusercontent.com/MildyNora/envault/master/install.sh | bash
```
```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/MildyNora/envault/master/install.ps1 | iex
```

或者**从源码安装**（需要 [Rust](https://rustup.rs)）：

```bash
git clone https://github.com/MildyNora/envault.git && cd envault && ./install.sh
```

以上任意一种方式都会安装二进制、创建你的保险库，并配置好 agent skill。支持 macOS、Windows 和 Linux；重新运行即可升级。

## 👤 给你 —— dashboard

运行 **`envault`**。一切都在这个 TUI 里（见上图）：添加和编辑密钥、开关 **Touch ID** 和**审计日志**、以及**轮换（rotate）**你的密钥对 —— 不用记任何命令。修改设置或轮换密钥都需要经过 Touch ID / Windows Hello 验证，因此 agent 无法替你完成这些操作。

## 🤖 给你的 agent —— 它只看到密文

你的 agent 永远只能看到**名称，以及经 age 加密的密文**。它把一个名称映射到环境变量，再通过 envault 运行你的命令，由 envault 注入真实的值，并把它**从输出中屏蔽掉**：

```console
$ envault link OPENAI_API_KEY openai
$ envault run -- python app.py      # 注入真实值 · 输出被屏蔽
```

当它需要一个你还没存过的密钥时，它不会让你把密钥粘贴到聊天里 —— 而是发起 `request`，随后弹出一个窗口给你：

<p align="center">
  <img src="docs/request.png" alt="envault request 窗口 —— 你把密钥交给 agent，而它永远看不到具体的值" width="720">
</p>

你只需粘贴一次（agent 永远看不到），或者直接拒绝。`envault skill install` 会把这套工作流教给 Claude Code、Codex 和 opencode。你也可以手动把密钥配置好，再把它们的名称告诉 agent。

<details>
<summary><b>你的 agent 会运行的命令</b> —— 你不需要用到这些</summary>

| 命令 | 作用 |
|---|---|
| `envault ls --json` | 列出密钥**名称**（从不显示值） |
| `envault link <VAR> <name>` | 把环境变量映射到某个名称 |
| `envault run -- <cmd>` | 运行命令，注入密钥并屏蔽输出 |
| `envault request <name>` | 向你索取它还没有的密钥 |
| `envault fill <name>` | 把密钥填入浏览器输入框（需手动开启） |
| `envault import <.env>` | 把 dotenv 文件加密导入保险库 |

</details>

## 工作原理

<p align="center">
  <img src="docs/architecture.svg" alt="envault 架构：可信区（你 + OS keychain）与不可信的 agent 区，以及经过保险库的编号数据流" width="520">
</p>

所有密钥都经过 [age](https://age-encryption.org) 加密；私钥保存在你的 **OS keychain** 中，绝不会以明文落到磁盘上。完整的设计与威胁模型见 [`docs/how-it-works.md`](docs/how-it-works.md)。

## 适用范围与坦诚的边界

envault 的目标是把密钥**挡在你的 agent 的上下文和你的文件之外** —— 也就是防住 prompt 泄漏和意外暴露这类威胁。它**不是运行时沙箱**：在极少数情况下，一个真正恶意、以**你的身份**运行的进程，仍然可以通过 `envault run` 使用某个密钥；而一台被完全攻陷的机器甚至能让审计日志从此停止记录。如果这才是你的威胁模型，你需要的是操作系统级别的隔离。详见 [SECURITY.md](SECURITY.md)。

## 参与贡献

欢迎提 issue 和 PR —— 见 [CONTRIBUTING.md](CONTRIBUTING.md)。发现了安全漏洞？请**不要**公开提 issue —— 见 [SECURITY.md](SECURITY.md)。

## 许可证

[MIT](LICENSE) · beta —— 请在你自己的真实硬件上验证 keychain / 生物识别相关的流程。
