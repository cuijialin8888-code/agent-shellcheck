<div align="center">
  <img src="assets/logo.svg" width="116" alt="agent-shellcheck 标志">
  <h1>agent-shellcheck</h1>
  <p><strong>面向 AGENTS.md 与 SKILL.md 的 ShellCheck。</strong></p>
  <p>在用户踩坑之前，找出 Bash、PowerShell、cmd、路径与 WSL 的可移植性问题。</p>
  <p>
    <a href="https://github.com/cuijialin8888-code/agent-shellcheck/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cuijialin8888-code/agent-shellcheck/actions/workflows/ci.yml/badge.svg"></a>
    <img alt="Python 3.9+" src="https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white">
    <img alt="零运行时依赖" src="https://img.shields.io/badge/runtime%20dependencies-0-10b981">
    <a href="LICENSE"><img alt="MIT 许可证" src="https://img.shields.io/badge/license-MIT-0f172a"></a>
  </p>
  <p><a href="README.md">English</a> · <a href="#30-秒开始">快速开始</a> · <a href="docs/cli.md">CLI</a> · <a href="docs/rules.md">规则目录</a> · <a href="docs/ci.md">CI</a></p>
</div>

智能体指令本质上是“可执行的文档”。一段在 Bash 中完全合理的安装命令，
可能在 PowerShell 中第一行就失败；原生 Windows 命令也可能误导 WSL 用户。
`agent-shellcheck` 会在这些问题进入仓库的位置给出文件、行号、证据和修正方向。

它是一个零运行时依赖的 Python CLI：静态分析、离线运行、默认只读、结果确定。
**扫描到的命令永远不会被执行。**

<p align="center">
  <img src="assets/demo.svg" width="920" alt="agent-shellcheck 在准确行号报告 PowerShell 代码块中的 POSIX 命令">
</p>

## 30 秒开始

直接运行 GitHub 仓库版本：

```console
uvx --from git+https://github.com/cuijialin8888-code/agent-shellcheck.git agent-shellcheck .
```

或安装到隔离的 CLI 环境：

```console
pipx install git+https://github.com/cuijialin8888-code/agent-shellcheck.git
agent-shellcheck .
```

PyPI 包发布后，可以使用更短的 `pipx install agent-shellcheck` 和
`uvx agent-shellcheck .`。

无需配置。目录扫描会发现常见的智能体指令文件，并按稳定顺序输出诊断：

```text
AGENTS.md:11:1  ASC001  error  POSIX environment assignment is incompatible with PowerShell on Windows
AGENTS.md:12:1  ASC018  error  POSIX source builtin is incompatible with PowerShell on Windows

2 errors, 0 warnings, 0 info in 1 file
```

## 它检查什么

| 问题 | 典型信号 |
|---|---|
| 代码块标签与命令冲突 | <code>```powershell</code> 中出现 `export ...` |
| 环境变量语法绑定平台 | 可移植指令中出现 `$env:NAME`、`%NAME%` 或 `export NAME=...` |
| 换行符属于另一种 Shell | POSIX 反斜杠、PowerShell 反引号或 cmd 脱字符出现在错误标签下 |
| 多行输入结构不兼容 | POSIX heredoc 或 PowerShell here-string 出现在冲突代码块中 |
| 路径假定了错误宿主 | `C:\...`、`.\scripts\...` 或不匹配的虚拟环境激活路径 |
| 命令签名绑定 Shell | 可移植指令中的 `sudo`、PowerShell cmdlet 或 cmd 内置命令 |
| 重定向绑定平台 | 错误 Shell 中出现 `/dev/null` 或 PowerShell `$null` 重定向 |
| 混淆 WSL 与 Windows 执行 | 在 WSL Bash 代码块中直接调用批处理文件 |

首版规则目录包含 20 条聚焦诊断。每条结果都有准确位置、证据、受影响的 Shell
和可执行的帮助信息，详见[规则参考](docs/rules.md)。

## 为什么需要一个专门的小工具

普通 Markdown linter 擅长结构和样式；ShellCheck、PSScriptAnalyzer 等工具擅长
分析单一 Shell 脚本。但是，只有结合指令文档上下文，才能回答：

- 代码块标签与里面的命令是否一致？
- 未标注的安装步骤是否真的可移植？
- Linux、WSL 与原生 Windows 是否被当成三个不同目标？
- 平台专用路径是否给出了清楚标注的替代方案？

`agent-shellcheck` 只解决这个窄而真实的空缺。它应与 ShellCheck、
PSScriptAnalyzer、测试和安全审查配合使用，而不是替代这些工具。

## 用法

扫描当前仓库并自动判断目标：

```console
agent-shellcheck .
```

检查原生 Windows 与 POSIX 环境下的可用性：

```console
agent-shellcheck AGENTS.md skills/ --target portable
```

按指定环境解释未标注命令：

```console
agent-shellcheck . --target powershell-windows
agent-shellcheck . --target bash-wsl
```

生成适合自动化的报告：

```console
agent-shellcheck . --format json --output report.json
agent-shellcheck . --format sarif --output report.sarif
agent-shellcheck . --format html --output report.html
agent-shellcheck . --format github
```

在不改变诊断证据的前提下调整 CI 策略：

```console
agent-shellcheck . --min-severity warning --fail-on warning
agent-shellcheck . --ignore ASC012 --exclude "vendor/**" --max-files 500
```

默认失败阈值是 `error`。`--min-severity` 决定显示哪些结果，`--fail-on`
决定完成扫描后何时返回失败状态。失败判定会使用全部未忽略的发现项，
即使其中一部分因更高的显示阈值而未出现在报告中。

运行 `agent-shellcheck --help` 或打开 [CLI 参考](docs/cli.md)查看完整命令契约。

### 仓库级策略

提交一个 `.agent-shellcheck.json`，让本地运行与 CI 共用同一套策略：

```json
{
  "$schema": "https://raw.githubusercontent.com/cuijialin8888-code/agent-shellcheck/v0.2.0/schemas/config.schema.json",
  "version": 1,
  "target": "portable",
  "minSeverity": "warning",
  "failOn": "error",
  "exclude": ["generated/**", "vendor/**"]
}
```

命令行参数优先于仓库配置。`agent-shellcheck --show-config` 可以在不扫描文件的
情况下解释最终策略，`--no-config` 可用于隔离配置问题。详见
[仓库配置说明](docs/configuration.md)。

### 目标环境

| 目标 | 如何解释通用或未标注命令 |
|---|---|
| `auto` | 根据代码块标签与上下文推断；无法推断时要求可移植。 |
| `portable` | 同时检查原生 Windows 与 POSIX 可用性，允许明确标注的替代步骤。 |
| `bash-linux` | Linux 上的 Bash。 |
| `bash-wsl` | Windows Subsystem for Linux 中的 Bash。 |
| `powershell-windows` | 原生 Windows 上的 PowerShell。 |
| `cmd-windows` | 原生 Windows 上的 cmd.exe。 |

这个区别很重要：`/mnt/c/project` 对 WSL 很自然，却既不是 Linux 服务器路径，
也不是原生 Windows 路径。

### 自动发现的文件

- `AGENTS.md`、`AGENTS.override.md` 与 `SKILL.md`
- `CLAUDE.md`、`CLAUDE.local.md` 与 `GEMINI.md`
- `.cursorrules`、`.clinerules`、`*.instructions.md` 与 `*.mdc`

也可以显式传入其他 Markdown 文件。扫描会跳过依赖、缓存、构建、虚拟环境和
版本控制目录，并且不会跟随符号链接。

### 输出格式

| 格式 | 用途 |
|---|---|
| `text` | 本地快速反馈 |
| `json` | 有版本的程序化结果 |
| `sarif` | GitHub 代码扫描标注 |
| `markdown` | CI 摘要与评审评论 |
| `html` | 可离线分享的自包含报告 |
| `github` | GitHub Actions 原生行内标注 |

参阅[输出契约](docs/outputs.md)或直接复制[GitHub Actions 示例](docs/ci.md)。

仓库还提供不依赖 Node 的复合 Action：

```yaml
- uses: cuijialin8888-code/agent-shellcheck@v0.2.0
  with:
    args: ". --target portable --format github"
```

从 v0.2 起，不填写 `args` 时会默认扫描仓库并输出原生标注；Action 也会自动
读取 `.agent-shellcheck.json`。

## 扫描的可信边界

- **不执行命令：** 指令里的命令始终只是待分析文本。
- **运行时不联网：** 分析只依赖 Python 标准库。
- **不改源文件：** 只有显式指定的报告文件可以被写入。
- **证据稳定：** 文件与结果稳定排序，规则 ID 不随意复用。
- **发现范围受控：** 不递归消费符号链接、依赖树、缓存和超大文件。
- **不夸大能力：** 它不是全 Shell 解析器、提示注入检测器或完整安全扫描器。

完整边界见[设计与信任模型](docs/design.md)。

## 更清楚的指令通常也更可移植

不要隐藏单平台假设：

````markdown
```console
source .venv/bin/activate
```
````

应明确标注替代步骤：

````markdown
**Bash（Linux 或 WSL）**

```bash
. .venv/bin/activate
```

**PowerShell（Windows）**

```powershell
. .venv\Scripts\Activate.ps1
```
````

目标不是强迫所有人使用“最小公分母”命令，而是让所需环境清楚可见，并为不同
读者提供真正能走通的路径。

## 参与贡献

误报反馈尤其有价值。一条好的新规则应包含：最小触发示例、相邻的不触发示例，
以及平台的一手文档。请从 [CONTRIBUTING.md](CONTRIBUTING.md) 开始，或使用
仓库内的结构化 Issue 表单。

## 许可证

[MIT](LICENSE) · 为跨 Shell 协作的人与编码智能体而构建。
