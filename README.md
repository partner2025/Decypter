# Decrypter

音乐加密格式解密工具，纯单机版，无需联网，不收集任何数据。

支持将网易云音乐 `.ncm` 和咪咕音乐 `.mg3d` 加密音频解密为可播放的普通音频文件。

## 功能特性

- **网易云 `.ncm`** → `.mp3` / `.flac`
- **咪咕 `.mg3d`** → `.wav`
- 拖拽文件到窗口即可解密（支持批量多选）
- 实时进度显示
- 解密后可单文件另存为或批量保存到文件夹
- 也可直接把文件拖到 `Decrypter.exe` 图标上，自动解密到同目录
- 单文件实现，不依赖任何第三方库

## 使用方法

### 图形界面

1. 双击 `Decrypter.exe` 启动程序
2. 选择解密格式（自动识别 / 网易云 NCM / 咪咕 MG3D）
3. 将 `.ncm` 或 `.mg3d` 文件拖入窗口，或点击「选择加密音频」按钮
4. 解密完成后点击「保存音频」保存到本地

### 命令行（拖放模式）

直接把加密音频文件拖到 `Decrypter.exe` 图标上，程序会自动解密并将结果保存到原文件所在目录。

## 编译

需要 MinGW / TDM-GCC 编译器。

```bash
# 1. 编译资源文件
windres app.rc -o app_res.o

# 2. 编译主程序
g++ -std=c++14 -municode -mwindows -O2 -static main.cpp app_res.o -o Decrypter.exe ^
    -luser32 -lgdi32 -lcomctl32 -lcomdlg32 -lole32 -lshell32
```

> **重要**：编译时务必加上 `-static`，否则 exe 会依赖 `libstdc++-6.dll`、`libgcc_s_seh-1.dll`，
> 在没安装 MinGW 的电脑上双击会打不开（提示缺少 DLL）。

如果 `windres` 提示预处理器错误，可改用以下方式：

```bash
gcc -E -xc-header -DRC_INVOKED app.rc -o app.rc.pp
windres --preprocessor "type" app.rc.pp -o app_res.o
```

## 目录结构

```
.
├── main.cpp          # 主程序源代码（单文件）
├── app.rc            # Windows 资源定义
├── app.ico           # 程序图标
├── app.manifest      # Windows 清单文件
├── Decrypter.exe     # 编译好的可执行文件
├── README.md         # 本文件
├── .gitignore        # Git 忽略规则
└── LICENSE           # 开源协议
```

## 说明

- 本工具仅用于个人学习与研究，请遵守相关法律法规
- 解密后的音频版权归原版权方所有，请勿用于商业用途
- 全部解密过程在本机完成，不上传任何数据

