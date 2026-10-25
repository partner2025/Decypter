// =============================================================================
//  Decrypter - 音乐加密格式解密工具 (单机版)
//  单文件 Win32 GUI 程序，自带 AES-128-ECB 与 NCM/MG3D 解密算法，不依赖任何第三方库。
//
//  支持格式:
//    · 网易云 .ncm  -> .mp3 / .flac
//    · 咪咕   .mg3d -> .wav
//
//  使用方式:
//    1. 启动程序后，把加密音频文件拖入窗口，或点击"选择加密音频"按钮
//    2. 解密完成后点击"保存音频"，单文件弹出另存为，多文件选择文件夹批量保存
//    3. 也可直接把 .ncm / .mg3d 文件拖到 exe 图标上，自动解密到同目录
//
//  编译 (MinGW / TDM-GCC):
//    g++ -std=c++14 -municode -mwindows -O2 -static main.cpp -o Decrypter.exe ^
//        -luser32 -lgdi32 -lcomctl32 -lcomdlg32 -lole32 -lshell32
//    说明: 必须加 -static, 否则 exe 依赖 libstdc++-6.dll / libgcc_s_seh-1.dll,
//          在没装 MinGW 的电脑上双击会打不开。
// =============================================================================

#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef UNICODE
#define UNICODE
#endif
#define WINVER       0x0501
#define _WIN32_WINNT 0x0501
#define _WIN32_IE    0x0501

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <memory>
#include <algorithm>
#include <functional>

// =========================== 常量 / 配色 ===========================
static const COLORREF ACCENT      = RGB(0x2F, 0x6F, 0xED);
static const COLORREF ACCENT_DARK = RGB(0x22, 0x55, 0xC4);
static const COLORREF ACCENT_SOFT = RGB(0xE8, 0xF0, 0xFE);
static const COLORREF COL_BG      = RGB(0xF3, 0xF5, 0xF9);
static const COLORREF COL_TEXT    = RGB(0x25, 0x2B, 0x37);
static const COLORREF COL_GRAY    = RGB(0x77, 0x7E, 0x8C);
static const COLORREF COL_WHITE   = RGB(0xFF, 0xFF, 0xFF);

// 控件 ID
#define IDC_SELECT_BTN  2002
#define IDC_SAVE_BTN    2003
#define IDC_LISTVIEW    2004
#define IDC_STATUS      2006
#define IDC_FMT_COMBO   2008
#define IDC_FMT_LABEL   2009
#define IDC_TITLE_SUB   2010

#define IDM_ABOUT   4004
#define IDM_EXIT    4003
#define IDM_OPEN    4005
#define IDM_SAVE    4006

#define WM_APP_PROGRESS (WM_APP + 1)
#define WM_APP_DONE     (WM_APP + 2)

// =========================== 工具函数 ===========================
static std::wstring utf8ToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(n, 0);
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}
static std::string wToUtf8(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n, nullptr, nullptr);
    return out;
}
static std::wstring baseNameNoExt(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    size_t start = (slash == std::wstring::npos) ? 0 : slash + 1;
    size_t dot = path.find_last_of(L'.');
    size_t end = (dot == std::wstring::npos || dot < start) ? path.size() : dot;
    return path.substr(start, end - start);
}
// 清洗文件名: 去掉非法字符, 限制长度
static std::wstring sanitizeName(const std::wstring& in) {
    std::wstring out;
    const wchar_t* bad = L"\\/:*?\"<>|";
    for (size_t i = 0; i < in.size() && out.size() < 60; ++i) {
        wchar_t c = in[i];
        if (wcschr(bad, c) || (unsigned)c < 0x20) c = L'_';
        out += c;
    }
    while (!out.empty() && (out.back() == L' ' || out.back() == L'.')) out.pop_back();
    if (out.empty()) out = L"未命名";
    return out;
}
static std::wstring truncStr(const std::wstring& s, size_t maxch) {
    if (s.size() <= maxch) return s;
    return s.substr(0, maxch) + L"...";
}
static std::wstring fmtSize(long long n) {
    wchar_t buf[64];
    if (n >= (1LL << 30)) swprintf(buf, 64, L"%.2f GB", n / 1073741824.0);
    else if (n >= (1LL << 20)) swprintf(buf, 64, L"%.2f MB", n / 1048576.0);
    else if (n >= 1024) swprintf(buf, 64, L"%.1f KB", n / 1024.0);
    else swprintf(buf, 64, L"%d B", (int)n);
    return buf;
}

// =========================== AES-128-ECB 实现 ===========================
namespace aes {

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const uint8_t rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void keyExpansion(const uint8_t key[16], uint8_t rk[176]) {
    for (int i = 0; i < 16; ++i) rk[i] = key[i];
    uint8_t t[4];
    for (int i = 16; i < 176; i += 4) {
        for (int j = 0; j < 4; ++j) t[j] = rk[i - 4 + j];
        if ((i & 0x0f) == 0) {
            uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int j = 0; j < 4; ++j) t[j] = sbox[t[j]];
            t[0] ^= rcon[i >> 4];
        }
        for (int j = 0; j < 4; ++j) rk[i + j] = rk[i - 16 + j] ^ t[j];
    }
}
static void addRoundKey(uint8_t s[16], const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}
static void invShiftRows(uint8_t s[16]) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    t = s[3];  s[3]  = s[7];  s[7]  = s[11]; s[11] = s[15]; s[15] = t;
}
static void invSubBytes(uint8_t s[16]) {
    for (int i = 0; i < 16; ++i) s[i] = inv_sbox[s[i]];
}
static void invMixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = s + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(gmul(0x0e,a0)^gmul(0x0b,a1)^gmul(0x0d,a2)^gmul(0x09,a3));
        col[1] = (uint8_t)(gmul(0x09,a0)^gmul(0x0e,a1)^gmul(0x0b,a2)^gmul(0x0d,a3));
        col[2] = (uint8_t)(gmul(0x0d,a0)^gmul(0x09,a1)^gmul(0x0e,a2)^gmul(0x0b,a3));
        col[3] = (uint8_t)(gmul(0x0b,a0)^gmul(0x0d,a1)^gmul(0x09,a2)^gmul(0x0e,a3));
    }
}
static void decryptBlock(uint8_t s[16], const uint8_t rk[176]) {
    addRoundKey(s, rk + 160);
    for (int round = 9; round >= 1; --round) {
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, rk + round * 16);
        invMixColumns(s);
    }
    invShiftRows(s);
    invSubBytes(s);
    addRoundKey(s, rk);
}
// ECB 解密 (仅用于 ncm 头部的密钥/元数据, 数据量很小)
static std::vector<uint8_t> ecbDecrypt(const uint8_t* data, size_t len, const uint8_t key[16]) {
    if (len == 0 || (len % 16) != 0) return {};
    uint8_t rk[176];
    keyExpansion(key, rk);
    std::vector<uint8_t> out(len);
    uint8_t blk[16];
    for (size_t i = 0; i < len; i += 16) {
        memcpy(blk, data + i, 16);
        decryptBlock(blk, rk);
        memcpy(out.data() + i, blk, 16);
    }
    return out;
}
static size_t pkcs7Unpad(const uint8_t* data, size_t len) {
    if (len == 0 || (len % 16) != 0) return len;
    uint8_t pad = data[len - 1];
    if (pad == 0 || pad > 16) return len;
    for (size_t i = 0; i < pad; ++i)
        if (data[len - 1 - i] != pad) return len;
    return len - pad;
}
} // namespace aes

// =========================== NCM 解密 (流式, 低内存) ===========================
struct NcmResult {
    bool success = false;
    std::vector<uint8_t> audio;
    std::string songName;      // UTF-8
    std::string format;        // "mp3" / "flac" / "wav"
    std::string error;
    long long fileSize = 0;
};

// Base64 解码
static bool b64Decode(const std::string& in, std::vector<uint8_t>& out) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val[256];
    for (int i = 0; i < 256; ++i) val[i] = -1;
    for (int i = 0; i < 64; ++i) val[(uint8_t)tbl[i]] = i;
    out.clear();
    out.reserve(in.size() / 4 * 3);
    int buf = 0, bits = 0;
    for (unsigned char c : in) {
        if (c == '=' || c == '\r' || c == '\n') continue;
        int v = val[c];
        if (v < 0) return false;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xff));
        }
    }
    return true;
}

static NcmResult decryptNcm(const std::wstring& path, std::function<void(float)> prog) {
    NcmResult r;
    FILE* fp = _wfopen(path.c_str(), L"rb");
    if (!fp) { r.error = "无法打开文件"; return r; }

    auto freadFull = [&](void* buf, size_t n) -> bool {
        return n == 0 || fread(buf, 1, n, fp) == n;
    };

    _fseeki64(fp, 0, SEEK_END);
    long long fsize = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);
    r.fileSize = fsize;
    if (fsize <= 0) { fclose(fp); r.error = "文件为空"; return r; }

    char magic[8];
    if (!freadFull(magic, 8)) { fclose(fp); r.error = "读取失败"; return r; }
    if (memcmp(magic, "CTENFDAM", 8) != 0) { fclose(fp); r.error = "不是有效的 NCM 文件"; return r; }

    static const uint8_t coreKey[16] = {
        0x68,0x7a,0x48,0x52,0x41,0x6d,0x73,0x6f,
        0x35,0x6b,0x49,0x6e,0x62,0x61,0x78,0x57};
    static const uint8_t metaKey[16] = {
        0x23,0x31,0x34,0x6c,0x6a,0x6b,0x5f,0x21,
        0x5c,0x5d,0x26,0x30,0x55,0x3c,0x27,0x28};

    // magic 后有 2 字节 gap
    _fseeki64(fp, 2, SEEK_CUR);

    // RC4 密钥: 4 字节小端长度, 数据先 XOR 0x64 再 AES-ECB 解密
    uint32_t keyLen = 0;
    if (!freadFull(&keyLen, 4)) { fclose(fp); r.error = "读取失败"; return r; }
    if (keyLen == 0 || keyLen > 1024 * 1024) { fclose(fp); r.error = "文件格式错误(密钥)"; return r; }
    std::vector<uint8_t> encKey(keyLen);
    if (!freadFull(encKey.data(), keyLen)) { fclose(fp); r.error = "读取失败"; return r; }
    for (size_t i = 0; i < encKey.size(); ++i) encKey[i] ^= 0x64;

    auto decKey = aes::ecbDecrypt(encKey.data(), keyLen, coreKey);
    size_t dkLen = aes::pkcs7Unpad(decKey.data(), decKey.size());
    std::string keyStr;
    if (dkLen > 17) keyStr = std::string(reinterpret_cast<char*>(decKey.data()) + 17, dkLen - 17);
    {
        const std::string pfx = "163 key(Don't modify):";
        auto pos = keyStr.find(pfx);
        if (pos != std::string::npos) keyStr = keyStr.substr(pos + pfx.size());
    }
    while (!keyStr.empty() && (keyStr.back() == '\0' || keyStr.back() == ' '))
        keyStr.pop_back();
    if (keyStr.empty()) { fclose(fp); r.error = "解析密钥失败"; return r; }

    // 元数据: 4 字节小端长度, 数据 XOR 0x63
    uint32_t metaLen = 0;
    if (!freadFull(&metaLen, 4)) { fclose(fp); r.error = "读取失败"; return r; }
    if (metaLen > 16 * 1024 * 1024) { fclose(fp); r.error = "文件格式错误(元数据)"; return r; }
    if (metaLen > 0) {
        std::vector<uint8_t> encMeta(metaLen);
        if (!freadFull(encMeta.data(), metaLen)) { fclose(fp); r.error = "读取失败"; return r; }
        for (size_t i = 0; i < encMeta.size(); ++i) encMeta[i] ^= 0x63;
        std::string meta(reinterpret_cast<char*>(encMeta.data()), encMeta.size());
        std::string body = meta;
        const std::string pfx = "163 key(Don't modify):";
        auto pos = meta.find(pfx);
        bool needAes = false;
        if (pos != std::string::npos) {
            body = meta.substr(pos + pfx.size());
            needAes = true;
        } else if (meta.find("\"musicName\"") == std::string::npos) {
            body.clear();
        }
        if (needAes) {
            std::vector<uint8_t> b64out;
            if (b64Decode(body, b64out) && !b64out.empty() && b64out.size() % 16 == 0) {
                auto dm = aes::ecbDecrypt(b64out.data(), b64out.size(), metaKey);
                size_t dmLen = aes::pkcs7Unpad(dm.data(), dm.size());
                if (dmLen > 6) body = std::string(reinterpret_cast<char*>(dm.data()) + 6, dmLen - 6);
                else body.clear();
            } else body.clear();
        }
        auto extractStr = [&](const std::string& keyfield) -> std::string {
            auto np = body.find("\"" + keyfield + "\"");
            if (np == std::string::npos) return "";
            auto cp = body.find(':', np);
            if (cp == std::string::npos) return "";
            auto q1 = body.find('"', cp);
            if (q1 == std::string::npos) return "";
            auto q2 = body.find('"', q1 + 1);
            if (q2 == std::string::npos) return "";
            return body.substr(q1 + 1, q2 - q1 - 1);
        };
        r.songName = extractStr("musicName");
        r.format = extractStr("format");
        if (!r.format.empty()) {
            for (auto& c : r.format) c = (char)tolower((unsigned char)c);
        }
    }

    // CRC(4) + gap(5)
    _fseeki64(fp, 9, SEEK_CUR);

    // 封面图: 4 字节小端长度
    uint32_t imgSize = 0;
    if (!freadFull(&imgSize, 4)) { fclose(fp); r.error = "读取失败"; return r; }
    if (imgSize > 0 && imgSize < (uint32_t)fsize)
        _fseeki64(fp, imgSize, SEEK_CUR);

    long long musicStart = _ftelli64(fp);
    if (musicStart < 0) { fclose(fp); r.error = "文件读取错误"; return r; }
    size_t musicLen = (size_t)(fsize - musicStart);
    if (musicLen == 0) { fclose(fp); r.error = "无音频数据"; return r; }

    // 构造 key box (RC4-KSA 变种)
    std::vector<uint8_t> rc4Key(keyStr.begin(), keyStr.end());
    uint8_t box[256];
    for (int i = 0; i < 256; ++i) box[i] = (uint8_t)i;
    {
        uint8_t c = 0, last = 0;
        size_t ko = 0;
        for (int i = 0; i < 256; ++i) {
            uint8_t swap = box[i];
            c = (uint8_t)((swap + last + rc4Key[ko]) & 0xff);
            ko++;
            if (ko >= rc4Key.size()) ko = 0;
            box[i] = box[c];
            box[c] = swap;
            last = c;
        }
    }

    // 流式解密: 第 k 字节(0起) 用流索引 j=(k+1)&0xff
    r.audio.reserve(musicLen);
    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK);
    size_t processed = 0;
    while (processed < musicLen) {
        size_t n = (std::min)(CHUNK, musicLen - processed);
        if (fread(buf.data(), 1, n, fp) != n) { fclose(fp); r.error = "读取音频数据失败"; return r; }
        uint8_t* p = buf.data();
        for (size_t k = 0; k < n; ++k) {
            unsigned j = (unsigned)((processed + k + 1) & 0xff);
            p[k] ^= box[(box[j] + box[(box[j] + j) & 0xff]) & 0xff];
        }
        r.audio.insert(r.audio.end(), buf.begin(), buf.begin() + n);
        processed += n;
        if (prog) prog((float)((double)processed / (double)musicLen));
    }
    fclose(fp);
    if (prog) prog(1.0f);

    // 校验音频头
    if (r.audio.size() >= 4) {
        bool isMp3 = r.audio[0] == 'I' && r.audio[1] == 'D' && r.audio[2] == '3';
        bool isMp3Raw = r.audio[0] == 0xFF && (r.audio[1] & 0xE0) == 0xE0;
        bool isFlac = r.audio[0] == 'f' && r.audio[1] == 'L' && r.audio[2] == 'a' && r.audio[3] == 'C';
        if (!isMp3 && !isMp3Raw && !isFlac) {
            r.audio.clear();
            r.error = "解密校验失败(密钥不匹配)";
            return r;
        }
        if (r.format.empty()) r.format = isFlac ? "flac" : "mp3";
    }

    r.success = true;
    return r;
}

// =========================== 咪咕 MG3D 解密 ===========================
// 算法依据 unlock-music 开源实现 (MIT):
//   密钥藏在文件 0x20 起、每 0x20 字节一段(前 19 段)的 32 字节大写 HEX 串中;
//   对候选密钥: 头 0x100 字节每字节做 (data - key[i%32]) 模 256,
//   校验 RIFF / WAVEfmt / fmt 块大小 16|18|40 / 后续块名可打印;
//   用首个有效密钥对全文件做同样的减法, 输出 WAV。
static NcmResult decryptMg3d(const std::wstring& path, std::function<void(float)> prog) {
    NcmResult r;
    FILE* fp = _wfopen(path.c_str(), L"rb");
    if (!fp) { r.error = "无法打开文件"; return r; }
    _fseeki64(fp, 0, SEEK_END);
    long long fsize = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);
    r.fileSize = fsize;
    if (fsize < 0x280) { fclose(fp); r.error = "MG3D 文件过小或已损坏"; return r; }

    const int SEG = 0x20;
    uint8_t head[0x280];
    if (fread(head, 1, sizeof(head), fp) != sizeof(head)) {
        fclose(fp); r.error = "读取文件头失败"; return r;
    }

    auto isHexUpper = [](uint8_t c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
    };
    auto isPrintable = [](uint8_t c) { return c >= 0x20 && c <= 0x7E; };
    auto rd32le = [](const uint8_t* p) -> uint32_t {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    };

    uint8_t key[SEG] = {0};
    bool found = false;
    uint8_t trial[0x100];
    for (int i = SEG; i < SEG * 20 && i + SEG <= (int)sizeof(head); i += SEG) {
        const uint8_t* cand = head + i;
        bool hexOk = true;
        for (int j = 0; j < SEG; ++j) if (!isHexUpper(cand[j])) { hexOk = false; break; }
        if (!hexOk) continue;
        for (int j = 0; j < 0x100; ++j) trial[j] = (uint8_t)(head[j] - cand[j % SEG]);
        if (memcmp(trial, "RIFF", 4) != 0) continue;
        if (memcmp(trial + 8, "WAVEfmt ", 8) != 0) continue;
        uint32_t fmtSize = rd32le(trial + 0x10);
        if (fmtSize != 16 && fmtSize != 18 && fmtSize != 40) continue;
        int chunk1 = 0x14 + (int)fmtSize;
        if (chunk1 + 8 > 0x100) continue;
        bool c1 = true;
        for (int j = 0; j < 4; ++j) if (!isPrintable(trial[chunk1 + j])) { c1 = false; break; }
        if (!c1) continue;
        int chunk2 = chunk1 + 8 + (int)rd32le(trial + chunk1 + 4);
        if (chunk2 + 4 <= 0x100) {
            bool c2 = true;
            for (int j = 0; j < 4; ++j) if (!isPrintable(trial[chunk2 + j])) { c2 = false; break; }
            if (!c2) continue;
        }
        memcpy(key, cand, SEG);
        found = true;
        break;
    }
    if (!found) { fclose(fp); r.error = "未找到 MG3D 内嵌密钥(文件可能已更新格式)"; return r; }

    // 流式整文件解密: p[k] = (p[k] - key[k % 32]) mod 256
    _fseeki64(fp, 0, SEEK_SET);
    r.audio.reserve((size_t)fsize);
    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK);
    long long processed = 0;
    while (processed < fsize) {
        size_t n = (std::min)(CHUNK, (size_t)(fsize - processed));
        if (fread(buf.data(), 1, n, fp) != n) { fclose(fp); r.error = "读取音频数据失败"; return r; }
        for (size_t k = 0; k < n; ++k) {
            size_t pos = (size_t)processed + k;
            buf[k] = (uint8_t)(buf[k] - key[pos % SEG]);
        }
        r.audio.insert(r.audio.end(), buf.begin(), buf.begin() + n);
        processed += (long long)n;
        if (prog) prog((float)((double)processed / (double)fsize));
    }
    fclose(fp);
    if (r.audio.size() < 12 || memcmp(r.audio.data(), "RIFF", 4) != 0 ||
        memcmp(r.audio.data() + 8, "WAVE", 4) != 0) {
        r.audio.clear();
        r.error = "MG3D 解密校验失败";
        return r;
    }
    r.format = "wav";
    if (prog) prog(1.0f);
    r.success = true;
    return r;
}

// 格式选择
enum FmtChoice { FMT_AUTO = 0, FMT_NCM = 1, FMT_MG3D = 2 };

static std::wstring extOf(const std::wstring& path) {
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) return L"";
    std::wstring e = path.substr(dot + 1);
    for (auto& c : e) c = (wchar_t)towlower((wint_t)c);
    return e;
}

// 按选择的格式分发解密
static NcmResult decryptFile(const std::wstring& path, int choice,
                             std::function<void(float)> prog) {
    NcmResult r;
    int fmt = choice;
    if (fmt == FMT_AUTO) {
        std::wstring e = extOf(path);
        if (e == L"ncm") fmt = FMT_NCM;
        else if (e == L"mg3d") fmt = FMT_MG3D;
        else { r.error = "不支持的文件类型, 仅支持 .ncm(网易云) 和 .mg3d(咪咕)"; return r; }
    }
    switch (fmt) {
    case FMT_NCM:  return decryptNcm(path, prog);
    case FMT_MG3D: return decryptMg3d(path, prog);
    default:
        r.error = "不支持的文件类型, 仅支持 .ncm(网易云) 和 .mg3d(咪咕)";
        return r;
    }
}

// =========================== 全局状态 ===========================
static HINSTANCE g_hInst = nullptr;
static HWND g_mainWnd  = nullptr;
static HWND g_progress = nullptr;
static HWND g_status   = nullptr;
static HWND g_saveBtn  = nullptr;
static HWND g_listview = nullptr;

static HFONT hFontUI = nullptr, hFontBold = nullptr, hFontTitle = nullptr,
             hFontSmall = nullptr, hFontZoneT = nullptr, hFontZoneS = nullptr;

static bool   g_busy = false;
static HANDLE g_thread = nullptr;

static std::vector<std::wstring> g_queue;
static int       g_queueIndex = 0;
static long long g_totalBytes = 0, g_doneBytes = 0, g_curFileSize = 0;
static int       g_fmtChoice = FMT_AUTO;
static HWND      g_fmtCombo = nullptr;

static const wchar_t* fmtExt(int choice) {
    switch (choice) {
    case FMT_NCM:  return L"ncm";
    case FMT_MG3D: return L"mg3d";
    }
    return nullptr;
}
static bool isSupportedExt(const std::wstring& e) {
    return e == L"ncm" || e == L"mg3d";
}

struct ResultRec {
    std::wstring path, song, err, fmt;
    bool ok = false;
    long long size = 0;
    std::vector<uint8_t> data;
};
static std::vector<ResultRec> g_results;

static RECT g_dropRect = {30, 116, 610, 288};

// 前向声明
static void CreateMainWindow();
static void OpenChooseFiles(HWND owner);
static void StartQueue();

// =========================== 绘制辅助 ===========================
static void centerWindow(HWND w) {
    RECT rc; GetWindowRect(w, &rc);
    int ww = rc.right - rc.left, wh = rc.bottom - rc.top;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(w, nullptr, (sw - ww) / 2, (sh - wh) / 2 - 20, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}
// 圆角按钮自绘
static void drawButton(LPDRAWITEMSTRUCT di, bool primary) {
    HDC dc = di->hDC;
    RECT rc = di->rcItem;
    bool pressed  = (di->itemState & ODS_SELECTED) != 0;
    bool disabled = (di->itemState & ODS_DISABLED) != 0;
    COLORREF fill = disabled ? RGB(0xD3, 0xD8, 0xE2)
                             : (pressed ? (primary ? ACCENT_DARK : ACCENT_SOFT)
                                        : (primary ? ACCENT : COL_WHITE));
    COLORREF txt  = disabled ? RGB(0x98, 0x9E, 0xAC)
                             : (primary ? COL_WHITE : ACCENT);
    HBRUSH br = CreateSolidBrush(fill);
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, 10, 10);
    FillRgn(dc, rgn, br);
    DeleteObject(rgn);
    DeleteObject(br);
    if (!primary) {
        HPEN pen = CreatePen(PS_SOLID, 1, disabled ? RGB(0xD8, 0xDC, 0xE4) : ACCENT);
        HGDIOBJ op = SelectObject(dc, pen);
        HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, 10, 10);
        SelectObject(dc, op);
        SelectObject(dc, ob);
        DeleteObject(pen);
    }
    wchar_t txtbuf[128] = {0};
    GetWindowTextW(di->hwndItem, txtbuf, 128);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, txt);
    HGDIOBJ of = SelectObject(dc, primary ? hFontBold : hFontUI);
    DrawTextW(dc, txtbuf, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, of);
}
// 主窗口背景: 蓝色标题带 + 浅灰主体
static void paintBackground(HDC dc, HWND hWnd, int headerH) {
    RECT rc; GetClientRect(hWnd, &rc);
    HBRUSH body = CreateSolidBrush(COL_BG);
    RECT bodyRc = {0, headerH, rc.right, rc.bottom};
    FillRect(dc, &bodyRc, body);
    DeleteObject(body);
    HBRUSH hdr = CreateSolidBrush(ACCENT);
    RECT hdrRc = {0, 0, rc.right, headerH};
    FillRect(dc, &hdrRc, hdr);
    DeleteObject(hdr);
    HBRUSH line = CreateSolidBrush(ACCENT_DARK);
    RECT lineRc = {0, headerH, rc.right, headerH + 2};
    FillRect(dc, &lineRc, line);
    DeleteObject(line);
}
static void onCtlColorStatic(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT& ret) {
    HDC dc = (HDC)wParam;
    static HBRUSH bgBrush = CreateSolidBrush(COL_BG);
    SetBkColor(dc, COL_BG);
    int id = GetDlgCtrlID((HWND)lParam);
    if (id == IDC_STATUS || id == IDC_TITLE_SUB) {
        SetTextColor(dc, COL_GRAY);
    } else {
        SetTextColor(dc, COL_TEXT);
    }
    ret = (LRESULT)bgBrush;
    (void)hWnd; (void)msg;
}
static void lvSetup(HWND lv) {
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    ListView_SetBkColor(lv, COL_WHITE);
    ListView_SetTextBkColor(lv, COL_WHITE);
    SendMessageW(lv, WM_SETFONT, (WPARAM)hFontUI, TRUE);
}
static void lvAddRow(HWND lv, const wchar_t* c0, const wchar_t* c1,
                     const wchar_t* c2, const wchar_t* c3) {
    LVITEMW it = {0};
    it.mask = LVIF_TEXT;
    it.iItem = ListView_GetItemCount(lv);
    it.pszText = (LPWSTR)c0;
    int idx = ListView_InsertItem(lv, &it);
    ListView_SetItemText(lv, idx, 1, (LPWSTR)c1);
    ListView_SetItemText(lv, idx, 2, (LPWSTR)c2);
    ListView_SetItemText(lv, idx, 3, (LPWSTR)c3);
}

// =========================== 解密线程与队列 ===========================
static DWORD WINAPI decryptThread(LPVOID p) {
    std::wstring path = *(std::wstring*)p;
    delete (std::wstring*)p;
    NcmResult* res = new NcmResult();
    *res = decryptFile(path, g_fmtChoice, [](float pr) {
        PostMessageW(g_mainWnd, WM_APP_PROGRESS, (WPARAM)(int)(pr * 1000.0f), 0);
    });
    PostMessageW(g_mainWnd, WM_APP_DONE, (WPARAM)res, 0);
    return 0;
}

static void addResultRow(const ResultRec& rec) {
    if (!g_listview) return;
    std::wstring name = truncStr(baseNameNoExt(rec.path), 28);
    std::wstring song = truncStr(rec.song, 22);
    std::wstring size = fmtSize(rec.size);
    std::wstring stat = rec.ok ? L"完成" : (L"失败: " + truncStr(rec.err, 20));
    lvAddRow(g_listview, name.c_str(), song.c_str(), size.c_str(), stat.c_str());
}

static void startNextInQueue() {
    if (g_queueIndex >= (int)g_queue.size()) {
        g_busy = false;
        int ok = 0;
        for (auto& r : g_results) if (r.ok) ++ok;
        SendMessageW(g_progress, PBM_SETPOS, g_totalBytes ? 1000 : 0, 0);
        if (ok > 0) {
            EnableWindow(g_saveBtn, TRUE);
            InvalidateRect(g_saveBtn, nullptr, TRUE);
            std::wstring s = L"解密完成! 成功 " + std::to_wstring(ok) + L" 个文件, 点击\"保存音频\"保存到本地。";
            SetWindowTextW(g_status, s.c_str());
        } else {
            SetWindowTextW(g_status, L"解密失败。");
        }
        return;
    }
    const std::wstring& p = g_queue[g_queueIndex];
    WIN32_FILE_ATTRIBUTE_DATA fa;
    long long sz = 0;
    if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fa))
        sz = ((long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    g_curFileSize = sz;
    std::wstring st = L"正在解密 (" + std::to_wstring(g_queueIndex + 1) + L"/" +
                      std::to_wstring(g_queue.size()) + L"): " +
                      truncStr(baseNameNoExt(p), 24);
    SetWindowTextW(g_status, st.c_str());
    g_thread = CreateThread(nullptr, 0, decryptThread, new std::wstring(p), 0, nullptr);
}

static void beginBatch(const std::vector<std::wstring>& files) {
    g_queue = files;
    g_queueIndex = 0;
    g_doneBytes = 0;
    g_totalBytes = 0;
    g_results.clear();
    ListView_DeleteAllItems(g_listview);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    for (auto& f : g_queue) {
        if (GetFileAttributesExW(f.c_str(), GetFileExInfoStandard, &fa))
            g_totalBytes += ((long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    }
    g_busy = true;
    EnableWindow(g_saveBtn, FALSE);
    SendMessageW(g_progress, PBM_SETPOS, 0, 0);
    SetWindowTextW(g_status, L"准备解密...");
    startNextInQueue();
}

// =========================== 选择 / 保存 ===========================
static bool extMatchesChoice(const std::wstring& path) {
    std::wstring e = extOf(path);
    if (g_fmtChoice == FMT_AUTO) return isSupportedExt(e);
    const wchar_t* want = fmtExt(g_fmtChoice);
    return want && e == want;
}

static void OpenChooseFiles(HWND owner) {
    if (g_busy) { MessageBoxW(owner, L"正在解密中, 请稍候...", L"提示", MB_OK); return; }
    OPENFILENAMEW ofn = {0};
    static wchar_t szFile[32768] = {0};
    szFile[0] = 0;
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = 32768;
    const wchar_t* filter;
    switch (g_fmtChoice) {
    case FMT_NCM:  filter = L"网易云 NCM 文件 (*.ncm)\0*.ncm\0所有文件 (*.*)\0*.*\0"; break;
    case FMT_MG3D: filter = L"咪咕 MG3D 文件 (*.mg3d)\0*.mg3d\0所有文件 (*.*)\0*.*\0"; break;
    default:       filter = L"支持的加密音频 (*.ncm;*.mg3d)\0*.ncm;*.mg3d\0"
                            "所有文件 (*.*)\0*.*\0"; break;
    }
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_EXPLORER;
    ofn.lpstrTitle = L"选择加密音频文件 (可按住 Ctrl 多选)";
    if (!GetOpenFileNameW(&ofn)) return;
    std::vector<std::wstring> files;
    wchar_t* p = szFile;
    std::wstring dir = p;
    p += wcslen(p) + 1;
    if (*p) {
        while (*p) {
            std::wstring full = dir + L"\\" + p;
            if (extMatchesChoice(full)) files.push_back(full);
            p += wcslen(p) + 1;
        }
    } else {
        if (extMatchesChoice(dir)) files.push_back(dir);
    }
    if (files.empty()) {
        MessageBoxW(owner,
            g_fmtChoice == FMT_AUTO
                ? L"请选择 .ncm(网易云) 或 .mg3d(咪咕) 文件, 或在左上角指定格式。"
                : L"所选文件与左上角选择的格式不匹配。",
            L"格式提示", MB_OK | MB_ICONWARNING);
        return;
    }
    beginBatch(files);
}

static void handleDrop(HDROP hDrop) {
    std::vector<std::wstring> files;
    UINT n = DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0);
    for (UINT i = 0; i < n; ++i) {
        wchar_t path[MAX_PATH * 2] = {0};
        if (DragQueryFileW(hDrop, i, path, MAX_PATH * 2)) {
            std::wstring f(path);
            if (extMatchesChoice(f)) files.push_back(f);
        }
    }
    DragFinish(hDrop);
    if (g_busy) { MessageBoxW(g_mainWnd, L"正在解密中, 请稍候...", L"提示", MB_OK); return; }
    if (files.empty()) {
        MessageBoxW(g_mainWnd,
            L"请拖入与所选格式匹配的文件:\n.ncm(网易云) / .mg3d(咪咕)",
            L"格式提示", MB_OK | MB_ICONWARNING);
        return;
    }
    beginBatch(files);
}

static bool writeAudioFile(const std::wstring& file, const ResultRec& rec) {
    FILE* out = _wfopen(file.c_str(), L"wb");
    if (!out) return false;
    size_t w = rec.data.empty() ? 0 : fwrite(rec.data.data(), 1, rec.data.size(), out);
    fclose(out);
    return w == rec.data.size();
}

static void DoSave(HWND hWnd) {
    int ok = 0;
    const ResultRec* single = nullptr;
    for (auto& r : g_results) if (r.ok) { ++ok; single = &r; }
    if (ok == 0) { MessageBoxW(hWnd, L"没有解密成功的内容可保存。", L"提示", MB_OK); return; }

    if (ok == 1) {
        std::wstring ext = single->fmt.empty() ? L"mp3" : single->fmt;
        std::wstring defName = sanitizeName(
            single->song.empty() ? baseNameNoExt(single->path) : single->song) + L"." + ext;
        OPENFILENAMEW ofn = {0};
        wchar_t szFile[MAX_PATH] = {0};
        wcsncpy(szFile, defName.c_str(), MAX_PATH - 1);
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hWnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrFilter = L"音频文件 (*.mp3;*.flac;*.wav)\0*.mp3;*.flac;*.wav\0所有文件 (*.*)\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrDefExt = ext.c_str();
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        ofn.lpstrTitle = L"保存解密后的音频";
        if (GetSaveFileNameW(&ofn)) {
            if (writeAudioFile(szFile, *single)) {
                std::wstring msg = L"已保存到:\n" + std::wstring(szFile);
                MessageBoxW(hWnd, msg.c_str(), L"保存成功", MB_OK | MB_ICONINFORMATION);
                SetWindowTextW(g_status, L"已保存。");
            } else {
                MessageBoxW(hWnd, L"写入文件失败。", L"保存失败", MB_OK | MB_ICONERROR);
            }
        }
        return;
    }

    // 多文件 -> 选择文件夹批量保存
    BROWSEINFOW bi = {0};
    bi.hwndOwner = hWnd;
    bi.lpszTitle = L"选择保存文件夹 (将保存全部解密成功的文件)";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    wchar_t dir[MAX_PATH] = {0};
    BOOL got = SHGetPathFromIDListW(pidl, dir);
    CoTaskMemFree(pidl);
    if (!got || !dir[0]) return;

    std::set<std::wstring> used;
    int saved = 0, failed = 0;
    for (auto& r : g_results) {
        if (!r.ok) continue;
        std::wstring ext = r.fmt.empty() ? L"mp3" : r.fmt;
        std::wstring base = sanitizeName(r.song.empty() ? baseNameNoExt(r.path) : r.song);
        std::wstring name = base + L"." + ext;
        int k = 1;
        while (used.count(name)) name = base + L" (" + std::to_wstring(++k) + L")." + ext;
        used.insert(name);
        if (writeAudioFile(std::wstring(dir) + L"\\" + name, r)) ++saved; else ++failed;
    }
    wchar_t msg[128];
    swprintf(msg, 128, L"保存完成: 成功 %d 个%s", saved,
             failed ? L", 失败请重试或检查文件夹权限。" : L"。");
    MessageBoxW(hWnd, msg, L"批量保存", MB_OK | MB_ICONINFORMATION);
    SetWindowTextW(g_status, L"已批量保存。");
}

// =========================== 主窗口 ===========================
static LRESULT CALLBACK MainProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    LRESULT ret;
    switch (msg) {
    case WM_CREATE: {
        // 副标题
        CreateWindowW(L"STATIC", L"支持 .ncm(网易云) / .mg3d(咪咕)  →  mp3 / flac / wav",
            WS_CHILD | WS_VISIBLE, 28, 79, 360, 20,
            hWnd, (HMENU)IDC_TITLE_SUB, g_hInst, nullptr);
        // 右上角: 解密格式选择
        CreateWindowW(L"STATIC", L"格式:",
            WS_CHILD | WS_VISIBLE, 392, 82, 36, 18,
            hWnd, (HMENU)IDC_FMT_LABEL, g_hInst, nullptr);
        g_fmtCombo = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            428, 78, 182, 200, hWnd, (HMENU)IDC_FMT_COMBO, g_hInst, nullptr);
        const wchar_t* items[] = {
            L"自动识别", L"网易云 NCM (.ncm)", L"咪咕 MG3D (.mg3d)"
        };
        for (auto* it : items) SendMessageW(g_fmtCombo, CB_ADDSTRING, 0, (LPARAM)it);
        SendMessageW(g_fmtCombo, CB_SETCURSEL, 0, 0);

        CreateWindowW(L"BUTTON", L"选择加密音频",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            220, 308, 200, 38, hWnd, (HMENU)IDC_SELECT_BTN, g_hInst, nullptr);
        g_saveBtn = CreateWindowW(L"BUTTON", L"保存音频",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | WS_DISABLED,
            220, 540, 200, 38, hWnd, (HMENU)IDC_SAVE_BTN, g_hInst, nullptr);

        g_listview = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL,
            30, 358, 580, 122, hWnd, (HMENU)IDC_LISTVIEW, g_hInst, nullptr);
        lvSetup(g_listview);
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.cx = 220; col.pszText = (LPWSTR)L"文件";
        ListView_InsertColumn(g_listview, 0, &col);
        col.cx = 180; col.pszText = (LPWSTR)L"歌曲";
        ListView_InsertColumn(g_listview, 1, &col);
        col.cx = 90;  col.pszText = (LPWSTR)L"大小";
        ListView_InsertColumn(g_listview, 2, &col);
        col.cx = 88;  col.pszText = (LPWSTR)L"状态";
        ListView_InsertColumn(g_listview, 3, &col);

        g_progress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            30, 492, 580, 20, hWnd, (HMENU)2005, g_hInst, nullptr);
        SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 1000));
        g_status = CreateWindowW(L"STATIC", L"就绪 — 选择格式后拖入加密音频开始解密",
            WS_CHILD | WS_VISIBLE, 32, 518, 576, 20, hWnd, (HMENU)IDC_STATUS, g_hInst, nullptr);

        for (int id : {IDC_SELECT_BTN, IDC_SAVE_BTN})
            SendMessageW(GetDlgItem(hWnd, id), WM_SETFONT, (WPARAM)hFontUI, TRUE);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)hFontSmall, TRUE);
        SendMessageW(GetDlgItem(hWnd, IDC_TITLE_SUB), WM_SETFONT, (WPARAM)hFontSmall, TRUE);
        SendMessageW(GetDlgItem(hWnd, IDC_FMT_LABEL), WM_SETFONT, (WPARAM)hFontSmall, TRUE);
        SendMessageW(g_fmtCombo, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

        DragAcceptFiles(hWnd, TRUE);
        return 0;
    }
    case WM_ERASEBKGND:
        paintBackground((HDC)wParam, hWnd, 70);
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hWnd, &ps);
        // 标题带文字
        SetBkMode(dc, TRANSPARENT);
        RECT rc = {30, 12, 500, 40};
        SetTextColor(dc, COL_WHITE);
        SelectObject(dc, hFontTitle);
        DrawTextW(dc, L"Decrypter 音乐解密工具", -1, &rc, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        // 拖放区 (虚线圆角框)
        RECT dz = g_dropRect;
        HBRUSH white = CreateSolidBrush(COL_WHITE);
        FillRect(dc, &dz, white);
        DeleteObject(white);
        HPEN pen = CreatePen(PS_DOT, 1, ACCENT);
        HGDIOBJ op = SelectObject(dc, pen);
        HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, dz.left, dz.top, dz.right, dz.bottom, 14, 14);
        SelectObject(dc, op);
        SelectObject(dc, ob);
        DeleteObject(pen);
        RECT t1 = {dz.left, dz.top + 42, dz.right, dz.top + 78};
        SetTextColor(dc, COL_TEXT);
        SelectObject(dc, hFontZoneT);
        DrawTextW(dc, L"将加密音频拖到这里", -1, &t1, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        RECT t2 = {dz.left, dz.top + 88, dz.right, dz.top + 112};
        SetTextColor(dc, COL_GRAY);
        SelectObject(dc, hFontZoneS);
        DrawTextW(dc, L"支持一次拖入多个文件, 或点击下方按钮选择", -1, &t2,
                  DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
        onCtlColorStatic(hWnd, msg, wParam, lParam, ret);
        return ret;
    case WM_DRAWITEM:
        drawButton((LPDRAWITEMSTRUCT)lParam, ((LPDRAWITEMSTRUCT)lParam)->CtlID == IDC_SELECT_BTN);
        return TRUE;
    case WM_LBUTTONDOWN: {
        POINT pt = {LOWORD(lParam), HIWORD(lParam)};
        if (PtInRect(&g_dropRect, pt)) OpenChooseFiles(hWnd);
        return 0;
    }
    case WM_DROPFILES:
        handleDrop((HDROP)wParam);
        return 0;
    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        if (id == IDC_FMT_COMBO && HIWORD(wParam) == CBN_SELCHANGE) {
            g_fmtChoice = (int)SendMessageW(g_fmtCombo, CB_GETCURSEL, 0, 0);
            return 0;
        }
        if (id == IDC_SELECT_BTN || id == IDM_OPEN) { OpenChooseFiles(hWnd); return 0; }
        if (id == IDC_SAVE_BTN || id == IDM_SAVE) { DoSave(hWnd); return 0; }
        if (id == IDM_ABOUT) {
            MessageBoxW(hWnd,
                L"音乐解密工具 (单机版)\n\n"
                L"支持格式:\n"
                L"  · 网易云 .ncm -> mp3/flac\n"
                L"  · 咪咕   .mg3d -> wav\n\n"
                L"使用方法:\n"
                L"  把 .ncm 或 .mg3d 文件拖入窗口, 或点击\"选择加密音频\"。\n"
                L"  解密完成后点击\"保存音频\"即可保存到本地。\n"
                L"  也可直接把文件拖到 exe 图标上, 自动解密到同目录。\n\n"
                L"本程序为单机版, 无需联网, 不收集任何数据, 全部处理在本机完成。",
                L"关于", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        if (id == IDM_EXIT) { DestroyWindow(hWnd); return 0; }
        break;
    }
    case WM_APP_PROGRESS: {
        double pr = (int)wParam / 1000.0;
        long long done = g_doneBytes + (long long)(pr * (double)g_curFileSize);
        int pos = g_totalBytes > 0 ? (int)(done * 1000 / g_totalBytes) : 0;
        SendMessageW(g_progress, PBM_SETPOS, pos, 0);
        std::wstring s = L"总进度 " + std::to_wstring(pos / 10) + L"%  (" +
                         fmtSize(done) + L" / " + fmtSize(g_totalBytes) + L")";
        SetWindowTextW(g_status, s.c_str());
        return 0;
    }
    case WM_APP_DONE: {
        std::unique_ptr<NcmResult> res((NcmResult*)wParam);
        if (g_thread) { CloseHandle(g_thread); g_thread = nullptr; }
        ResultRec rec;
        rec.ok = res->success;
        rec.song = utf8ToW(res->songName);
        rec.fmt = utf8ToW(res->format);
        rec.err = utf8ToW(res->error);
        rec.size = res->success ? (long long)res->audio.size() : res->fileSize;
        rec.path = g_queue[g_queueIndex];
        if (res->success) rec.data = std::move(res->audio);
        g_doneBytes += (g_curFileSize > 0 ? g_curFileSize : 0);
        g_results.push_back(std::move(rec));
        addResultRow(g_results.back());
        ++g_queueIndex;
        startNextInQueue();
        return 0;
    }
    case WM_CLOSE:
        if (g_busy) {
            if (MessageBoxW(hWnd, L"正在解密中, 确定退出吗?", L"提示",
                            MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
        }
        DestroyWindow(hWnd);
        return 0;
    case WM_DESTROY:
        g_fmtCombo = nullptr;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static void CreateMainWindow() {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(1));
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"NCMMainClass";
    RegisterClassW(&wc);

    RECT rc = {0, 0, 640, 592};
    AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, TRUE);
    int h = rc.bottom - rc.top + GetSystemMetrics(SM_CYMENU);
    g_mainWnd = CreateWindowW(L"NCMMainClass", L"Decrypter",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, h,
        nullptr, nullptr, g_hInst, nullptr);

    HMENU mFile = CreateMenu();
    AppendMenuW(mFile, MF_STRING, IDM_OPEN, L"选择加密音频(&O)");
    AppendMenuW(mFile, MF_STRING, IDM_SAVE, L"保存音频(&S)");
    AppendMenuW(mFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(mFile, MF_STRING, IDM_EXIT, L"退出(&X)");
    HMENU mHelp = CreateMenu();
    AppendMenuW(mHelp, MF_STRING, IDM_ABOUT, L"关于(&A)");
    HMENU bar = CreateMenu();
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)mFile, L"文件(&F)");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)mHelp, L"帮助(&H)");
    SetMenu(g_mainWnd, bar);

    centerWindow(g_mainWnd);
    ShowWindow(g_mainWnd, SW_SHOW);
    UpdateWindow(g_mainWnd);
}

// =========================== WinMain ===========================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int) {
    g_hInst = hInstance;

    // 命令行模式: 把加密音频拖到 exe 图标上, 直接解密保存到同目录
    {
        std::wstring arg = lpCmdLine ? lpCmdLine : L"";
        {
            size_t b = arg.find_first_not_of(L" \t\r\n");
            size_t e = arg.find_last_not_of(L" \t\r\n");
            arg = (b == std::wstring::npos) ? L"" : arg.substr(b, e - b + 1);
        }
        if (arg.size() >= 2 && arg.front() == L'"' && arg.back() == L'"')
            arg = arg.substr(1, arg.size() - 2);
        if (isSupportedExt(extOf(arg)) &&
            GetFileAttributesW(arg.c_str()) != INVALID_FILE_ATTRIBUTES) {
            NcmResult res = decryptFile(arg, FMT_AUTO, nullptr);
            if (!res.success) {
                MessageBoxW(nullptr, utf8ToW(res.error).c_str(), L"解密失败", MB_OK | MB_ICONERROR);
                return 1;
            }
            size_t sp = arg.find_last_of(L"\\/");
            std::wstring dir = (sp == std::wstring::npos) ? L"" : arg.substr(0, sp + 1);
            std::wstring name = res.songName.empty()
                ? baseNameNoExt(arg) : sanitizeName(utf8ToW(res.songName));
            std::wstring fmt = res.format.empty() ? L"mp3" : utf8ToW(res.format);
            std::wstring outPath = dir + name + L"." + fmt;
            FILE* fp = _wfopen(outPath.c_str(), L"wb");
            bool ok = fp != nullptr &&
                      fwrite(res.audio.data(), 1, res.audio.size(), fp) == res.audio.size();
            if (fp) fclose(fp);
            if (ok) MessageBoxW(nullptr, (L"解密成功!\n" + outPath).c_str(), L"完成", MB_OK | MB_ICONINFORMATION);
            else    MessageBoxW(nullptr, L"写入文件失败", L"错误", MB_OK | MB_ICONERROR);
            return ok ? 0 : 1;
        }
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc) };
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // 字体
    hFontUI    = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Microsoft YaHei UI");
    hFontBold  = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Microsoft YaHei UI");
    hFontTitle = CreateFontW(-21, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Microsoft YaHei UI");
    hFontSmall = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Microsoft YaHei UI");
    hFontZoneT = CreateFontW(-19, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Microsoft YaHei UI");
    hFontZoneS = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Microsoft YaHei UI");

    // 直接进入解密主界面
    CreateMainWindow();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        HWND act = GetActiveWindow();
        if (act && IsDialogMessageW(act, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DeleteObject(hFontUI); DeleteObject(hFontBold); DeleteObject(hFontTitle);
    DeleteObject(hFontSmall); DeleteObject(hFontZoneT); DeleteObject(hFontZoneS);
    CoUninitialize();
    return (int)msg.wParam;
}
