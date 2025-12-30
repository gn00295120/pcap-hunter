# PCAP Hunter - Claude Code 專案指引

## 專案概述

PCAP Hunter 是一個 AI 增強的威脅狩獵工作台，結合 Zeek、Tshark 與 LLM 進行 PCAP 分析。

## 技術棧

- **語言**: Python 3.11+
- **框架**: Streamlit (UI)
- **網路分析**: PyShark, Zeek, Tshark
- **AI**: OpenAI-compatible API (LM Studio / GPT-4)
- **格式化**: Ruff
- **測試**: pytest

## 專案結構

```
app/
├── config.py          # 配置管理
├── main.py            # Streamlit 入口
├── llm/               # LLM 客戶端
├── pipeline/          # 分析管線
│   ├── beacon.py      # C2 偵測
│   ├── carve.py       # 檔案提取
│   ├── geoip.py       # GeoIP 查詢
│   ├── osint.py       # OSINT 整合
│   ├── pcap_count.py  # 封包計數
│   ├── pyshark_pass.py # 深度封包解析
│   └── zeek.py        # Zeek 整合
├── security/          # 安全功能
├── ui/                # UI 元件
└── utils/             # 工具函式
tests/                 # 測試
```

## 開發指令

```bash
make install   # 安裝依賴
make run       # 啟動應用
make test      # 執行測試
make lint      # 程式碼檢查
make format    # 格式化程式碼
make clean     # 清理暫存
```

## 程式碼規範

- 使用 Ruff 進行格式化（line-length: 120）
- 目標版本 Python 3.11
- 遵循 PEP 8
- 使用 Google style docstrings

## 安全注意事項

- PCAP 檔案可能包含敏感資料，確保安全處理
- 提取的檔案儲存在隔離目錄
- API 金鑰透過環境變數或 .env 管理
