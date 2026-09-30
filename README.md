# 🔍 CLIENT-MAPPER (Java Client Decompiler & Mapping Tool)

![Status](https://img.shields.io/badge/Status-Work%20in%20Progress%20%2F%20WIP-yellow?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![CI](https://img.shields.io/badge/CI%2FCD-Active-success?style=for-the-badge)

**CLIENT-MAPPER** is a static analysis and decompilation tool for inspecting Java binaries (JAR/class files), integrating CFR, Fernflower, and Procyon decompilers to map out client class structures.

---

## 📌 Project Status

- **Status:** 🟡 **Work in Progress (WIP)**
- **CI/CD:** Automated GitHub Actions syntax check enabled.
- **Configuration:** Custom decompiler and output paths via `config.json`.

---

## 🚀 Key Features

- **Multi-Decompiler Engine Integration:** Built-in CFR, Fernflower, and Procyon decompiler bridges.
- **Client Scanner Module:** Extracts methods, fields, and dependency maps from target Java classes.
- **Graphical Interface:** UI module for visual decompilation analysis.

---

## 🛠️ Installation & Usage

```bash
pip install -r requirements.txt
python client/main.py
```

---

## ⚙️ Configuration (`config.json`)

```json
{
  "decompiler_default": "cfr",
  "output_dir": "decompiled_output",
  "log_level": "INFO",
  "timeout_seconds": 300
}
```

---

## 📄 License

Licensed under the MIT License.
