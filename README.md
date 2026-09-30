# 🔍 CLIENT-MAPPER (Java Client Decompiler & Mapping Tool)

![Status](https://img.shields.io/badge/Durum-Geli%C5%9Ftirilmeye%20A%C3%A7%C4%B1k%20%2F%20WIP-yellow?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![CI](https://img.shields.io/badge/CI%2FCD-Active-success?style=for-the-badge)

**CLIENT-MAPPER**, Java istemci binary dosyalarını (JAR/class) analiz etme, decompile etme (CFR, Fernflower, Procyon entegrasyonu) ve istemci yapısını haritalandırma aracıdır.

---

## 📌 Proje Durumu (Project Status)

- **Durum:** 🟡 **Geliştirilmeye Açık / WIP (Work in Progress)**
- **Test & CI/CD:** GitHub Actions otomasyonu eklendi.
- **Konfigürasyon:** `config.json` ile ayrıştırıcı ve çıktı dizini ayarlanabilir.

---

## 🚀 Özellikler

- **Çoklu Decompiler Desteği:** CFR, Fernflower ve Procyon motorları entegredir.
- **İstemci Tarayıcı Modülü:** İstemci sınıflarındaki metodları ve veri haritasını çıkarır.
- **Masaüstü Arayüzü:** UI modülü ile görsel analiz olanağı sunar.

---

## 🛠️ Kurulum ve Kullanım

```bash
pip install -r requirements.txt
python client/main.py
```

---

## ⚙️ Yapılandırma (`config.json`)

```json
{
  "decompiler_default": "cfr",
  "output_dir": "decompiled_output",
  "log_level": "INFO",
  "timeout_seconds": 300
}
```

---

## 📄 Lisans

MIT License
