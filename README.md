#  Analisis Prioritas Risiko Vulnerability pada CISA KEV

Analisis data vulnerability yang telah diketahui dieksploitasi di dunia nyata menggunakan **CISA KEV, NVD, dan EPSS**.

Project ini bertujuan untuk melihat karakteristik vulnerability dari sisi vendor, tingkat keparahan, probabilitas eksploitasi, hingga pola karakteristik serangan. Pada tahap Machine Learning, digunakan **K-Means Clustering** untuk menemukan profil vulnerability yang memiliki karakteristik serupa.

---

## Project Overview

CISA Known Exploited Vulnerabilities (KEV) berisi vulnerability yang telah diketahui dieksploitasi. Dengan jumlah vulnerability yang besar, penanganannya membutuhkan prioritas yang tidak hanya bergantung pada tingkat keparahan.

Project ini menggabungkan:

- **CISA KEV** → konteks vulnerability yang telah dieksploitasi
- **NVD** → karakteristik teknis dan CVSS
- **EPSS** → probabilitas eksploitasi

Data dari ketiga sumber digabung menggunakan `cveID`.

**Total data: 1,733 CVE**

---

## Business Questions

### Q1 — Vendor & Product
Vendor dan produk teknologi apa saja yang paling mendominasi katalog vulnerability CISA KEV?

### Q2 — CVSS & EPSS
Bagaimana karakteristik sebaran tingkat keparahan teknis dibandingkan dengan probabilitas eksploitasi?

### Q3 — Attack Vector & User Interaction
Seberapa besar ketergantungan eksploitasi terhadap interaksi pengguna pada berbagai jalur serangan?

### Q4 — Vulnerability Profiling
Apakah vulnerability di dalam CISA KEV memiliki profil karakteristik yang berbeda berdasarkan severity, exploitability, impact, dan EPSS?

---

## Methodology

```text
CISA KEV ─────┐
              ├──→ Airflow → MySQL → Python
NVD ──────────┤
              │
EPSS ─────────┘
                    ↓
              Data Wrangling
                    ↓
                   EDA
                    ↓
          Feature Selection
                    ↓
          Feature Engineering
                    ↓
              StandardScaler
                    ↓
                 K-Means
                    ↓
             Cluster Profiling
