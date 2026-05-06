# MCP-Based Web VAPT Scanner

An AI-powered Web Vulnerability Assessment and Penetration Testing (VAPT) Scanner built using the **Model Context Protocol (MCP)** framework. This project automates reconnaissance, vulnerability scanning, and security assessment workflows for web applications using modular MCP-based integrations.

---

## 🚀 Features

- 🔍 Automated Web Reconnaissance
- 🌐 Subdomain Enumeration
- 📡 Port & Service Scanning
- 🛡️ Vulnerability Detection
- ⚡ MCP-based Modular Architecture
- 🤖 AI-Assisted Security Workflow
- 📑 Structured Scan Reports
- 🔧 Easy Tool Integration
- 🧩 Extensible Scanner Modules

---

## 🧠 What is MCP?

**Model Context Protocol (MCP)** is a standardized protocol that allows AI systems and external tools to communicate seamlessly. It enables AI-driven automation and orchestration of security tools within a unified workflow.

This project leverages MCP to integrate multiple VAPT functionalities into a single intelligent scanning pipeline.

---

# 🏗️ Project Architecture

```text
                    ┌─────────────────────┐
                    │   User Input URL    │
                    └─────────┬───────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │ MCP Orchestrator Engine │
                 └─────────┬───────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
 ┌────────────┐    ┌──────────────┐   ┌──────────────┐
 │ Recon Tool │    │ Scanner Tool │   │ Report Module│
 └────────────┘    └──────────────┘   └──────────────┘
        │                  │                  │
        ▼                  ▼                  ▼
 Subdomains        Vulnerability Scan     Findings Report
 Port Scan         Security Analysis      Risk Summary
 Crawling          Exploit Detection      Recommendations
```

---

# ⚙️ Tech Stack

- Python
- MCP (Model Context Protocol)
- Web Security Tools
- APIs & Automation Scripts
- AI-assisted Security Workflow
- CLI-based Scanner Architecture

---

# 📂 Project Structure

```bash
MCP-based-Web-VAPT-scanner/
│
├── scanner/
│   ├── recon/
│   ├── vuln_scan/
│   ├── reporting/
│   └── utils/
│
├── mcp_server/
│
├── reports/
│
├── requirements.txt
├── README.md
└── main.py
```

---

# 🔧 Installation

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/Thuriaanandh/Cyber-security.git
cd Cyber-security/MCP-based\ Web\ VAPT\ scanner
```

---

## 2️⃣ Create Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / Mac

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

Run the scanner:

```bash
python main.py
```

Example:

```bash
python main.py --target https://example.com
```

---

# 🔎 Scanner Workflow

1. Target Input
2. Reconnaissance Phase
3. Endpoint Discovery
4. Vulnerability Scanning
5. Risk Analysis
6. Report Generation

---

# 🛡️ Vulnerability Checks

The scanner can be extended to detect:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Open Redirect
- Sensitive File Exposure
- Security Misconfigurations
- Missing Headers
- Weak SSL/TLS Configurations
- Directory Traversal
- Authentication Issues

---

# 📊 Sample Output

```bash
[+] Target Loaded
[+] Running Reconnaissance...
[+] Subdomains Found: 12
[+] Open Ports Detected
[+] Starting Vulnerability Scan...
[!] XSS Vulnerability Detected
[!] Missing CSP Header
[+] Report Generated Successfully
```

---

# 📑 Future Improvements

- AI-based vulnerability prioritization
- Automated exploit validation
- Dashboard UI
- Docker deployment
- CI/CD security integration
- Cloud deployment support
- Multi-target parallel scanning
- Integration with OWASP ZAP / Nmap / Nuclei

---

# 🎯 Learning Objectives

This project helps understand:

- Web Application Security
- Penetration Testing Workflow
- MCP Architecture
- Security Automation
- AI-assisted Cybersecurity
- Vulnerability Assessment Methodologies

---

# ⚠️ Disclaimer

This tool is developed strictly for:

- Educational purposes
- Authorized security testing
- Research environments

Do **NOT** use this project against systems without proper authorization. Unauthorized scanning or penetration testing may violate laws and regulations.

---

# 🤝 Contributing

Contributions are welcome.

## Steps:

1. Fork the repository

2. Create a new branch

```bash
git checkout -b feature-name
```

3. Commit changes

```bash
git commit -m "Added new feature"
```

4. Push to branch

```bash
git push origin feature-name
```

5. Open a Pull Request

---

# 📜 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

## Thuriaanandh Deepak

Cybersecurity Student | AI + Security Enthusiast | VAPT Researcher

- GitHub: https://github.com/Thuriaanandh

---

# ⭐ Support

If you found this project useful:

- Star the repository
- Fork the project
- Share with others
- Contribute improvements

---

# 📚 References

- OWASP Web Security Testing Guide
- Nmap Documentation
- OWASP ZAP Documentation
- Nuclei Templates
- MCP Documentation

---
