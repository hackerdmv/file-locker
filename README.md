# File Locker (Ético) – Criptografia de Arquivos em Python

> Projeto educacional que demonstra **criptografia simétrica segura** e **organização de projeto**,
> sem comportamento malicioso. **Não se propaga, não deleta, não exige resgate** — serve apenas
> para proteger arquivos **do próprio usuário**.

## ⚙️ Tecnologias
- Python 3.10+
- [cryptography](https://pypi.org/project/cryptography/) (Fernet/AES-256)
- PBKDF2-HMAC-SHA256 com salt por arquivo

## 📦 Instalação
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
