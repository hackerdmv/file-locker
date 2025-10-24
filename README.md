# 🛡️ File Locker – Criptografia de Arquivos em Python

![Execução do File Locker](images/execucao.png)

## 📖 Descrição
Projeto educacional que demonstra **criptografia simétrica segura** e **organização de projeto**, **sem comportamento malicioso**.  
✅ Não se propaga  
✅ Não deleta arquivos  
✅ Não exige resgate  
👉 Serve apenas para proteger arquivos **do próprio usuário**.

---

## ⚙️ Tecnologias
- Python 3.10+
- Biblioteca [`cryptography`](https://pypi.org/project/cryptography/)
- Fernet (AES-256)
- PBKDF2-HMAC-SHA256 com sal por arquivo

---

## 📦 Instalação
```bash
# 1. Criar ambiente virtual
python -m venv .venv

# 2. Ativar
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Instalar dependências
pip install -r requirements.txt
