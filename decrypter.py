#!/usr/bin/env python3
import argparse
import base64
import sys
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

MAGIC = b"FILELOCK1"
HEADER_VERSION = b"\x01"
SALT_LEN = 16
DERIVE_ITERS = 200_000
ENC_SUFFIX = ".locked"

def parse_args():
    p = argparse.ArgumentParser(
        description="File Locker (ético): descriptografar arquivos .locked."
    )
    p.add_argument("paths", nargs="+", help="Arquivo(s) .locked para descriptografar.")
    p.add_argument("--dry-run", action="store_true", help="Somente mostra o que faria.")
    p.add_argument("--overwrite", action="store_true", help="Sobrescrever arquivo de saída.")
    return p.parse_args()

def read_header(blob: bytes):
    if len(blob) < len(MAGIC) + 1 + SALT_LEN:
        raise ValueError("Arquivo inválido ou corrompido (muito curto).")
    magic = blob[:len(MAGIC)]
    version = blob[len(MAGIC):len(MAGIC)+1]
    salt = blob[len(MAGIC)+1:len(MAGIC)+1+SALT_LEN]
    token = blob[len(MAGIC)+1+SALT_LEN:]
    if magic != MAGIC:
        raise ValueError("Cabeçalho inválido (MAGIC mismatch).")
    if version != HEADER_VERSION:
        raise ValueError("Versão de cabeçalho não suportada.")
    return salt, token

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=DERIVE_ITERS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def decrypt_file(src: Path, password: str, dry_run: bool, overwrite: bool):
    if src.suffix != ENC_SUFFIX and not src.name.endswith(ENC_SUFFIX):
        print(f"⚠️  Não parece um arquivo criptografado (.locked): {src}")
        return

    # Saída: remove apenas o sufixo final ".locked"
    if src.name.endswith(ENC_SUFFIX):
        out_name = src.name[:-len(ENC_SUFFIX)]
    else:
        out_name = src.stem  # fallback

    dst = src.with_name(out_name)
    if dst.exists() and not overwrite:
        print(f"⚠️  Saída já existe (use --overwrite): {dst}")
        return

    if dry_run:
        print(f"[DRY-RUN] Descriptografaria: {src} -> {dst}")
        return

    blob = src.read_bytes()
    salt, token = read_header(blob)
    key = derive_key_from_password(password, salt)
    f = Fernet(key)

    try:
        data = f.decrypt(token)
    except Exception as e:
        print(f"❌ Falha ao descriptografar {src}: senha incorreta ou arquivo corrompido. ({e})")
        return

    dst.write_bytes(data)
    print(f"✅ Descriptografado: {src} -> {dst}")

def main():
    args = parse_args()
    pwd = getpass("Informe a senha usada na criptografia: ")

    for raw in args.paths:
        p = Path(raw)
        if not p.exists() or not p.is_file():
            print(f"⚠️  Não encontrado/arquivo inválido: {p}")
            continue
        decrypt_file(p, pwd, args.dry_run, args.overwrite)

if __name__ == "__main__":
    main()
