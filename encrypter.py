#!/usr/bin/env python3
import argparse
import base64
import os
import sys
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import secrets

MAGIC = b"FILELOCK1"          # Identifica arquivos do nosso formato
HEADER_VERSION = b"\x01"      # Versão do “formato” do cabeçalho
SALT_LEN = 16                 # 128-bit salt
DERIVE_ITERS = 200_000        # PBKDF2 iterações (bom equilíbrio para desktop)
ENC_SUFFIX = ".locked"        # Extensão de saída

SKIP_DIRS = {
    "/Windows", "/Program Files", "/Program Files (x86)",
    "/System", "/System32", "/usr", "/bin", "/sbin", "/etc", "/var", "/proc",
    "/dev", "/sys"
}

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Deriva chave 32 bytes (Fernet) via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=DERIVE_ITERS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def build_header(salt: bytes) -> bytes:
    """Cabeçalho: MAGIC | VERSION | SALT (16 bytes)."""
    return MAGIC + HEADER_VERSION + salt

def parse_args():
    p = argparse.ArgumentParser(
        description="File Locker (ético): criptografa apenas os arquivos que você indicar."
    )
    p.add_argument("paths", nargs="+", help="Arquivo(s) ou diretório(s) para processar.")
    p.add_argument("--pattern", default="*",
                   help="Glob de arquivos (ex.: *.txt). Válido ao varrer diretórios. Padrão: *")
    p.add_argument("--recursive", action="store_true",
                   help="Varrer subdiretórios recursivamente.")
    p.add_argument("--dry-run", action="store_true",
                   help="Apenas mostrar o que seria feito (não altera nada).")
    p.add_argument("--confirm", metavar="FRASE",
                   help="Confirmação explícita. Ex.: --confirm EU-SOU-O-DONO-DOS-ARQUIVOS")
    p.add_argument("--overwrite", action="store_true",
                   help="Sobrescrever saída se já existir .locked.")
    return p.parse_args()

def check_consent(args) -> None:
    expected = "EU-SOU-O-DONO-DOS-ARQUIVOS"
    if args.confirm != expected:
        print(
            "❌ Operação bloqueada: é necessário consentimento explícito.\n"
            f"Use: --confirm {expected}\n"
            "Este utilitário é apenas para seus próprios arquivos."
        )
        sys.exit(2)

def is_system_dir(path: Path) -> bool:
    try:
        abs_p = path.resolve().as_posix()
        return any(abs_p.startswith(sd) for sd in SKIP_DIRS)
    except Exception:
        return False

def iter_target_files(paths, pattern, recursive):
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            print(f"⚠️  Ignorando: não existe -> {p}")
            continue

        if p.is_file():
            yield p
        elif p.is_dir():
            if is_system_dir(p):
                print(f"⛔ Diretório sensível ignorado: {p}")
                continue
            if recursive:
                for f in p.rglob(pattern):
                    if f.is_file():
                        yield f
            else:
                for f in p.glob(pattern):
                    if f.is_file():
                        yield f

def encrypt_file(src: Path, password: str, dry_run: bool, overwrite: bool):
    if src.suffix == ENC_SUFFIX:
        print(f"↪️  Já criptografado (pulando): {src}")
        return

    dst = src.with_suffix(src.suffix + ENC_SUFFIX)
    if dst.exists() and not overwrite:
        print(f"⚠️  Saída já existe (use --overwrite): {dst}")
        return

    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    if dry_run:
        print(f"[DRY-RUN] Criptografaria: {src} -> {dst}")
        return

    data = src.read_bytes()
    token = fernet.encrypt(data)

    header = build_header(salt)
    dst.write_bytes(header + token)
    print(f"✅ Criptografado: {src} -> {dst}")

def main():
    args = parse_args()
    check_consent(args)

    pwd = getpass("Defina uma senha (será usada para TODOS os arquivos desta execução): ")
    if len(pwd) < 8:
        print("❌ Defina uma senha com pelo menos 8 caracteres.")
        sys.exit(2)

    files = list(iter_target_files(args.paths, args.pattern, args.recursive))
    if not files:
        print("Nenhum arquivo encontrado com os parâmetros fornecidos.")
        return

    for f in files:
        encrypt_file(f, pwd, args.dry_run, args.overwrite)

if __name__ == "__main__":
    main()
