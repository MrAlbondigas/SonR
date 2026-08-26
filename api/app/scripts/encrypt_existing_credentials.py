"""Migracion unica: reescribe las credenciales ya guardadas para que pasen por el
cifrado (EncryptedString). Los valores que ya estaban en texto plano se leen tal
cual (ver crypto.py) y, al reasignarlos, SQLAlchemy los marca como modificados y
los vuelve a guardar ya cifrados. Idempotente: si ya estan cifrados, decifrar y
re-cifrar produce un resultado distinto en bytes pero equivalente en texto plano,
sin efecto observable.
"""

from app.database import SessionLocal
from app import models


def main():
    db = SessionLocal()
    try:
        creds = db.query(models.SSHCredential).all()
        findings = db.query(models.CredentialFinding).all()

        for cred in creds:
            cred.password = cred.password
        for finding in findings:
            finding.password = finding.password

        db.commit()
        print(f"ssh_credentials migradas: {len(creds)}")
        print(f"credential_findings migradas: {len(findings)}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
