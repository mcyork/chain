
import os
from OpenSSL import crypto
from collections import defaultdict
from datetime import datetime
import re

def load_certificate(file_path):
    with open(file_path, "rt") as f:
        cert_str = f.read()
    return crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)

def get_subject(cert):
    return cert.get_subject().CN

def get_issuer(cert):
    return cert.get_issuer().CN

def check_expiry(cert):
    return datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ') < datetime.utcnow()

def construct_chains(cert_directory):
    # Load all certificates
    certs = {}
    for file in os.listdir(cert_directory):
        if file.endswith(".cer"):
            file_path = os.path.join(cert_directory, file)
            cert = load_certificate(file_path)
            subject = get_subject(cert)
            certs[subject] = cert

    return certs

def create_chain_for(cert, certs):
    chain = [get_subject(cert)]
    while get_subject(cert) != get_issuer(cert):
        cert = certs[get_issuer(cert)]
        if get_subject(cert) == get_issuer(cert):  # This is a Root CA
            break
        chain.append(get_subject(cert))
    return chain

def load_replacements(template_path):
    replacements = {}
    with open(template_path, 'rt') as f:
        for line in f:
            if '=' in line:
                original, replacement = line.strip().split('=', maxsplit=1)
                replacements[original] = replacement
    return replacements

def apply_replacements(text, replacements):
    for original, replacement in replacements.items():
        pattern = re.compile(re.escape(original), re.IGNORECASE)
        text = pattern.sub(replacement, text)
    text = text.replace('--', '-')
    return text

def write_chains(certs, output_directory, replacements):
    for subject, cert in certs.items():
        chain = create_chain_for(cert, certs)
        expired = any(check_expiry(certs[cert]) for cert in chain)
        filename_parts = ["chain"]
        if expired:
            filename_parts.append("expired")
        filename_parts.extend(apply_replacements(cert.replace(' ', ''), replacements) for cert in chain)
        file_name = "-".join(filename_parts) + ".pem"
        file_path = os.path.join(output_directory, file_name)
        with open(file_path, "wt") as f:
            for cert in chain[:-1]:  # Exclude the last certificate in the chain (root)
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certs[cert]).decode())

def main():
    cert_directory = "."  # Directory where .cer files are located
    output_directory = "."  # Directory where chain .pem files should be written
    template_path = "template.txt"  # Path to the template file for replacements

    certs = construct_chains(cert_directory)
    replacements = load_replacements(template_path)
    write_chains(certs, output_directory, replacements)

if __name__ == "__main__":
    main()
