import os
from OpenSSL import crypto
from collections import defaultdict
from datetime import datetime
import re

def load_certificates(file_path):
    with open(file_path, "rt") as f:
        cert_str = f.read()
    # Split the file into individual certificates
    certs_str = cert_str.split("-----END CERTIFICATE-----")
    certs = [crypto.load_certificate(crypto.FILETYPE_PEM, cert_str + "-----END CERTIFICATE-----")
             for cert_str in certs_str if cert_str.strip()]
    return certs

def get_subject(cert):
    return cert.get_subject().CN

def get_issuer(cert):
    return cert.get_issuer().CN

def get_serial_number(cert):
    return cert.get_serial_number()

def check_expiry(cert):
    return datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ') < datetime.utcnow()

def construct_chains(cert_directory):
    # Load all certificates
    certs = {}
    for file in os.listdir(cert_directory):
        if file.endswith(".cer"):
            file_path = os.path.join(cert_directory, file)
            certificates = load_certificates(file_path)
            for cert in certificates:
                subject = get_subject(cert)
                serial_number = get_serial_number(cert)
                certs[(subject, serial_number)] = cert

    return certs

def create_chain_for(cert, certs):
    chain = [(get_subject(cert), get_serial_number(cert))]
    while get_subject(cert) != get_issuer(cert):
        # Get the issuer's certificate based on the issuer name only
        issuer_cert = next(c for c in certs.values() if get_subject(c) == get_issuer(cert))
        cert = issuer_cert
        if get_subject(cert) == get_issuer(cert):  # This is a Root CA
            break
        chain.append((get_subject(cert), get_serial_number(cert)))
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
    for (subject, serial_number), cert in certs.items():
        chain = create_chain_for(cert, certs)
        # Exclude the root certificate (last one in the chain)
        if get_subject(cert) == get_issuer(cert):
            chain = chain[:-1]
        expired = any(check_expiry(certs[cert]) for cert in chain)
        filename_parts = ["chain"]
        if expired:
            filename_parts.append("expired")
        # Remove conversion to lowercase to preserve the case of the certificate subjects in the file names
        filename_parts.extend(apply_replacements(cert[0].replace(' ', ''), replacements) for cert in chain)
        file_name = "-".join(filename_parts) + ".pem"
        file_path = os.path.join(output_directory, file_name)
        # Only write files if the chain is not empty
        if chain:
            with open(file_path, "wt") as f:
                for cert in chain:
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
