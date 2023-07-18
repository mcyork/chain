import os
import argparse
import logging
from OpenSSL import crypto
from collections import defaultdict
from datetime import datetime
import re

version = "2.0"

def load_certificates(file_path):
    logging.debug(f"Loading certificates from {file_path}")
    with open(file_path, "rt") as f:
        cert_str = f.read()
    certs_str = cert_str.split("-----END CERTIFICATE-----")
    certs = [crypto.load_certificate(crypto.FILETYPE_PEM, cert_str + "-----END CERTIFICATE-----")
             for cert_str in certs_str if cert_str.strip()]
    logging.debug(f"Loaded {len(certs)} certificates from {file_path}")
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
    certs = {}
    for file in os.listdir(cert_directory):
        if file.endswith(".cer"):
            file_path = os.path.join(cert_directory, file)
            certificates = load_certificates(file_path)
            for cert in certificates:
                subject = get_subject(cert)
                serial_number = get_serial_number(cert)
                certs[(subject, serial_number)] = cert
    logging.debug(f"Constructed chains for {len(certs)} certificates")
    return certs

def create_chain_for(cert, certs):
    chain = [(get_subject(cert), get_serial_number(cert))]
    while get_subject(cert) != get_issuer(cert):
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
    logging.debug(f"Loaded {len(replacements)} replacements from {template_path}")
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
        if get_subject(cert) == get_issuer(cert):
            chain = chain[:-1]
        expired = any(check_expiry(certs[cert]) for cert in chain)
        filename_parts = ["chain"]
        if expired:
            filename_parts.append("expired")
        filename_parts.extend(apply_replacements(cert[0].replace(' ', ''), replacements) for cert in chain)
        file_name = "-".join(filename_parts) + ".pem"
        file_path = os.path.join(output_directory, file_name)
        if chain:
            with open(file_path, "wt") as f:
                for cert in chain:
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certs[cert]).decode())
            logging.debug(f"Wrote chain to {file_path}")
        cert_filename_parts = ["cert", apply_replacements(get_subject(cert).replace(' ', ''), replacements), str(get_serial_number(cert))]
        cert_file_name = "-".join(cert_filename_parts) + ".pem"
        cert_file_path = os.path.join(output_directory, cert_file_name)
        with open(cert_file_path, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())
        logging.debug(f"Wrote certificate to {cert_file_path}")

def main():
    parser = argparse.ArgumentParser(description='Construct certificate chains.')
    parser.add_argument('-s', '--source', default='.', help='Directory where .cer files are located')
    parser.add_argument('-d', '--destination', default='.', help='Directory where chain .pem files should be written')
    parser.add_argument('-t', '--template', default='template.txt', help='Path to the template file for replacements')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (specify multiple times for more detail)')
    parser.add_argument('-V', '--version', action='store_true', help='Show version number and exit')
    args = parser.parse_args()

    if args.version:
        print(version)
        return

    if args.verbose == 0:
        log_level = logging.WARNING
    elif args.verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')

    cert_directory = args.source
    output_directory = args.destination
    template_path = args.template

    certs = construct_chains(cert_directory)
    replacements = load_replacements(template_path)
    write_chains(certs, output_directory, replacements)

if __name__ == "__main__":
    main()
