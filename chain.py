import os
from OpenSSL import crypto
from collections import defaultdict
from datetime import datetime

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

def construct_chain(cert_directory):
    # Load all certificates
    certs = {}
    for file in os.listdir(cert_directory):
        if file.endswith(".cer"):
            file_path = os.path.join(cert_directory, file)
            cert = load_certificate(file_path)
            subject = get_subject(cert)
            certs[subject] = cert
    
    # Construct chains
    chains = defaultdict(list)
    for subject, cert in certs.items():
        issuer = get_issuer(cert)
        chains[issuer].append(subject)
    
    return chains, certs

def write_chains(chains, certs, output_directory):
    for issuer, subjects in chains.items():
        expired = any(check_expiry(certs[subject]) for subject in subjects)
        filename_parts = ["chain"]
        if expired:
            filename_parts.append("expired")
        filename_parts.extend(subject.replace(' ', '') for subject in subjects)
        file_name = "-".join(filename_parts) + ".pem"
        file_path = os.path.join(output_directory, file_name)
        with open(file_path, "wt") as f:
            for subject in subjects:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certs[subject]).decode())

def main():
    cert_directory = "."  # Directory where .cer files are located
    output_directory = "."  # Directory where chain .pem files should be written

    chains, certs = construct_chain(cert_directory)
    write_chains(chains, certs, output_directory)

if __name__ == "__main__":
    main()
