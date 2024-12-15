from OpenSSL import SSL
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import ssl
import socket

from OpenSSL import SSL
from urllib.parse import urlparse
import socket

def get_certificate_chain(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path
    port = parsed_url.port or 443

    context = SSL.Context(SSL.TLSv1_2_METHOD)
    connection = SSL.Connection(context, socket.create_connection((hostname, port)))
    connection.set_tlsext_host_name(hostname.encode())
    connection.set_connect_state()
    connection.do_handshake()

    cert_chain = connection.get_peer_cert_chain()
    details = []

    for idx, cert in enumerate(cert_chain, 1):
        subject = cert.get_subject()
        issuer = cert.get_issuer()

        details.append({
            "Subject (Nazwa instytucji)": subject.commonName,
            "Issuer (Wystawca)": issuer.commonName,
        })
    
    connection.close()
    return details

def get_ssl_certificate(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path
    port = parsed_url.port or 443  

    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
    
    return cert