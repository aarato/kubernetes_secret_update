import unittest
import os
import datetime
from main import KubeSecret
from base64 import b64decode, b64encode
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class TestSecret(unittest.TestCase):
    def setUp(self):
        # test1 cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open("test1.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            ))

        subject = issuer = x509.Name([
            # x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Illinois"),
            # x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chicago"),
            # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"test1.example.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        # Write our certificate out to disk.
        with open("test1.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # test2 cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open("test2.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            ))

        subject = issuer = x509.Name([
            # x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Illinois"),
            # x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chicago"),
            # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"test2.example.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 20 days
            datetime.datetime.utcnow() + datetime.timedelta(days=20)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        # Write our certificate out to disk.
        with open("test2.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))


    def tearDown(self):
        os.remove("test1.key")
        os.remove("test1.crt")
        os.remove("test2.key")
        os.remove("test2.crt")

    # Get certificate files
    def test_00(self):
        test         = KubeSecret(name="test", tls_cert_file="test1.crt", tls_key_file="test1.key", log_enable=False)
        secret       = test.get_certificate_files()    
        cert_binary  = b64decode( secret["data"]["tls.crt"] )
        cert_object  = x509.load_pem_x509_certificate(cert_binary)
        name = cert_object.subject.rdns[0].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # print(cert_object)
        self.assertEqual(name,"test1.example.com")
    #_Create certificate
    def test_01(self):
        test         = KubeSecret(name="test", tls_cert_file="test1.crt", tls_key_file="test1.key", log_enable=True)
        secret       = test.set_secret()    
        cert_binary  = b64decode( secret["data"]["tls.crt"] )
        cert_object  = x509.load_pem_x509_certificate(cert_binary)
        name = cert_object.subject.rdns[0].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # print(cert_object)
        self.assertEqual(name,"test1.example.com")

    # Update Certificate
    def test_03(self):
        test         = KubeSecret(name="test", tls_cert_file="test2.crt", tls_key_file="test2.key", log_enable=True)
        secret       = test.set_secret()    
        cert_binary  = b64decode( secret["data"]["tls.crt"] )
        cert_object  = x509.load_pem_x509_certificate(cert_binary)
        name = cert_object.subject.rdns[0].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # print(cert_object)
        self.assertEqual(name,"test2.example.com")

    # Update Certificate again with same cert, with skip update
    def test_04(self):
        test         = KubeSecret(name="test", tls_cert_file="test2.crt", tls_key_file="test2.key", log_enable=True)
        secret       = test.set_secret()    
        cert_binary  = b64decode( secret["data"]["tls.crt"] )
        cert_object  = x509.load_pem_x509_certificate(cert_binary)
        name = cert_object.subject.rdns[0].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # print(cert_object)
        self.assertEqual(name,"test2.example.com")

    # Get certificate
    def test_05(self):
        test         = KubeSecret(name="test", log_enable=False)
        secret       = test.get_secret()    
        cert_binary  = b64decode( secret["data"]["tls.crt"] )
        cert_object  = x509.load_pem_x509_certificate(cert_binary)
        name = cert_object.subject.rdns[0].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # print(cert_object)
        self.assertEqual(name,"test2.example.com")

    # Delete certificate
    def test_06(self):
        test         = KubeSecret(name="test", log_enable=False)
        success       = test.delete_secret()    
        # print(cert_object)
        self.assertEqual(success,True)


if __name__ == "__main__":
    unittest.main()