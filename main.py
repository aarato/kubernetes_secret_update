from cryptography import x509
from base64 import b64decode,b64encode
from os import getenv
from dotenv import load_dotenv
import requests
import sys
import logging  
import json

# Load environment variables from .env file, if present
load_dotenv()

# Setup logging
log_format = logging.Formatter('[%(asctime)s] [%(levelname)s] - %(message)s')
log = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout) 
handler.setFormatter(log_format)  
log.addHandler(handler)

class KubeSecret:

  # Setup
  def __init__(
      self,
      name=None,
      tls_cert_file=None,
      tls_key_file=None,
      namespace="default",
      apiserver="https://kubernetes.default.svc",
      ca_file="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
      token_file="/var/run/secrets/kubernetes.io/serviceaccount/token",
      log_enable=True):
    
    self.name          = name if name else getenv("SECRETNAME", "tls-default") 
    self.tls_cert_file = tls_cert_file if tls_cert_file else getenv("TLS_CERT_FILE", self.name+".crt") 
    self.tls_key_file  = tls_key_file if tls_key_file else getenv("TLS_KEY_FILE", self.name+".key") 
    self.namespace     = getenv("NAMESPACE", namespace) 
    self.apiserver     = getenv("APISERVER", apiserver) 
    self.ca_file       = getenv("CAFILE", ca_file) 
    self.ca            = self.read_ca()
    self.token_file    = getenv("TOKENFILE", token_file)
    self.token         = self.read_token()
    self.headers       = {"Authorization": f"Bearer {self.token}"}
    self.secret        = {
                          "apiVersion":"v1",
                          "kind" :"Secret",
                          "metadata" :{
                            "namespace" : self.namespace,
                            "name": self.name 
                            },
                          "data": {
                              "tls.crt": None,
                              "tls.key": None
                            },
                          "type": "kubernetes.io/tls"
                          }
    if log_enable : 
      log.setLevel(logging.INFO)
    else:
      log.setLevel(logging.ERROR)

  # Read Kubernetes Certificate Authority from file, exit if fails
  def read_ca(self):
    try:
      with open(self.ca_file, mode='r') as file: 
          ca = file.read()
          return ca
    except BaseException as error:
      log.error(f"CA certificate is not avaialable at {self.ca_file}")
      sys.exit("CA certificate error")
    
  # Read the Kubernetes Authorization token, exit if fails
  def read_token(self):
    try:
      with open( self.token_file, mode='r') as file: 
          token = file.read()
          return token
    except BaseException as error:
      log.error(f"TOKEN_FILE env variable is not set and the token file is not avaialable at {self.token_file}")
      sys.exit("Token error")

  # Get new certificate and private key from files and return Secret object, exit if fails
  def get_certificate_files(self):
    # Read certificate from file
    try:
      with open( self.tls_cert_file , mode='rb') as file: 
        tls_cert_new_bin                  = file.read()
        self.secret["data"]["tls.crt"]    = (b64encode( tls_cert_new_bin)).decode()
    except BaseException as error:
      log.error(f"Certificate is not avaialable at {self.tls_cert_file}")
      log.error(f"ERROR {error}")
      sys.exit("Certificate file error")
    # Read certificate key from file
    try:
      with open( self.tls_key_file , mode='rb') as file: 
        tls_key_new_bin                  = file.read()
        self.secret["data"]["tls.key"]    = (b64encode (tls_key_new_bin)).decode()
    except BaseException as error:
      log.error(f"Certificate private key is not avaialable at {self.tls_key_file}")
      sys.exit("Certificate key error")      

    return self.secret

  # Read Kubernetes TLS Secret with cert and key - return Secret object and None if not found
  def get_secret(self):
    try:
      url     = f"{self.apiserver}/api/v1/namespaces/{self.namespace}/secrets"
      r = requests.get( url , headers=self.headers, verify=self.ca_file)
      json = r.json()   
      secrets          = json["items"]
      secret           = next( (item for item in secrets if item["metadata"]["name"] == self.name ), None)
      return secret
    except BaseException as error:
      log.error(f"Could not properly connect to Kubernetes via API {url}")
      sys.exit("Kubernetes API Error")

  # Create Secret with TLS Certificate or update certificate in Kubernetes Secret
  def set_secret(self):
    new_secret = self.get_certificate_files()
    cert_new = x509.load_pem_x509_certificate( b64decode( new_secret["data"]["tls.crt"] ) )
    old_secret = self.get_secret()

    if not old_secret:
      # Cretate secret's certificate with certificate from file
      url     = f"{self.apiserver}/api/v1/namespaces/{self.namespace}/secrets"
      try:
        r = requests.post( url , json=new_secret, headers=self.headers, verify=self.ca_file)
      except Exception as err:
        log.error(f"UR: {url}")
        log.error(f"JSON: {new_secret}")
        log.error(f"Headers: {self.headers}")
        log.error(f"EXCEPTION: {err}")
        sys.exit("Kubernetes POST Error")
        
      
      if r.status_code == 201:
        log.info(f"Secret {self.name} has been created! Certificate: {cert_new.subject} expiration: {cert_new.not_valid_after} !")
        return new_secret
      else:
        log.error(f"Secret {self.name} with certificate {cert_new.subject} failed to created with status code {r.status_code}")
        log.error(r.text)     
        return None    

    cert_old = x509.load_pem_x509_certificate( b64decode( old_secret["data"]["tls.crt"] ) )
    if  cert_new.not_valid_after > cert_old.not_valid_after:
      # Update secret's certificate with certificate from file
      old_cert = x509.load_pem_x509_certificate( b64decode( old_secret["data"]["tls.crt"] ) )
      url     = f"{self.apiserver}/api/v1/namespaces/{self.namespace}/secrets/{self.name}"
      r = requests.put( url , json=new_secret, headers=self.headers, verify=self.ca_file)
      if r.status_code == 200:
        log.info(f"Secret {self.name} has been updated! Certificate: {cert_new.subject} expiration: {cert_new.not_valid_after} !")
        return new_secret
      else:
        log.error(f"Secret {self.name} with certificate {cert_new.subject} failed to update with status code {r.status_code}")
        log.error(r.text)
        return None
    else:
      log.info(f"Secret '{self.name}' is NOT updated, as certificate {cert_new.subject} expiration is NOT later than: {cert_old.not_valid_after} !")
      return new_secret

  # Delete Secret
  def delete_secret(self):
    old_secret = self.get_secret()
    if old_secret:
      old_cert = x509.load_pem_x509_certificate( b64decode( old_secret["data"]["tls.crt"] ) )

      url     = f"{self.apiserver}/api/v1/namespaces/{self.namespace}/secrets/{self.name}"
      # Delete secret
      r = requests.delete( url , json=old_secret, headers=self.headers, verify=self.ca_file)
      if r.status_code == 200:
        log.info(f"Secret {self.name} has been delete!")
        return True
      else:
        log.error(f"Secret {self.name} with certificate {old_cert.subject} failed to update with status code {r.status_code}")
        log.error(r.text)
        return None     

    else:
      log.error(f"Secret {self.name} with certificate does not exists!")
      return None

if __name__ == "__main__":
    secret = KubeSecret()
    secret.set_secret()