# Introduction
This repo includes a python script that updates/creates Kubernetes TLS secret objects with provided certificate/key files. The Kubernetes object is only updated if the provided certificate expiration date is later than the one stored in the existing TLS Secret object. Using the provided Dockerfile the script can be containerized and it is intended to be run as a standalone Kubernetes cronjob that monitors a mounted directory where the certificates are located.

## Sample Declarative Configuration
See the provided example_config.yaml file, that includes the CronJob objects along with the requires ServceAccount, ClusterRole and ClusterRoleBinding.
```
kubectl apply -f example_config.yaml
```
You can verify the stored certificate using kubectl. Example:
```
kubectl get secrets mysecret -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 --text
```

## Environment Variables
| Name            | Description               | Mandatory | Default Value
| -----------     | -----------               |---------- | ---------- |
| SECRETNAME      | secret object name        | yes       | N/A        |
| TLS_CERT_FILE   | Certificate file name     | yes       | N/A        |
| TLS_KEY_FILE    | Private Key file name     | yes       | N/A        |
| APISERVER       | Kubernetes API server URL | no        | https://kubernetes.default.svc |
| NAMESPACE       | Kubernetes namespace      | no        | /var/run/secrets/kubernetes.io/serviceaccount/namespace  |
| TOKENFILE       | Kubernetes Auth Token     | no        | /var/run/secrets/kubernetes.io/serviceaccount/token  |
| CAFILE          | Kubernetes CA certificate | no        | /var/run/secrets/kubernetes.io/serviceaccount/ca_file    |

