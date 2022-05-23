# Introduction
This repo includes a python script that updates/creates Kubernetes TLS secret objects with provided certificate/key files. The Kubernetes object is only updated if the provided certificate expiration date is later than the one stored in the existing TLS Secret object. Using the provided Dockerfile the script can be containerized and it is intended to be run as a standalone Kubernetes cronjob that monitors a mounted directory where the certificates are located.

## Prerequisites
- Service Account: This is required for authentication and authorization purposes so that the script could change the secret
- Environment Variables: The variables used to customize the script runtime.
### Service Account
A sample declarative configuration file - *sample_account.yaml* - is also included with this repo.
```
#Create ServiceAccount, ClusterRole and ClusterRoleBinding
kubectl create serviceaccount test
kubectl create clusterrole test --verb=get,list,watch,create,update,patch,delete --resource=secrets
kubectl create clusterrolebinding test --clusterrole=test --serviceaccount=default:test
```
### Environment Variables
If script is run inside a Kubernetes pod and a service account is associated with the pod, only the mandatory variables are needed to run the script.
| Name            | Description                | Mandatory | Default Value
| -----------     | -----------                |---------- | ---------- |
| SECRETNAME      | secret object name         | yes       | N/A        |
| TLS_CERT_FILE   | Certificate file name      | yes       | N/A        |
| TLS_KEY_FILE    | Private Key file name      | yes       | N/A        |
| APISERVER       | Kubernetes API server URL  | no        | https://kubernetes.default.svc |
| NAMESPACE       | Kubernetes namespace       | no        | /var/run/secrets/kubernetes.io/serviceaccount/namespace  |
| TOKENFILE       | Service account auth token | no        | /var/run/secrets/kubernetes.io/serviceaccount/token  |
| CAFILE          | Kubernetes CA certificate  | no        | /var/run/secrets/kubernetes.io/serviceaccount/ca_file    |

## Sample Declarative Configuration

See the provided - *example_cronjob.yaml* - file as an example that runs the script everyday and updates the secret TLS certificate from an attached volume as long as the certificate has a later expiration date.
```
kubectl apply -f example_cronjob.yaml
```
You can verify the stored certificate using kubectl. Example:
```
kubectl get secrets mysecret -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 --text
```

## Build a Multi-Arch Docker Image
```
docker buildx build \
--push \
--tag $DOCKER_USERNAME/kubernetes_secret_update:latest \
-f Dockerfile \
--platform linux/amd64,linux/arm64 . 
```

## Testing Code Outside of Cluster
The code was primarily written to run inside of a kubernetes pod. In order to run it outside of the cluster you may need to retrieve some of the additional files (CA certificate and authorization token) in order to access the cluster from the outside.
```
# Get the name of the Kubernetes CA secret and save the CA to a file
CA=`kubectl get secret -n kube-system | grep default-token | awk '{ print $1}'`
kubectl -n kube-system get secret $CA -o jsonpath="{['data']['ca\.crt']}" | base64 --decode > ca.crt

# Get the name of the service account token and save the TOKEN to a file
TOKEN=`kubectl get secrets | grep secret-robot | awk '{ print $1}'`
kubectl get secrets $TOKEN -o jsonpath="{['data']['token']}" | base64 --decode > token.txt

# Create 2 certififcate/key pairs qith different expiration dates for testing
openssl req -x509 -newkey rsa:4096 -out testcert1.crt -keyout testcert1.key -sha256 -days 100 -nodes -subj '/CN=localhost
openssl req -x509 -newkey rsa:4096 -out testcert2.crt -keyout testcert2.key -sha256 -days 200 -nodes -subj '/CN=localhost'

```

