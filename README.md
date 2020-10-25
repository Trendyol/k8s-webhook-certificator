# certificator

🔐  🗒️  Creating K8S Secret which type is tls that includes corresponding client certificates which is signed by K8S CA and private key 

### Description

Generate a certificate suitable for use with a webhook service.

This cli tool uses k8s' CertificateSigningRequest API to generate a certificate signed by k8s CA suitable for use with sidecar-injector webhook services. This requires permissions to create and approve CSR.See [Kubernetes TLS management](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/) for detailed explanation and additional instructions.

The server key/cert will be stored in a k8s secret.

### Understanding the problem 

When we started to develop an Kubernetes Admission Webhook we notice that there was a requirement that enforced by the apiserver for the admission webhook server and this is TLS connection so apiserver and admission webhook server must connect via TLS with each other.See: [Contacting the webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#contacting-the-webhook). To ensure that we need a CA (Certificate Authority) and a client certificate which is signed by this CA. 

There are many ways to do that like creating a scripts that create CA and a client itself using openssl cli or using Kubernetes TLS management which is create client certificates by approving CSR's. 

But both ways when we decide to use Helm are a not become part of the Helm process , they are just a step before applying Helm release. 

So how can we become this step a part of this Helm process? Easy, Helm Hooks and a little code written with golang.

### Solution 

With the help of Helm Hooks, we can solve the problem of creating a setup step before installing all the templates to the cluster. 

Then if we create a cli tool that helps us to create CSR with a client certificate which is approved by this CSR with CA which is belongs to Kubernetes cluster itself and then creating a Kubernetes Secret which includes private key and a client certificate, then we will have successfully completed the process by calling this cli tool in Kubernetes Job.
