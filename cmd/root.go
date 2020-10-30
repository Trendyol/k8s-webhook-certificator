/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	certv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"
	"strings"
	"time"
)

//var cfgFile string

var (
	kubeconfig, namespace, secret, service string
	days                                   int
	forceRenewal                           bool
	csrNameTemplate0                       = "${service}"
	csrNameTemplate1                       = "${service}.${namespace}"
	csrNameTemplate2                       = "${service}.${namespace}.svc"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "certificator",
	Short: "🔐🗒️ Creating K8S Secret which type is tls that includes corresponding client certificates which is signed by K8S CA and private key.",
	Long: `Generate a certificate suitable for use with a webhook service.

This cli tool uses k8s' CertificateSigningRequest API to generate a certificate signed by k8s CA suitable for use with sidecar-injector webhook services. This requires permissions to create and 	approve CSR.See Kubernetes TLS management(https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/) for detailed explanation and additional instructions
	
The server key/cert will be stored in a k8s secret.
	
Usage:
  certificator --service hello
  certificator --service hello --namespace platform --secret app-tls-secret`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		var config *rest.Config

		if kubeconfig == "" {
			// creates the in-cluster config
			restInClusterConfig, err := rest.InClusterConfig()
			if err != nil {
				log.Fatalf("rest.InClusterConfig() - error occurred, detail: %v", err)
			}
			config = restInClusterConfig
		} else {
			configFromFlags, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				log.Fatalf("clientcmd.BuildConfigFromFlags - error occurred, detail: %v", err)
			}
			config = configFromFlags
		}

		// creates the clientset
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("kubernetes.NewForConfig - error occurred, detail: %v", err)
		}

		r := strings.NewReplacer("${service}", service, "${namespace}", namespace)
		clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("rsa.GenerateKey - error occurred, detail: %v", err)
		}

		csrNameWithService := r.Replace(csrNameTemplate0)
		csrNameWithServiceAndNamespace := r.Replace(csrNameTemplate1)
		csrNameFull := r.Replace(csrNameTemplate2)

		template := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: csrNameWithServiceAndNamespace,
			},
			DNSNames: []string{csrNameWithService, csrNameWithServiceAndNamespace, csrNameFull},
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, clientPrivateKey)
		if err != nil {
			log.Fatalf("x509.CreateCertificateRequest - error occurred, detail: %v", err)
		}

		clientCSRPEM := new(bytes.Buffer)
		_ = pem.Encode(clientCSRPEM, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		// create  server cert/key CSR and  send to k8s API
		certificateSigningRequestsClient := clientset.CertificatesV1beta1().CertificateSigningRequests()

		certificateSigningRequest := &certv1beta1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: csrNameWithServiceAndNamespace,
			},
			Spec: certv1beta1.CertificateSigningRequestSpec{
				Request: clientCSRPEM.Bytes(),
				Usages:  []certv1beta1.KeyUsage{certv1beta1.UsageDigitalSignature, certv1beta1.UsageKeyEncipherment, certv1beta1.UsageServerAuth},
				Groups:  []string{"system:authenticated"},
			},
		}

		log.Println("Certificate signing request, status: Retrieving")
		csExistInCluster, err := certificateSigningRequestsClient.Get(context.TODO(), csrNameWithServiceAndNamespace, metav1.GetOptions{})
		if err != nil {
			log.Printf("Get CertificateSigningRequest - error occurred, detail: %v, but ignored", err)
		}

		if csExistInCluster.Status.Certificate != nil {
			log.Println("Certificate signing request, status: Retrieved")
			certificateAlreadyCreated := csExistInCluster.Status.Certificate
			block, _ := pem.Decode(certificateAlreadyCreated)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("x509.ParseCertificate - error occurred, detail: %v", err)
			}
			log.Println("Certificate signing request, status: Checking NotAfter date")

			validForDays := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
			log.Printf("Certificate signing request - status: This certificate valid for %d days", validForDays)

			expired := validForDays <= days
			log.Printf("Certificate signing request - status: Renewal necessary %t", expired || forceRenewal)

			log.Printf("Certificate signing request, status: Expired %t", expired)
			log.Printf("Certificate signing request, status: Force renewal %t", forceRenewal)
			if expired || forceRenewal {
				log.Println("Certificate signing request, status: Renewal process started")
				log.Println("Certificate signing request, status: Deleting")
				err = certificateSigningRequestsClient.Delete(context.TODO(), csrNameWithServiceAndNamespace, metav1.DeleteOptions{})
				if err != nil {
					log.Fatalf("Delete CertificateSigningRequest - error occurred, detail: %v, but ignored", err)
				}
				log.Println("Certificate signing request, status: Deleted")
			} else {
				log.Println("Certificate signing request, status: Renewal process is not necessary, skipped")
				os.Exit(0)
			}
		}
		log.Println("Certificate signing request, status: Not Retrieved")

		log.Println("Certificate signing request, status: Creating")
		csr, err := certificateSigningRequestsClient.Create(context.TODO(), certificateSigningRequest, metav1.CreateOptions{})
		if err != nil {
			log.Fatalf("Create CertificateSigningRequest - error occurred, detail: %v", err)
		}

		log.Println("Certificate signing request, status: Created")
		log.Println("Certificate signing request, status: Updating")

		// approve and fetch the signed certificate
		csr.Status.Conditions = append(csr.Status.Conditions, certv1beta1.CertificateSigningRequestCondition{
			Type:           certv1beta1.CertificateApproved,
			Message:        "This CSR was approved by certificator cli",
			LastUpdateTime: metav1.Now(),
		})

		_, err = certificateSigningRequestsClient.UpdateApproval(context.TODO(), csr, metav1.UpdateOptions{})
		if err != nil {
			log.Fatalf("UpdateApproval - error occurred, detail: %v", err)
		}

		log.Println("Certificate signing request, status: Updated")

		log.Println("Certificate signing request, status: Retrieving")
		var updatedCsr *certv1beta1.CertificateSigningRequest
		var attempt = 0
		for {
			if attempt < 3 {
				res, err := certificateSigningRequestsClient.Get(context.TODO(), csrNameWithServiceAndNamespace, metav1.GetOptions{})
				if err != nil {
					log.Fatalf("Get CertificateSigningRequest - error occurred, detail: %v", err)
				}
				updatedCsr = res
				if updatedCsr.Status.Certificate != nil {
					log.Println("Certificate signing request, status: Certificate Found")
					break
				}
				log.Println("Certificate signing request, status: No certificate found trying after 1 sec")
				time.Sleep(1 * time.Second)
			} else {
				log.Fatal("Certificate signing request, status: No certificate found, backed off after 3 attempt")
			}
			attempt += 1
		}

		log.Println("Certificate signing request, status: Retrieved")

		clientPrivateKeyPEM := new(bytes.Buffer)
		_ = pem.Encode(clientPrivateKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(clientPrivateKey),
		})

		clientCert := updatedCsr.Status.Certificate

		log.Println("Secret, status: Updating")
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secret,
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.key": clientPrivateKeyPEM.Bytes(),
				"tls.crt": clientCert,
			},
		}

		_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), tlsSecret, metav1.UpdateOptions{})
		if err != nil {
			log.Printf("Secret, status: Update secret - error occurred, detail: %v, ignored.", err)
			log.Println("Secret, status: Creating")
			_, err = clientset.CoreV1().Secrets(namespace).Create(context.TODO(), tlsSecret, metav1.CreateOptions{})
			if err != nil {
				log.Fatalf("create secret - error occurred, detail: %v", err)
			}
			log.Println("Secret, status: Created")
		} else {
			log.Println("Secret, status: Updated")
		}

		log.Printf("Done in %d milliseconds", time.Since(start).Milliseconds())
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	//cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.certificator.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "default", "Namespace where webhook service and secret reside.")
	rootCmd.Flags().StringVarP(&service, "service", "s", "", "Service name of webhook.")
	rootCmd.Flags().StringVarP(&secret, "secret", "t", "tls-secret", "Secret name for CA certificate and server certificate/key pair.")
	rootCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "kubeconfig path")
	rootCmd.Flags().IntVarP(&days, "days", "d", 1, "the number of days remaining for certificate renewal")
	rootCmd.Flags().BoolVarP(&forceRenewal, "force", "f", false, "enable force renewal before expiration time")

	_ = rootCmd.MarkFlagRequired("service")
}

// initConfig reads in config file and ENV variables if set.
//func initConfig() {
//	if cfgFile != "" {
//		// Use config file from the flag.
//		viper.SetConfigFile(cfgFile)
//	} else {
//		// Find home directory.
//		home, err := homedir.Dir()
//		if err != nil {
//			fmt.Println(err)
//			os.Exit(1)
//		}
//
//		// Search config in home directory with name ".certificator" (without extension).
//		viper.AddConfigPath(home)
//		viper.SetConfigName(".certificator")
//	}
//
//	viper.AutomaticEnv() // read in environment variables that match
//
//	// If a config file is found, read it in.
//	if err := viper.ReadInConfig(); err == nil {
//		fmt.Println("Using config file:", viper.ConfigFileUsed())
//	}
//}
