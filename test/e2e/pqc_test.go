/*
Copyright 2025.

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

package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	webserversv1alpha1 "github.com/web-servers/jws-operator/api/v1alpha1"
	kbappsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PQC (Post-Quantum Cryptography) test verifies ML-DSA-65 certificate support
// and X25519MLKEM768 key exchange for Tomcat workloads managed by the operator.
//
// The test generates ML-DSA-65 certificates locally (on the test machine),
// injects them into the pod via a Secret, and verifies PQC TLS using
// Go 1.24's native crypto/tls support (X25519MLKEM768 key exchange).
//
// Prerequisites:
//   - TEST_IMG must be a JWS image with OpenSSL 3.5.5+ and Tomcat Native / APR or FFM support
//   - test-tls-secret must exist (standard RSA TLS secret, see test-scripts/TLS.md)
//   - Local openssl must support mldsa65 (test is skipped otherwise)
//   - oc CLI must be available and logged in (used for port-forward)
var _ = Describe("PQCTest", Ordered, func() {
	SetDefaultEventuallyTimeout(5 * time.Minute)
	SetDefaultEventuallyPollingInterval(5 * time.Second)

	ctx := context.Background()
	name := "pqc-test"
	appName := "pqc-test-app"
	pqcConfigMapName := "pqc-setup"
	pqcSecretName := "pqc-certs"

	var certDir string

	// Shell script that runs inside the pod before Tomcat starts.
	// It configures server.xml for PQC TLS. Certificates are pre-generated
	// and mounted via Secret at /secrets/pqc-certs/.
	pqcSetupScript := `#!/bin/bash
# PQC setup: configure Tomcat server.xml for PQC TLS
# ML-DSA-65 certificates are pre-generated and mounted at /secrets/pqc-certs/

FILE=$(find /opt -name server.xml 2>/dev/null | head -1)
if [ -z "${FILE}" ]; then
    FILE=$(find /deployments -name server.xml 2>/dev/null | head -1)
fi

if [ -z "${FILE}" ]; then
    echo "PQC SETUP ERROR: server.xml not found"
    return 0 2>/dev/null || true
fi

if [ ! -f /secrets/pqc-certs/server.crt ] || [ ! -f /secrets/pqc-certs/server.key ]; then
    echo "PQC SETUP ERROR: certificates not found at /secrets/pqc-certs/"
    return 0 2>/dev/null || true
fi

echo "PQC: ML-DSA-65 certificates found at /secrets/pqc-certs/"

# Enable OpenSSLLifecycleListener (uncomment if commented, or insert if missing)
if grep -q '<!-- <Listener className="org.apache.catalina.core.OpenSSLLifecycleListener"' ${FILE}; then
    sed -i 's|<!-- <Listener className="org.apache.catalina.core.OpenSSLLifecycleListener" /> -->|<Listener className="org.apache.catalina.core.OpenSSLLifecycleListener" />|' ${FILE}
    echo "PQC: OpenSSLLifecycleListener uncommented"
elif ! grep -q 'OpenSSLLifecycleListener' ${FILE}; then
    sed -i '/<Server /a\  <Listener className="org.apache.catalina.core.OpenSSLLifecycleListener" />' ${FILE}
    echo "PQC: OpenSSLLifecycleListener inserted"
else
    echo "PQC: OpenSSLLifecycleListener already present"
fi

# Add MLDSA certificate alongside the existing RSA certificate in SSLHostConfig
if grep -q '</SSLHostConfig>' ${FILE}; then
    sed -i 's|</SSLHostConfig>|<Certificate certificateFile="/secrets/pqc-certs/server.crt" certificateKeyFile="/secrets/pqc-certs/server.key" type="MLDSA" /> </SSLHostConfig>|' ${FILE}
    echo "PQC: MLDSA Certificate added to SSLHostConfig"
else
    echo "PQC SETUP WARNING: SSLHostConfig not found in server.xml"
fi

echo "PQC setup completed"
`

	// generatePQCCerts generates ML-DSA-65 certificates using the local openssl.
	// Skips the test if the local openssl does not support mldsa65.
	generatePQCCerts := func() string {
		if _, err := exec.LookPath("openssl"); err != nil {
			Skip("openssl not found in PATH — cannot generate PQC certificates")
		}

		dir, err := os.MkdirTemp("", "pqc-certs-")
		Expect(err).ShouldNot(HaveOccurred())

		cmd := exec.Command("openssl", "genrsa", "-out", filepath.Join(dir, "ca.key"), "2048")
		out, err := cmd.CombinedOutput()
		Expect(err).ShouldNot(HaveOccurred(), "openssl genrsa failed: %s", string(out))

		cmd = exec.Command("openssl", "req", "-x509", "-new", "-nodes",
			"-key", filepath.Join(dir, "ca.key"), "-sha256", "-days", "365",
			"-out", filepath.Join(dir, "ca.crt"), "-subj", "/CN=PQC-Test-CA")
		out, err = cmd.CombinedOutput()
		Expect(err).ShouldNot(HaveOccurred(), "openssl req CA failed: %s", string(out))

		cmd = exec.Command("openssl", "req", "-newkey", "mldsa65",
			"-keyout", filepath.Join(dir, "server.key"), "-nodes",
			"-out", filepath.Join(dir, "server.csr"), "-subj", "/CN=localhost")
		out, err = cmd.CombinedOutput()
		if err != nil {
			os.RemoveAll(dir)
			Skip(fmt.Sprintf("Local openssl does not support mldsa65: %s", string(out)))
		}

		cmd = exec.Command("openssl", "x509", "-req",
			"-in", filepath.Join(dir, "server.csr"),
			"-CA", filepath.Join(dir, "ca.crt"), "-CAkey", filepath.Join(dir, "ca.key"),
			"-CAcreateserial", "-out", filepath.Join(dir, "server.crt"),
			"-days", "365", "-sha256")
		out, err = cmd.CombinedOutput()
		Expect(err).ShouldNot(HaveOccurred(), "openssl x509 sign failed: %s", string(out))

		thetest.Logf("ML-DSA-65 certificates generated in %s", dir)
		return dir
	}

	// startPortForward starts `oc port-forward` and returns the local port and a cleanup function.
	startPortForward := func(podName string, remotePort int) (int, func()) {
		listener, err := net.Listen("tcp", "localhost:0")
		Expect(err).ShouldNot(HaveOccurred())
		localPort := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		cmd := exec.Command("oc", "port-forward",
			fmt.Sprintf("pod/%s", podName),
			fmt.Sprintf("%d:%d", localPort, remotePort),
			"-n", namespace)

		stdout, err := cmd.StdoutPipe()
		Expect(err).ShouldNot(HaveOccurred())

		Expect(cmd.Start()).Should(Succeed(), "failed to start oc port-forward")

		// Wait for "Forwarding from ..." message
		scanner := bufio.NewScanner(stdout)
		ready := make(chan bool, 1)
		go func() {
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "Forwarding from") {
					ready <- true
					return
				}
			}
			ready <- false
		}()

		select {
		case ok := <-ready:
			Expect(ok).To(BeTrue(), "oc port-forward did not become ready")
		case <-time.After(30 * time.Second):
			cmd.Process.Kill()
			Fail("oc port-forward timed out")
		}

		return localPort, func() {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}

	pqcConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pqcConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			"pqc-setup.sh": pqcSetupScript,
		},
	}

	webserver := &webserversv1alpha1.WebServer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "WebServer",
			APIVersion: "web.servers.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: webserversv1alpha1.WebServerSpec{
			ApplicationName: appName,
			Replicas:        1,
			WebImage: &webserversv1alpha1.WebImageSpec{
				ApplicationImage: testImg,
			},
			TLSConfig: webserversv1alpha1.TLSConfig{
				TLSSecret:     "test-tls-secret",
				RouteHostname: "tls",
			},
			Volume: &webserversv1alpha1.VolumeSpec{
				ConfigMaps: []string{pqcConfigMapName},
				Secrets:    []string{pqcSecretName},
			},
			EnvironmentVariables: []corev1.EnvVar{
				{
					Name:  "ENV_FILES",
					Value: "/env/my-files/test.sh,/configmaps/" + pqcConfigMapName + "/pqc-setup.sh",
				},
			},
		},
	}

	getFirstPod := func() (podName string, containerName string) {
		podList := &corev1.PodList{}
		listOpts := []client.ListOption{
			client.InNamespace(namespace),
			client.MatchingLabels(map[string]string{
				"application": appName,
				"WebServer":   name,
			}),
		}
		ExpectWithOffset(1, k8sClient.List(ctx, podList, listOpts...)).Should(Succeed())
		ExpectWithOffset(1, podList.Items).ShouldNot(BeEmpty(), "no pods found for WebServer %s", name)
		podName = podList.Items[0].Name
		containerName = getPodContainerName(podName)
		return
	}

	BeforeAll(func() {
		certDir = generatePQCCerts()

		certData, err := os.ReadFile(filepath.Join(certDir, "server.crt"))
		Expect(err).ShouldNot(HaveOccurred())
		keyData, err := os.ReadFile(filepath.Join(certDir, "server.key"))
		Expect(err).ShouldNot(HaveOccurred())

		pqcSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pqcSecretName,
				Namespace: namespace,
			},
			Data: map[string][]byte{
				"server.crt": certData,
				"server.key": keyData,
			},
		}
		createSecret(pqcSecret)
		thetest.Logf("Secret %s created with ML-DSA-65 certificates", pqcSecretName)

		Expect(k8sClient.Create(ctx, pqcConfigMap)).Should(Succeed())
		thetest.Logf("ConfigMap %s created", pqcConfigMapName)

		createWebServer(webserver)
	})

	AfterAll(func() {
		deleteWebServer(webserver)

		Expect(k8sClient.Delete(ctx, pqcConfigMap)).Should(Succeed())
		Eventually(func() bool {
			err := k8sClient.Get(ctx, types.NamespacedName{Name: pqcConfigMapName, Namespace: namespace}, &corev1.ConfigMap{})
			return apierrors.IsNotFound(err)
		}, "1m", "5s").Should(BeTrue(), "pqc-setup ConfigMap should be deleted")

		pqcSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pqcSecretName,
				Namespace: namespace,
			},
		}
		deleteSecret(pqcSecret)

		if certDir != "" {
			os.RemoveAll(certDir)
		}
	})

	Context("PostQuantumCryptoTest", func() {

		It("should start Tomcat with OpenSSL and MLDSA certificate", func() {
			foundDeployment := &kbappsv1.Deployment{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: namespace}, foundDeployment)
				if err != nil {
					thetest.Logf("Deployment not found yet: %s", err)
					return false
				}
				return foundDeployment.Status.AvailableReplicas >= 1
			}, "5m", "10s").Should(BeTrue(), "Deployment should have at least 1 available replica")

			podName, _ := getFirstPod()

			Eventually(func() bool {
				logs := getPodLogs(namespace, podName)
				return strings.Contains(logs, "OpenSSL successfully initialized")
			}, "3m", "10s").Should(BeTrue(), "Tomcat should initialize OpenSSL")

			logs := getPodLogs(namespace, podName)
			Expect(logs).To(ContainSubstring("MLDSA"),
				"Tomcat logs should show MLDSA certificate configuration")
			Expect(logs).To(ContainSubstring("PQC setup completed"),
				"PQC setup script should complete successfully")

			thetest.Logf("Tomcat started with OpenSSL and MLDSA certificate")
		})

		It("should negotiate X25519MLKEM768 PQC key exchange", func() {
			podName, _ := getFirstPod()

			localPort, stopFw := startPortForward(podName, 8443)
			defer stopFw()

			// Only offer X25519MLKEM768 — if the handshake succeeds,
			// the server negotiated PQC key exchange (no other option offered).
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				CurvePreferences:  []tls.CurveID{tls.X25519MLKEM768},
			}
			addr := fmt.Sprintf("localhost:%d", localPort)

			Eventually(func() error {
				conn, err := tls.Dial("tcp", addr, tlsConfig)
				if err != nil {
					return fmt.Errorf("TLS dial failed: %w", err)
				}
				state := conn.ConnectionState()
				conn.Close()
				thetest.Logf("TLS negotiated: Version=0x%04x CipherSuite=0x%04x",
					state.Version, state.CipherSuite)
				return nil
			}, "1m", "5s").Should(Succeed(),
				"TLS handshake with only X25519MLKEM768 should succeed")

			thetest.Logf("PQC key exchange verified: X25519MLKEM768")
		})

		It("should serve HTTPS with PQC key exchange", func() {
			podName, _ := getFirstPod()

			localPort, stopFw := startPortForward(podName, 8443)
			defer stopFw()

			// Force X25519MLKEM768 only — proves PQC key exchange for HTTP traffic
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					CurvePreferences:  []tls.CurveID{tls.X25519MLKEM768},
				},
			}
			httpClient := &http.Client{
				Transport: transport,
				Timeout:   30 * time.Second,
			}

			url := fmt.Sprintf("https://localhost:%d/health", localPort)
			var resp *http.Response
			Eventually(func() error {
				var err error
				resp, err = httpClient.Get(url)
				return err
			}, "1m", "5s").Should(Succeed(), "HTTPS GET with X25519MLKEM768 should succeed")
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(http.StatusOK),
				"HTTPS request with PQC should return HTTP 200")

			thetest.Logf("PQC HTTPS verified: HTTP 200 with X25519MLKEM768")
		})
	})
})
