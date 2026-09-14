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
	"context"
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
// Background:
//
//	The jws-operator itself (Go 1.24) already supports PQC for its own TLS
//	communications — Go 1.24 enables X25519MLKEM768 by default in crypto/tls
//	(see https://go.dev/doc/go1.24#crypto-mlkem). This satisfies OpenShift 5.x
//	control plane PQC requirements automatically.
//
//	This test verifies PQC for the Tomcat pods the operator manages, which use
//	Java/OpenSSL for TLS (not Go's crypto/tls). Tomcat PQC requires:
//	OpenSSLLifecycleListener (FFM/Panama) + ML-DSA-65 certificates.
//
//	The test uses only existing CRD fields (no operator code changes):
//	tlsConfig, volumeSpec.configMaps, and environmentVariables.
//
// Prerequisites:
//   - TEST_IMG must be a JWS image based on RHEL 10 with Java 25+ and OpenSSL 3.5.5+
//   - test-tls-secret must exist (standard RSA TLS secret, see test-scripts/TLS.md)
//   - The container image must include openssl and curl binaries
var _ = Describe("PQCTest", Ordered, func() {
	SetDefaultEventuallyTimeout(5 * time.Minute)
	SetDefaultEventuallyPollingInterval(5 * time.Second)

	ctx := context.Background()
	name := "pqc-test"
	appName := "pqc-test-app"
	pqcConfigMapName := "pqc-setup"

	// Shell script that runs inside the pod before Tomcat starts.
	// It generates ML-DSA-65 certificates and configures server.xml for PQC TLS.
	pqcSetupScript := `#!/bin/bash
# PQC setup: generate ML-DSA-65 certificates and configure Tomcat for PQC TLS

mkdir -p /tmp/pqc

# --- Certificate generation ---

# RSA CA (used to sign the PQC certificate)
openssl genrsa -out /tmp/pqc/ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key /tmp/pqc/ca.key -sha256 -days 365 \
    -out /tmp/pqc/ca.crt -subj "/CN=PQC-Test-CA" 2>/dev/null

# ML-DSA-65 key and CSR
openssl req -newkey mldsa65 -keyout /tmp/pqc/server.key -nodes \
    -out /tmp/pqc/server.csr -subj "/CN=localhost" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "PQC SETUP ERROR: openssl does not support mldsa65 on this image"
    return 0 2>/dev/null || true
fi

# Sign with the RSA CA
openssl x509 -req -in /tmp/pqc/server.csr \
    -CA /tmp/pqc/ca.crt -CAkey /tmp/pqc/ca.key -CAcreateserial \
    -out /tmp/pqc/server.crt -days 365 -sha256 2>/dev/null

if [ ! -f /tmp/pqc/server.crt ]; then
    echo "PQC SETUP ERROR: failed to generate ML-DSA-65 certificate"
    return 0 2>/dev/null || true
fi

echo "PQC: ML-DSA-65 certificates generated in /tmp/pqc/"

# --- server.xml modifications ---

FILE=$(find /opt -name server.xml 2>/dev/null | head -1)
if [ -z "${FILE}" ]; then
    FILE=$(find /deployments -name server.xml 2>/dev/null | head -1)
fi

if [ -z "${FILE}" ]; then
    echo "PQC SETUP ERROR: server.xml not found"
    return 0 2>/dev/null || true
fi

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

# Add MLDSA certificate alongside the existing RSA certificate in SSLHostConfig.
# The operator's test.sh already added: <Certificate certificateFile="/tls/server.crt" .../>
# We add a second Certificate of type MLDSA pointing to the PQC certs.
if grep -q '</SSLHostConfig>' ${FILE}; then
    sed -i 's|</SSLHostConfig>|<Certificate certificateFile="/tmp/pqc/server.crt" certificateKeyFile="/tmp/pqc/server.key" type="MLDSA" /> </SSLHostConfig>|' ${FILE}
    echo "PQC: MLDSA Certificate added to SSLHostConfig"
else
    echo "PQC SETUP WARNING: SSLHostConfig not found in server.xml (TLS connector may not be configured yet)"
fi

echo "PQC setup completed"
`

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
			},
			EnvironmentVariables: []corev1.EnvVar{
				{
					// Override operator's ENV_FILES to include both:
					// 1. Operator's test.sh (adds TLS Connector to server.xml)
					// 2. Our pqc-setup.sh (adds OpenSSLLifecycleListener + MLDSA cert)
					// K8s: last duplicate env var wins, so this overrides the operator's value.
					Name:  "ENV_FILES",
					Value: "/env/my-files/test.sh,/configmaps/" + pqcConfigMapName + "/pqc-setup.sh",
				},
			},
		},
	}

	// getFirstPod returns the name and container name of the first running pod for this WebServer.
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
	})

	Context("PostQuantumCryptoTest", func() {

		It("should start Tomcat with OpenSSL FFM and MLDSA certificate", func() {
			// Wait for deployment to have at least 1 available replica
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

			// Verify Tomcat initialized OpenSSL via FFM (Panama)
			Eventually(func() bool {
				logs := getPodLogs(namespace, podName)
				return strings.Contains(logs, "OpenSSL successfully initialized using FFM")
			}, "3m", "10s").Should(BeTrue(), "Tomcat should initialize OpenSSL via FFM")

			// Verify MLDSA certificate was loaded
			logs := getPodLogs(namespace, podName)
			Expect(logs).To(ContainSubstring("certificate type [MLDSA]"),
				"Tomcat logs should show MLDSA certificate was loaded")

			thetest.Logf("Tomcat started with OpenSSL FFM and MLDSA certificate")
		})

		It("should accept TLS connections with PQC key exchange", func() {
			podName, containerName := getFirstPod()

			// Send HTTPS request using curl with X25519MLKEM768 key exchange group
			stdout, stderr, err := executeCommandOnPod(podName, containerName, []string{
				"curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
				"--curves", "X25519MLKEM768",
				"https://localhost:8443/health",
			})
			Expect(err).ShouldNot(HaveOccurred(),
				"curl with PQC curves failed. stderr: %s", stderr)
			Expect(strings.TrimSpace(stdout)).To(Equal("200"),
				"HTTPS request with X25519MLKEM768 should return HTTP 200, got: %s (stderr: %s)", stdout, stderr)

			thetest.Logf("PQC TLS connection successful (HTTP 200)")
		})

		It("should negotiate X25519MLKEM768 group and ML-DSA signature in TLS handshake", func() {
			podName, containerName := getFirstPod()

			// Use openssl s_client to inspect TLS negotiation details
			stdout, _, err := executeCommandOnPod(podName, containerName, []string{
				"sh", "-c",
				"echo | openssl s_client -connect localhost:8443 2>&1 || true",
			})
			Expect(err).ShouldNot(HaveOccurred(), "openssl s_client exec failed")

			thetest.Logf("openssl s_client output:\n%s", stdout)

			// Verify PQC key exchange group was negotiated
			Expect(stdout).To(ContainSubstring("X25519MLKEM768"),
				"TLS should negotiate X25519MLKEM768 key exchange group")

			// Verify ML-DSA peer signature type
			Expect(strings.ToLower(stdout)).To(ContainSubstring("mldsa"),
				"TLS should use ML-DSA for peer signature")

			thetest.Logf("PQC TLS negotiation verified: X25519MLKEM768 + ML-DSA")
		})
	})
})
