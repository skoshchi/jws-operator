Create folder
mkdir jws-operator
cd jws-operator

Clean the cache
go clean --modcache
go clean --cache

Create operator
operator-sdk init --domain web.servers.org --repo github.com/web-servers/jws-operator
operator-sdk create api --version v1alpha1 --kind WebServer --resource --controller

Add into PROJECT
"group: webservers"

Remove "_v1alpha1_webserver.yaml" from config/samples/kustomization.yaml

Login to quay.io
podman login quay.io

Set IMG env variable:
export IMG=quay.io/${USER}/jws-operator:new-sdk

Original versions of following files were copied
api/v1alpha1/webserver_types.go -> api/v1alpha1/webserver_types.go
controllers/helper.go -> internal/controller/helper.go
controllers/service.go -> internal/controller/service.go
controllers/servicemonitor.go -> internal/controller/servicemonitor.go
controllers/templates.go -> internal/controller/templates.go
controllers/webserver_controller.go -> internal/controller/webserver_controller.go

update package in helper.go, service.go, servicemonitor.go, templates.go, webserver_controller.go (from controllers -> controller)

TODO
update templates.go connected to k8s.io/apimachinery/pkg/api/resource

Build the operator
go mod tidy
make manifests docker-build docker-push

Try to create bundle
make bundle

Update bundle files:
- bundle/manifests/jws-operator.clusterserviceversion.yaml
- config/manifests/bases/jws-operator.clusterserviceversion.yaml

Build the bundle
make bundle-build bundle-push BUNDLE_IMG=quay.io/mmadzin/jws-operator-bundle:new-sdk

