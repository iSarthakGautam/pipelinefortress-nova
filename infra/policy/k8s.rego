# Policy-as-code for the Kubernetes manifests (CIS Kubernetes Benchmark 5.2.x / 5.7). Run with:
#   conftest test infra/k8s/deployment.hardened.yaml --policy infra/policy      (must pass)
#   conftest test infra/k8s/deployment.yaml          --policy infra/policy      (must FAIL: it is the planted bad manifest)
package main

import rego.v1

containers contains c if some c in input.spec.template.spec.containers

is_workload if input.kind == "Deployment"

deny contains msg if {
	is_workload
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("%s: container is privileged (CIS 5.2.1)", [c.name])
}

deny contains msg if {
	is_workload
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	some c in containers
	not c.securityContext.runAsNonRoot == true
	msg := sprintf("%s: runAsNonRoot is not true at pod or container level (CIS 5.2.6)", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	c.securityContext.runAsNonRoot == false
	msg := sprintf("%s: runAsNonRoot is explicitly false (CIS 5.2.6)", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("%s: root filesystem is writable (CIS 5.2.4)", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s: allowPrivilegeEscalation is not false (CIS 5.2.5)", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	not "ALL" in c.securityContext.capabilities.drop
	msg := sprintf("%s: capabilities.drop does not include ALL (CIS 5.2.9)", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	not c.resources.limits.memory
	msg := sprintf("%s: no memory limit", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	not c.resources.limits.cpu
	msg := sprintf("%s: no cpu limit", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	endswith(c.image, ":latest")
	msg := sprintf("%s: image uses the mutable :latest tag", [c.name])
}

deny contains msg if {
	is_workload
	some c in containers
	not contains(c.image, ":")
	not contains(c.image, "@")
	msg := sprintf("%s: image has no tag or digest (defaults to latest)", [c.name])
}
