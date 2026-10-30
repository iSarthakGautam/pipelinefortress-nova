# PR-002 Review — R1

## Review Metadata

| Field | Details |
|---|---|
| Patch | `artifacts/prs/v2/pr-002.patch` |
| Original patch | `artifacts/prs/pr-002.patch` |
| Model output | `artifacts/prs/v2/pr-002.model_output.txt` |
| Target | `eval/fixtures/pr_targets/deployment.yaml` |
| Security rule | `CKV_K8S_40` |
| Reviewer | R1 |
| Verdict | **ACCEPT WITH VALIDATION LIMITS** |
| Review scope | Patch correctness, Kubernetes security context, and local runtime validation |

## 1. Patch Applicability and Scope

The original v1 patch at `artifacts/prs/pr-002.patch` is malformed. The recorded Git error is:

`error: corrupt patch at line 8`

Therefore, the original v1 patch must not be considered successfully applied or validated.

The v2 patch at `artifacts/prs/v2/pr-002.patch` was checked against the intended fixture directory using:

```bash
git apply --check \
  --directory=eval/fixtures/pr_targets \
  artifacts/prs/v2/pr-002.patch
```

**Result: PASS.** The command exited with status `0`.

The v2 patch changes the container security context from:

```yaml
securityContext:
  runAsNonRoot: false
```

to:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
```

The change is scoped to the container security context. It does not modify the Deployment selector, labels, replica count, container port, or image reference in the fixture.

The review verdict applies to v2 only. The v1 patch's malformed status remains unchanged.

## 2. Technical Review and Security Impact

### 2.1 Non-root execution

Setting `runAsNonRoot: true` instructs Kubernetes to require the container to run as a non-root user. Setting `runAsUser: 10001` specifies the numeric UID used for the container process.

These settings complement one another: the numeric UID selects the intended user, while `runAsNonRoot` enforces the non-root requirement.

The local hardened image was configured to use UID `10001`. During runtime validation, the following command was executed:

```bash
kubectl exec deployment/vulnshop-api \
  -n pr002-runtime-test -- id
```

Observed output:

```text
uid=10001(appuser) gid=10001(appgroup) groups=10001(appgroup),10001(appgroup)
```

**Result: PASS.** The running container process was observed with UID `10001`, rather than UID `0`.

### 2.2 Image compatibility

The test image was built from the project's `docker/Dockerfile.hardened` and loaded into Minikube as `vulnshop-api:1.0.0`.

The image's configured user was checked with:

```bash
docker image inspect vulnshop-api:1.0.0 \
  --format 'Configured user: {{.Config.User}}'
```

Observed result:

```text
Configured user: 10001
```

The application started successfully with the patched Kubernetes security context. This provides evidence of compatibility with the specific local image tested.

It does not establish compatibility with every possible image version or with an independently built production image.

### 2.3 Scope of the patch

The v2 patch introduces a targeted security-context change. The runtime test also used an isolated namespace and the locally built hardened image.

The image and test environment are validation inputs; they are not additional changes made by the v2 patch itself.

## 3. Runtime Validation Results

The patched deployment was tested in the isolated Minikube namespace `pr002-runtime-test`.

| Validation | Observed result | Verdict |
|---|---|---|
| v2 patch applicability | `git apply --check` exited `0` | PASS |
| Deployment rollout | Successfully rolled out | PASS |
| Available replicas | `1/1` | PASS |
| Container state | `Running` | PASS |
| Container readiness | `1/1 Ready` | PASS |
| Container restarts | `0` during the observed test | PASS |
| Runtime UID | `10001 (appuser)` | PASS |
| Applied security context | `runAsNonRoot: true`, `runAsUser: 10001` | PASS |
| Homepage smoke test | `GET /` returned HTTP `200 OK` | PASS |
| Health endpoint | `GET /healthz` returned HTTP `200 OK` | PASS |

The application logs showed that the Node.js API gateway started on port `3000` and that the Flask service started on port `5000`.

The homepage returned HTTP `200 OK`. The health endpoint returned:

```json
{
  "service": "vulnshop-api",
  "status": "HEALTHY"
}
```

The final Kubernetes inspection showed one available replica and a running pod with zero restarts.

**Runtime conclusion:** The v2 security-context change passed the tested local runtime scenario. The application started, ran as UID `10001`, and responded successfully on both tested endpoints.

## 4. Technical Risks and Validation Limits

The runtime evidence supports acceptance of the v2 change for the reviewed scope, but the following limits remain.

1. **Image-specific validation:** The test used the local hardened image built from `docker/Dockerfile.hardened`. The result does not prove that other image variants or future image versions will run correctly as UID `10001`.

2. **Filesystem permissions:** The tested startup succeeded, but all application write paths and other runtime operations were not exhaustively tested under the non-root identity.

3. **Limited endpoint coverage:** Only the homepage and `/healthz` were tested. The result does not establish that every API route or background operation works correctly.

4. **Production readiness:** The application logs warned that Flask was using a development server. This is outside the scope of the security-context patch, but it must be addressed separately before treating the tested setup as production-ready.

5. **Environment coverage:** The runtime result comes from one local Minikube environment. It does not substitute for validation in the intended CI/CD and production deployment environments.

6. **Original v1 patch:** The original v1 patch remains malformed. The v2 result must not be reported as proof that v1 applies cleanly.

## 5. What Would Make This Acceptable

The v2 patch is accepted for the reviewed scope because its applicability, security context, container UID, deployment readiness, and basic HTTP behavior were verified.

Before using the change in a production deployment, the following should also be completed:

- Confirm that the exact image intended for deployment supports UID `10001`.
- Test application filesystem permissions and required runtime operations under that UID.
- Run relevant API and integration tests, not just the homepage and health endpoint.
- Validate the image and deployment in the intended CI/CD environment.
- Address the development-server warning as a separate production-hardening task.
- Keep the v1 patch's malformed status distinct from the reviewed v2 result.

These are follow-up validation requirements, not claims that the current runtime test failed.

## 6. Reproduce the Review

Run these commands from the repository root.

### 6.1 Check the v2 patch

```bash
git apply --check \
  --directory=eval/fixtures/pr_targets \
  artifacts/prs/v2/pr-002.patch

echo "Exit code: $?"
```

Expected exit code: `0`.

### 6.2 Build and load the local hardened image

```bash
docker build \
  -f docker/Dockerfile.hardened \
  -t vulnshop-api:1.0.0 \
  apps/vulnshop-api

minikube image load vulnshop-api:1.0.0

docker image inspect vulnshop-api:1.0.0 \
  --format 'Configured user: {{.Config.User}}'
```

Expected configured user: `10001`.

### 6.3 Create an isolated test deployment

```bash
kubectl create namespace pr002-runtime-test \
  --dry-run=client -o yaml | kubectl apply -f -

cp eval/fixtures/pr_targets/deployment.yaml \
  /tmp/pr002-deployment.yaml

sed -i \
  's/runAsNonRoot: false/runAsNonRoot: true\n            runAsUser: 10001/' \
  /tmp/pr002-deployment.yaml

kubectl apply -n pr002-runtime-test \
  -f /tmp/pr002-deployment.yaml

kubectl patch deployment vulnshop-api \
  -n pr002-runtime-test \
  --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"vulnshop-api","imagePullPolicy":"Never"}]}}}}'

kubectl rollout status deployment/vulnshop-api \
  -n pr002-runtime-test --timeout=120s
```

### 6.4 Verify the running UID and deployment

```bash
kubectl exec deployment/vulnshop-api \
  -n pr002-runtime-test -- id

kubectl get deployment,pods \
  -n pr002-runtime-test

kubectl get deployment vulnshop-api \
  -n pr002-runtime-test \
  -o jsonpath='{.spec.template.spec.containers[0].securityContext}'

echo
```

Expected UID: `10001`.

Expected security context includes `runAsNonRoot: true` and `runAsUser: 10001`.

### 6.5 Test the application endpoints

In one terminal:

```bash
kubectl port-forward \
  -n pr002-runtime-test \
  deployment/vulnshop-api 3000:3000
```

In another terminal:

```bash
curl -i http://127.0.0.1:3000/
curl -i http://127.0.0.1:3000/healthz
```

Observed results in this review: both endpoints returned HTTP `200 OK`; `/healthz` reported status `HEALTHY`.

### 6.6 Cleanup

After collecting the required evidence:

```bash
kubectl delete namespace pr002-runtime-test
```

This removes the isolated runtime-test resources.

## 7. Final Verdict

**ACCEPT WITH VALIDATION LIMITS — PR-002 v2 reviewed by R1.**

The v2 patch applies cleanly to the intended fixture and adds `runAsNonRoot: true` with `runAsUser: 10001`. Runtime testing in the isolated Minikube namespace confirmed that the tested hardened image started successfully as UID `10001`, reached a ready state, and returned HTTP `200 OK` from both the homepage and health endpoint.

Acceptance is limited to the reviewed v2 patch and tested local image/environment. Production suitability, broader endpoint coverage, filesystem behavior, and compatibility with other images require separate validation. The malformed v1 patch remains unchanged and is not covered by this verdict.
