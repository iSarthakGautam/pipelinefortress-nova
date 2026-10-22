# PR target fixtures (SYNTHETIC)

Small stand-ins for files R3 owns (`docker/Dockerfile`, `infra/k8s/deployment.yaml`, `apps/vulnshop-api/...`),
which are still empty. `ai/pr_bot.py` asks the local model to patch these and records whether the patch applies.
Re-run `ai/pr_bot.py` against R3's real files once they land. Nothing here is a scanner result.
