# Kestral Helm Chart

Deploy the Kestral REST API on Kubernetes.

## TL;DR

```bash
helm install my-kestral ./deploy/helm/kestral
```

## Configuration

The most common values you may want to override:

| Key | Description | Default |
|---|---|---|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Container image | `kestral` |
| `image.tag` | Image tag (defaults to `Chart.appVersion`) | `""` |
| `config.mode` | `block`, or `monitor` to log only | `block` |
| `config.threshold` | Risk score threshold for blocking | `0.7` |
| `service.type` | `ClusterIP` / `NodePort` / `LoadBalancer` | `ClusterIP` |
| `ingress.enabled` | Expose via Ingress | `false` |
| `autoscaling.enabled` | Enable HorizontalPodAutoscaler | `false` |
| `persistence.enabled` | Mount a PVC at `config.dataDir` (vault, history) | `false` |

See [`values.yaml`](values.yaml) for the complete list.

## Examples

### Production deployment with autoscaling and persistence

```yaml
# values-prod.yaml
replicaCount: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
persistence:
  enabled: true
  size: 10Gi
  storageClass: gp3
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: kestral.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: kestral-tls
      hosts:
        - kestral.example.com
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

```bash
helm install kestral ./deploy/helm/kestral -f values-prod.yaml
```

### Local development with port-forward

```bash
helm install dev ./deploy/helm/kestral --set replicaCount=1
kubectl port-forward svc/dev-kestral 8000:8000
curl http://localhost:8000/health
```

## Verify before installing

```bash
# Lint
helm lint ./deploy/helm/kestral

# Render templates without applying
helm template my-kestral ./deploy/helm/kestral
```

## Uninstall

```bash
helm uninstall my-kestral
```

If `persistence.enabled` was set, the PVC remains by design — delete it manually if you want to discard the vault and history databases.
