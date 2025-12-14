#!/bin/bash
# Build & Push images
docker build -t your-registry/siem-server:latest server/
docker build -t your-registry/siem-dashboard:latest dashboard/
docker push your-registry/siem-server:latest
docker push your-registry/siem-dashboard:latest

# K8s Deploy
kubectl apply -f k8s/
kubectl rollout status deployment/siem-server -n siem
kubectl port-forward svc/traefik -n siem 8080:80
