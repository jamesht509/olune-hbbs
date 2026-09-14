#!/bin/bash
# Descobre o IP publico atual (IMDSv2) e grava em /opt/olune-server/.env (usado pelo hbbs e pelo Olune Access).
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || true)
if [ -n "$IP" ]; then echo "OLUNE_PUBLIC_HOST=$IP" > /opt/olune-server/.env; fi
