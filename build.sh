

#!/bin/bash
set -e

VERSION=v0.3.0
cross build --release --target x86_64-unknown-linux-gnu
mkdir -p localbin
cp target/x86_64-unknown-linux-gnu/release/udp-tracer localbin
docker build -t maheshrayas/udp-tracer:$VERSION . -f Dockerfile
docker push maheshrayas/udp-tracer:$VERSION
kind load docker-image  maheshrayas/udp-tracer:$VERSION
kubectl apply -f deployment.yaml