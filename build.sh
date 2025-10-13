echo $GH_PAT | docker login ghcr.io -u mkilijanek --password-stdin

sudo docker buildx build --pull --no-cache --provenance=true --sbom=true -t ghcr.io/mkilijanek/parsedmarc:8.18.6 --push .
