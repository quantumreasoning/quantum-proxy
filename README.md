export CR_PAT="ghp_your_github_personal_access_token"
echo $CR_PAT | docker login ghcr.io -u quantumreasoning --password-stdin
docker build -t ghcr.io/quantumreasoning/quantumreasoning/quantum-proxy:v0.2.0 .