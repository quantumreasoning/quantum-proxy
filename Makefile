IMAGE ?= ghcr.io/quantumreasoning/quantumreasoning/quantum-proxy
TAG ?= latest
PUSH ?= true
LOAD ?= false

image: image-quantum-proxy

image-quantum-proxy:
	docker buildx build . \
		--provenance false \
		--tag $(IMAGE):$(TAG) \
		--cache-from type=registry,ref=$(IMAGE):latest \
		--cache-to type=inline \
		--push=$(PUSH) \
		--label "org.opencontainers.image.source=https://github.com/quantumreasoning/quantum-proxy" \
		--load=$(LOAD)
