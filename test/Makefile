# Builds caddy with caddy-security and this module, then runs Caddyfile with
# the settings in .env (copy .env.example to start).

XCADDY        ?= xcaddy
# Empty builds the latest Caddy release; e.g. CADDY_VERSION=v2.11.7
CADDY_VERSION ?=
SECURITY      ?= github.com/greenpau/caddy-security

CADDY  := ./caddy
CONFIG := --config Caddyfile --adapter caddyfile --envfile .env

.PHONY: build run validate adapt clean

build: $(CADDY)

$(CADDY): ../ldapauthz.go ../go.mod ../go.sum
	$(XCADDY) build $(CADDY_VERSION) --output $@ \
		--with $(SECURITY) \
		--with github.com/haught/caddy-ldapauthz=..

.env:
	cp .env.example .env
	@echo "Created test/.env from .env.example; fill in your settings and re-run." && false

run: $(CADDY) .env
	$(CADDY) run $(CONFIG)

validate: $(CADDY) .env
	$(CADDY) validate $(CONFIG)

adapt: $(CADDY) .env
	$(CADDY) adapt $(CONFIG) --pretty

clean:
	rm -f $(CADDY)
