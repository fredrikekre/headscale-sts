# Deploys headscale-sts on the headscale host: downloads the release binary
# (checksum verified), installs the systemd unit, and creates the config and
# API key files if they do not exist. Run as root, e.g. `sudo make install`.
#
# The config is installed from a local (gitignored) config.yaml, created for
# the deployment based on config.example.yaml. The apikey target only runs
# when the file is missing, so `make install` never rotates the key; to
# rotate it: rm /etc/headscale-sts/apikey && make install restart.

VERSION           ?= v0.1.0
ARCH              ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
APIKEY_EXPIRATION ?= 3650d

PREFIX   ?= /usr/local
BIN      := $(PREFIX)/bin/headscale-sts
UNIT     := /etc/systemd/system/headscale-sts.service
CONF_DIR := /etc/headscale-sts
CONFIG   := $(CONF_DIR)/config.yaml
APIKEY   := $(CONF_DIR)/apikey

RELEASE_BIN := headscale-sts-$(VERSION)-linux-$(ARCH)
RELEASE_URL := https://github.com/fredrikekre/headscale-sts/releases/download/$(VERSION)

# Do not leave half-written targets behind on error (e.g. a failed
# `headscale apikeys create` must not leave an empty apikey file).
.DELETE_ON_ERROR:

.PHONY: install restart clean

install: $(BIN) $(UNIT) $(CONFIG) $(APIKEY)
	systemctl enable --now headscale-sts

restart:
	systemctl restart headscale-sts

# Download the release binary and verify its checksum
$(RELEASE_BIN):
	curl -fsSLO $(RELEASE_URL)/$(RELEASE_BIN)
	curl -fsSL -o SHA256SUMS-$(VERSION) $(RELEASE_URL)/SHA256SUMS
	sha256sum -c --ignore-missing SHA256SUMS-$(VERSION)

$(BIN): $(RELEASE_BIN)
	install -m 755 -o root -g root $< $@

$(UNIT): headscale-sts.service
	install -m 644 -o root -g root $< $@
	systemctl daemon-reload

$(CONF_DIR):
	install -d -m 755 -o root -g root $@

# Install the local (gitignored) config.yaml; re-installed when it changes
# (follow up with `make restart`).
$(CONFIG): config.yaml | $(CONF_DIR)
	install -m 644 -o root -g root $< $@

config.yaml:
	$(error config.yaml not found: create it for this deployment, see config.example.yaml)

# Generate the headscale API key. Not regenerated as long as the file exists.
$(APIKEY): | $(CONF_DIR)
	umask 077 && headscale apikeys create --expiration $(APIKEY_EXPIRATION) > $@
	chown root:root $@ && chmod 600 $@

clean:
	rm -f headscale-sts-v*-linux-* SHA256SUMS-v*
