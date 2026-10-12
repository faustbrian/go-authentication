SHELL := /usr/bin/env bash

GOLIB ?= golib

.PHONY: source-docs-check check check-full ci cohesion inventory repository-check conformance

check: source-docs-check conformance
	$(GOLIB) check --local --all

check-full: source-docs-check
	$(GOLIB) check --all

ci: source-docs-check conformance
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) check --local --all

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check

conformance:
	$(MAKE) -f verification/package.mk conformance

source-docs-check:
	$(GOLIB) source-docs check
