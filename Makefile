SHELL := /usr/bin/env bash

GOLIB ?= golib

.PHONY: check check-full ci cohesion inventory repository-check conformance

check: conformance
	$(GOLIB) check --local --all

check-full:
	$(GOLIB) check --all

ci: conformance
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) check --local --all

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check

conformance:
	$(MAKE) -f verification/package.mk conformance
