CORE_VERSION_ROOT := $(realpath $(CORE_VERSION_ROOT))
CORE_BUILD_COMMIT := $(shell \
	if [ "$$(git -C "$(CORE_VERSION_ROOT)" rev-parse --show-toplevel 2>/dev/null)" = "$(CORE_VERSION_ROOT)" ] && \
		core_build_revision=$$(git -C "$(CORE_VERSION_ROOT)" rev-parse --short=7 HEAD 2>/dev/null) && \
		core_build_dirty=$$(git -C "$(CORE_VERSION_ROOT)" status --porcelain --untracked-files=normal -- . 2>/dev/null); then \
		if [ -n "$$core_build_dirty" ]; then printf '%s-dirty' "$$core_build_revision"; else printf '%s' "$$core_build_revision"; fi; \
	else printf '%s' unknown; fi)

$(CORE_VERSION_FILES): core-version-force
	@python3 -c 'import os,sys,tempfile; from pathlib import Path; path=Path(sys.argv[1]); content=("\043define VLESS_CORE_COMMIT \"%s\"\n"%sys.argv[2]).encode(); path.parent.mkdir(parents=True,exist_ok=True); same=path.exists() and path.read_bytes()==content; sys.exit(0) if same else None; temporary=tempfile.NamedTemporaryFile(dir=path.parent,delete=False); temporary.write(content); temporary.close(); os.replace(temporary.name,path)' "$@" "$(CORE_BUILD_COMMIT)"

core-version-force:

.PHONY: core-version-force
