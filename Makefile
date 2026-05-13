ZISKEMU     ?= $(HOME)/.zisk/bin/ziskemu
ZESU_ZISK    = zisk/zig-out/bin/zesu-zisk
BENCH_INPUT ?= bench/inputs/bench.bin
BASELINE_DIR = bench/baselines

.PHONY: build bench bench-profile bench-baseline bench-diff

# Build the zkVM binary (pulls zesu from ../zesu via path dependency).
# build.zig lives under zisk/ — invoke zig there.
build:
	cd zisk && zig build -Doptimize=ReleaseFast

# Fast run — prints step count only.
bench: build
	@$(ZISKEMU) --steps \
	  -e $(ZESU_ZISK) \
	  -i $(BENCH_INPUT) \
	  2>&1 | grep -E '^(STEPS|info:|error:)'

# Full profiling run — opcode histogram + top ROIs.
bench-profile: build
	@$(ZISKEMU) -X -S -T 25 -D -C 10 \
	  -e $(ZESU_ZISK) \
	  -i $(BENCH_INPUT) \
	  2>&1

# Save current step count as a baseline keyed by zesu git SHA.
# Usage: make bench-baseline  or  make bench-baseline SHA=some-label
bench-baseline: build
	$(eval SHA ?= $(shell git -C ../zesu rev-parse --short HEAD))
	@mkdir -p $(BASELINE_DIR)
	@steps=$$($(ZISKEMU) --steps -e $(ZESU_ZISK) -i $(BENCH_INPUT) 2>&1 | grep '^STEPS:' | awk '{print $$2}'); \
	  echo "$(SHA): $$steps" | tee $(BASELINE_DIR)/$(SHA).txt; \
	  echo "Baseline saved to $(BASELINE_DIR)/$(SHA).txt"

# Diff current step count against the most recent saved baseline.
bench-diff: build
	$(eval LATEST := $(shell ls -t $(BASELINE_DIR)/*.txt 2>/dev/null | head -1))
	@if [ -z "$(LATEST)" ]; then echo "No baseline found. Run: make bench-baseline"; exit 1; fi
	@prev_steps=$$(awk '{print $$2}' $(LATEST)); \
	  prev_sha=$$(basename $(LATEST) .txt); \
	  curr_steps=$$($(ZISKEMU) --steps -e $(ZESU_ZISK) -i $(BENCH_INPUT) 2>&1 | grep '^STEPS:' | awk '{print $$2}'); \
	  delta=$$((curr_steps - prev_steps)); \
	  pct=$$(echo "scale=2; $$delta * 100 / $$prev_steps" | bc); \
	  echo "Baseline : $$prev_sha  $$prev_steps steps"; \
	  echo "Current  : $$(git -C ../zesu rev-parse --short HEAD)  $$curr_steps steps"; \
	  echo "Delta    : $$delta steps ($$pct%)"
