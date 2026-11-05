# CalVer: tag releases as YYYY.0M.MICRO (git tag 2026.11.0); the build embeds it.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra
LDLIBS   ?= -lncursesw

wgmon: src/main.cpp src/parse.hpp
	$(CXX) $(CXXFLAGS) -DWGMON_VERSION='"$(VERSION)"' -o $@ src/main.cpp $(LDFLAGS) $(LDLIBS)

test: src/test.cpp src/parse.hpp
	$(CXX) -std=c++20 -g -Wall -Wextra -fsanitize=address,undefined -o wgmon-test src/test.cpp
	./wgmon-test

# Static x86_64 binary in dist/wgmon, built in Docker (nothing to install here). scp it to the VPS.
dist:
	docker build -f lab/Dockerfile --target out --build-arg VERSION=$(VERSION) -o dist .

lab:
	VERSION=$(VERSION) docker compose -f lab/compose.yml up --build -d

lab-down:
	docker compose -f lab/compose.yml down -v

.PHONY: test dist lab lab-down
