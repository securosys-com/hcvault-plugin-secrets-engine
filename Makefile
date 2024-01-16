UNAME = $(shell uname -s)
.DEFAULT_GOAL := all
ARTIFACT_NAME = HCVault_Plugin-Secrets-Engine
TEST_RESULT_PATH = $(PWD)/
GOPATH=`go env GOPATH`

ifndef ARTIFACT_NAME
override ARTIFACT_NAME = HCVault_Plugin-Secrets-Engine
endif

all: fmt build start
release:
	@if [ "$(OS)" == "" ] && [ "$(ARCH)" == "" ] && [ "$(UNAME)" == "windows" ] ; then\
		echo "Build windows"; \
		CGO_ENABLED=0 go build -o builds/securosys-hsm.exe cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm.exe > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip securosys-hsm.exe securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm.exe; \
		rm builds/securosys-hsm_SHA256SUM; \
		echo "Finished!"; \
		exit 0; \
	fi;
	@if [ "$(OS)" == "" ] && [ "$(ARCH)" == "" ] && [ "$(UNAME)" != "windows" ] ; then\
		echo "Build $(UNAME)"; \
		CGO_ENABLED=0 go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
		echo "Finished!"; \
		exit 0; \
	fi;
	@if [ "$(OS)" == "windows" ]; then\
		echo "Build windows in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=${OS} GOARCH="${ARCH}" go build -o builds/securosys-hsm.exe cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm.exe > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip securosys-hsm.exe securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm.exe; \
		rm builds/securosys-hsm_SHA256SUM; \
		echo "Finished!"; \
	else\
		echo "Build ${OS} in ARCH: ${ARCH}"; \
		CGO_ENABLED=0 GOOS=${OS} GOARCH="${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_${OS}_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
		echo "Finished!"; \
	fi;

release-all:
	rm -rf builds
	for ARCH in amd64 arm64; do\
        echo "Build MacOS in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=darwin GOARCH="$${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_darwin_$${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_darwin_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	
	for ARCH in 386 amd64; do\
        echo "Build Windows in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=windows GOARCH="$${ARCH}" go build -o builds/securosys-hsm.exe cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm.exe > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_windows_$${ARCH}.zip securosys-hsm.exe securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_windows_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm.exe; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	
	for ARCH in 386 amd64 arm arm64; do\
        echo "Build Linux in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=linux GOARCH="$${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_linux_$${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_linux_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	
	for ARCH in 386 amd64 arm; do\
        echo "Build FreeBSD in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=freebsd GOARCH="$${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_freebsd_$${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_freebsd_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	
	for ARCH in 386 amd64 arm; do\
        echo "Build NetBSD in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=netbsd GOARCH="$${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_netbsd_$${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_netbsd_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	for ARCH in 386 amd64 arm; do\
        echo "Build OpenBSD in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=openbsd GOARCH="$${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_openbsd_$${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_openbsd_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	
	for ARCH in amd64; do\
        echo "Build Solaris in ARCH: $${ARCH}"; \
		CGO_ENABLED=0 GOOS=solaris GOARCH="$${ARCH}" go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; \
		cd builds; \
		shasum -a 256 securosys-hsm >> securosys-hsm_SHA256SUM; \
		zip -9 ${ARTIFACT_NAME}_solaris_$${ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; \
		shasum -a 256 ${ARTIFACT_NAME}_solaris_$${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
		cd ..; \
		rm builds/securosys-hsm; \
		rm builds/securosys-hsm_SHA256SUM; \
    done;
	
	echo "Finished!";	

build:
	CGO_ENABLED=0 go build -o vault/plugins/securosys-hsm cmd/securosys-hsm/main.go

start:
	./vault_exec server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	./vault_exec secrets enable securosys-hsm

clean:
	rm -f ./vault/plugins/securosys-hsm

fmt:
	go fmt $$(go list ./...)

test:
	go install github.com/jstemmer/go-junit-report/v2@latest
	cd tests && go test -count=1 -tags="unit integration" -v -timeout 15m 2>&1 ./... | ${GOPATH}/bin/go-junit-report -iocopy -out ${TEST_RESULT_PATH}junit_report.xml -set-exit-code

.PHONY: build clean fmt start enable
