FROM ubuntu:20.04
RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -qy llvm clang software-properties-common make git && \
	add-apt-repository -y ppa:tuxinvader/kernel-build-tools && \
	apt-add-repository -y ppa:longsleep/golang-backports && \
	apt-get update && \
	apt-get install -y libbpf-dev golang-1.17 && \
	ln -s /usr/lib/go-1.17/bin/go /bin/go
COPY ./ /problem
WORKDIR /problem
RUN go mod download
RUN make -C bpf
CMD go run .
