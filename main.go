//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2022 The Inspektor Gadget authors

package main

import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang ok ./bpf/ok.bpf.c -- -I./bpf -I.. -target bpf -D__TARGET_ARCH_x86"
//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang problem ./bpf/problem.bpf.c -- -I./bpf -I.. -target bpf -D__TARGET_ARCH_x86"

func main() {
	ret := 0

	var err error

	var problemSpec *ebpf.CollectionSpec
	var problemCollection ebpf.CollectionOptions
	var problemIpv4Entry link.Link
	var problemIpv4Exit link.Link
	var problemReader *perf.Reader
	var problemObjs problemObjects

	var okSpec *ebpf.CollectionSpec
	var okCollection ebpf.CollectionOptions
	var okIpv4Entry link.Link
	var okIpv4Exit link.Link
	var okReader *perf.Reader
	var okObjs okObjects


	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	done := make(chan bool, 1)

	problemSpec, err = loadProblem()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ebpf program: %w", err)

		os.Exit(1)
	}

	problemCollection = ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}

	if err := problemSpec.LoadAndAssign(&problemObjs, &problemCollection); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ebpf program: %w", err)

		os.Exit(1)
	}

	problemIpv4Entry, err = link.Kprobe("inet_bind", problemObjs.Ipv4BindEntry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ipv4 kprobe: %w", err)

		ret = 1

		goto clean
	}

	problemIpv4Exit, err = link.Kretprobe("inet_bind", problemObjs.Ipv4BindExit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ipv4 kretprobe: %w", err)

		ret = 1

		goto clean
	}

	problemReader, err = perf.NewReader(problemObjs.problemMaps.Events, os.Getpagesize())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating perf ring buffer: %w", err)

		ret = 1

		goto clean
	}

	okSpec, err = loadOk()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ebpf program: %w", err)

		os.Exit(1)
	}

	okCollection = ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}

	if err := okSpec.LoadAndAssign(&okObjs, &okCollection); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ebpf program: %w", err)

		os.Exit(1)
	}

	okIpv4Entry, err = link.Kprobe("inet_bind", okObjs.Ipv4BindEntry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ipv4 kprobe: %w", err)

		ret = 1

		goto clean
	}

	okIpv4Exit, err = link.Kretprobe("inet_bind", okObjs.Ipv4BindExit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ipv4 kretprobe: %w", err)

		ret = 1

		goto clean
	}

	okReader, err = perf.NewReader(okObjs.okMaps.Events, os.Getpagesize())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating perf ring buffer: %w", err)

		ret = 1

		goto clean
	}

	go func(){
		<-sigChan
		done <- true
	}()

	<-done

clean:
	problemReader.Close()
	problemIpv4Entry.Close()
	problemIpv4Exit.Close()
	problemObjs.Close()

	okReader.Close()
	okIpv4Entry.Close()
	okIpv4Exit.Close()
	okObjs.Close()

	os.Exit(ret)
}
