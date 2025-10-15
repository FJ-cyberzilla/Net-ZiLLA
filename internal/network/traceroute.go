// internal/network/traceroute.go
package network

import (
	"context"
	"fmt"
	"net"
	"time"
)

type TraceRoute struct {
	Hops []Hop
}

type Hop struct {
	Number    int
	IP        string
	Hostname  string
	RTT       time.Duration
	Status    string
}

type Tracer struct {
	timeout   time.Duration
	maxHops   int
}

func NewTracer() *Tracer {
	return &Tracer{
		timeout: 5 * time.Second,
		maxHops: 30,
	}
}

func (t *Tracer) Trace(target string) (*TraceRoute, error) {
	// Resolve target to IP
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for target")
	}

	targetIP := ips[0].String()
	route := &TraceRoute{}

	for hop := 1; hop <= t.maxHops; hop++ {
		hopResult, done, err := t.traceHop(targetIP, hop)
		if err != nil {
			continue
		}

		route.Hops = append(route.Hops, *hopResult)

		if done {
			break
		}
	}

	return route, nil
}

func (t *Tracer) traceHop(target string, ttl int) (*Hop, bool, error) {
	// This is a simplified traceroute implementation
	// In production, you'd use raw sockets for proper ICMP tracing
	
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", target), t.timeout)
	if err != nil {
		return &Hop{
			Number: ttl,
			Status: "timeout",
		}, false, nil
	}
	defer conn.Close()

	// Get the local address to determine the hop
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	
	// Perform reverse DNS lookup
	hostnames, _ := net.LookupAddr(localAddr.IP.String())
	hostname := ""
	if len(hostnames) > 0 {
		hostname = hostnames[0]
	}

	// Simple RTT measurement
	start := time.Now()
	_, err = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	if err == nil {
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(t.timeout))
		conn.Read(buf)
	}
	rtt := time.Since(start)

	hop := &Hop{
		Number:   ttl,
		IP:       localAddr.IP.String(),
		Hostname: hostname,
		RTT:      rtt,
		Status:   "success",
	}

	// Check if we've reached the target
	done := localAddr.IP.String() == target

	return hop, done, nil
}
