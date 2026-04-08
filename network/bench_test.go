package network

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/ironwood/types"
)

// latencyConn simulates a WAN link with configurable one-way delay.
// It uses a buffered channel internally so writes don't block on reads
// (like a real kernel TCP buffer), and delays delivery via a goroutine.
type latencyConn struct {
	readLock  sync.Mutex
	recvBuf   []byte
	recv      chan []byte // buffered: delayed data arrives here
	writeLock sync.Mutex
	send      chan []byte // the other side's recv channel
	delay     time.Duration
	closeLock *sync.Mutex
	closed    chan struct{}
}

func newLatencyConnPair(keyA, keyB ed25519.PublicKey, delay time.Duration) (*latencyConn, *latencyConn) {
	// Large buffer so writes return instantly (like kernel TCP buffers)
	toA := make(chan []byte, 4096)
	toB := make(chan []byte, 4096)
	cl := new(sync.Mutex)
	closed := make(chan struct{})
	connA := &latencyConn{recv: toA, send: toB, delay: delay, closeLock: cl, closed: closed}
	connB := &latencyConn{recv: toB, send: toA, delay: delay, closeLock: cl, closed: closed}
	return connA, connB
}

func (l *latencyConn) Read(b []byte) (int, error) {
	l.readLock.Lock()
	defer l.readLock.Unlock()
	if len(l.recvBuf) == 0 {
		select {
		case <-l.closed:
			return 0, errors.New("closed")
		case bs := <-l.recv:
			l.recvBuf = append(l.recvBuf, bs...)
		}
	}
	n := len(b)
	if len(l.recvBuf) < n {
		n = len(l.recvBuf)
	}
	copy(b, l.recvBuf[:n])
	l.recvBuf = l.recvBuf[n:]
	return n, nil
}

func (l *latencyConn) Write(b []byte) (int, error) {
	l.writeLock.Lock()
	defer l.writeLock.Unlock()
	bs := append([]byte(nil), b...)
	if l.delay > 0 {
		// Simulate network delay: data arrives after one-way latency
		go func() {
			time.Sleep(l.delay)
			select {
			case l.send <- bs:
			case <-l.closed:
			}
		}()
	} else {
		select {
		case <-l.closed:
			return 0, errors.New("closed")
		case l.send <- bs:
		}
	}
	return len(bs), nil
}

func (l *latencyConn) Close() error {
	l.closeLock.Lock()
	defer l.closeLock.Unlock()
	select {
	case <-l.closed:
		return errors.New("closed")
	default:
		close(l.closed)
	}
	return nil
}

func (l *latencyConn) LocalAddr() net.Addr                { return nil }
func (l *latencyConn) RemoteAddr() net.Addr               { return nil }
func (l *latencyConn) SetDeadline(t time.Time) error      { return nil }
func (l *latencyConn) SetReadDeadline(t time.Time) error  { return nil }
func (l *latencyConn) SetWriteDeadline(t time.Time) error { return nil }

// setupTwoNodes creates a connected pair of ironwood nodes with the given options.
func setupTwoNodes(opts ...Option) (a, b *PacketConn, addrA, addrB types.Addr, cleanup func()) {
	_, privA, _ := ed25519.GenerateKey(nil)
	_, privB, _ := ed25519.GenerateKey(nil)
	a, _ = NewPacketConn(privA, opts...)
	b, _ = NewPacketConn(privB, opts...)
	pubA := ed25519.PublicKey(a.LocalAddr().(types.Addr))
	pubB := ed25519.PublicKey(b.LocalAddr().(types.Addr))
	cA, cB := newDummyConn(pubA, pubB)
	go a.HandleConn(pubB, cA, 0)
	go b.HandleConn(pubA, cB, 0)
	waitForRoot([]*PacketConn{a, b}, 30*time.Second)
	addrA = a.LocalAddr().(types.Addr)
	addrB = b.LocalAddr().(types.Addr)
	cleanup = func() {
		a.Close()
		b.Close()
	}
	return
}

// setupTwoNodesLatency creates nodes connected via latencyConn.
func setupTwoNodesLatency(delay time.Duration, opts ...Option) (a, b *PacketConn, addrA, addrB types.Addr, cleanup func()) {
	_, privA, _ := ed25519.GenerateKey(nil)
	_, privB, _ := ed25519.GenerateKey(nil)
	a, _ = NewPacketConn(privA, opts...)
	b, _ = NewPacketConn(privB, opts...)
	pubA := ed25519.PublicKey(a.LocalAddr().(types.Addr))
	pubB := ed25519.PublicKey(b.LocalAddr().(types.Addr))
	cA, cB := newLatencyConnPair(pubA, pubB, delay)
	go a.HandleConn(pubB, cA, 0)
	go b.HandleConn(pubA, cB, 0)
	waitForRoot([]*PacketConn{a, b}, 30*time.Second)
	addrA = a.LocalAddr().(types.Addr)
	addrB = b.LocalAddr().(types.Addr)
	cleanup = func() {
		a.Close()
		b.Close()
	}
	return
}

// drainReceiver runs a background goroutine that reads packets and counts bytes.
// The goroutine exits when the PacketConn is closed (by the test's cleanup func).
func drainReceiver(pc *PacketConn, bufSize int) (rxBytes *atomic.Int64, rxPkts *atomic.Int64) {
	rxBytes = &atomic.Int64{}
	rxPkts = &atomic.Int64{}
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			rxBytes.Add(int64(n))
			rxPkts.Add(1)
		}
	}()
	return
}

// =============================================================================
// Benchmark 1: Raw throughput — baseline packets/sec and MB/s
// =============================================================================

func BenchmarkThroughput(b *testing.B) {
	for _, size := range []int{64, 512, 1024, 4096, 8192} {
		b.Run(fmt.Sprintf("payload=%d", size), func(b *testing.B) {
			sender, receiver, _, addrB, cleanup := setupTwoNodes()
			defer cleanup()

			msg := make([]byte, size)
			rxBytes, _ := drainReceiver(receiver, size+256)

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sender.WriteTo(msg, addrB)
			}
			b.StopTimer()
			// Brief pause for receiver to catch up
			time.Sleep(200 * time.Millisecond)
			_ = rxBytes
		})
	}
}

// =============================================================================
// Benchmark 2: writeSem impact — does inflight window cap throughput?
// Uses timed measurement instead of waiting for all packets
// =============================================================================

func TestWriteSemInflight(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	for _, inflight := range []int{64, 256, 1024, 4096, 0} {
		name := fmt.Sprintf("inflight=%d", inflight)
		if inflight == 0 {
			name = "inflight=unlimited"
		}
		t.Run(name, func(t *testing.T) {
			sender, receiver, _, addrB, cleanup := setupTwoNodes(
				WithMaxInflightWrites(inflight),
			)
			defer cleanup()

			msg := make([]byte, 1024)
			rxBytes, rxPkts := drainReceiver(receiver, 2048)

			duration := 2 * time.Second
			deadline := time.After(duration)
			var txCount int
			start := time.Now()
		loop:
			for {
				select {
				case <-deadline:
					break loop
				default:
					sender.WriteTo(msg, addrB)
					txCount++
				}
			}
			elapsed := time.Since(start)
			time.Sleep(300 * time.Millisecond) // let receiver drain

			txMB := float64(txCount*1024) / (1024 * 1024)
			rxMB := float64(rxBytes.Load()) / (1024 * 1024)
			t.Logf("TX: %d pkts, %.1f MB/s | RX: %d pkts, %.1f MB/s | Loss: %.1f%%",
				txCount, txMB/elapsed.Seconds(),
				rxPkts.Load(), rxMB/elapsed.Seconds(),
				(1-float64(rxPkts.Load())/float64(txCount))*100)
		})
	}
}

// =============================================================================
// Benchmark 3: writeSem with simulated 200ms RTT
// This proves window sizing kills throughput on high-latency links
// =============================================================================

func TestWriteSemWithLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	for _, inflight := range []int{64, 256, 1024, 4096, 0} {
		name := fmt.Sprintf("inflight=%d", inflight)
		if inflight == 0 {
			name = "inflight=unlimited"
		}
		t.Run(name, func(t *testing.T) {
			// 100ms one-way = ~200ms RTT
			sender, receiver, _, addrB, cleanup := setupTwoNodesLatency(
				100*time.Millisecond,
				WithMaxInflightWrites(inflight),
			)
			defer cleanup()

			msg := make([]byte, 1024)
			rxBytes, rxPkts := drainReceiver(receiver, 2048)

			duration := 5 * time.Second
			deadline := time.After(duration)
			var txCount int
			start := time.Now()
		loop:
			for {
				select {
				case <-deadline:
					break loop
				default:
					sender.WriteTo(msg, addrB)
					txCount++
				}
			}
			elapsed := time.Since(start)
			time.Sleep(1 * time.Second) // let receiver drain through latency

			txMB := float64(txCount*1024) / (1024 * 1024)
			rxMB := float64(rxBytes.Load()) / (1024 * 1024)
			t.Logf("TX: %d pkts, %.1f MB/s | RX: %d pkts, %.1f MB/s | Loss: %.1f%%",
				txCount, txMB/elapsed.Seconds(),
				rxPkts.Load(), rxMB/elapsed.Seconds(),
				(1-float64(rxPkts.Load())/float64(txCount))*100)
		})
	}
}

// =============================================================================
// Benchmark 4: Single-packet round-trip latency
// Measures the per-packet overhead of the full actor chain
// =============================================================================

func BenchmarkRoundTripLatency(b *testing.B) {
	sender, receiver, addrA, addrB, cleanup := setupTwoNodes()
	defer cleanup()

	msg := make([]byte, 64)
	buf := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.WriteTo(msg, addrB)
		receiver.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, err := receiver.ReadFrom(buf)
		if err != nil {
			b.Fatal(err)
		}
		receiver.WriteTo(msg, addrA)
		sender.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, err = sender.ReadFrom(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

// =============================================================================
// Benchmark 5: Router serialization — multiple concurrent senders to 1 receiver
// If router is the bottleneck, adding senders won't increase total throughput
// =============================================================================

func TestRouterSerialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	for _, senders := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("senders=%d", senders), func(t *testing.T) {
			_, privRecv, _ := ed25519.GenerateKey(nil)
			receiver, _ := NewPacketConn(privRecv)
			recvPub := ed25519.PublicKey(receiver.LocalAddr().(types.Addr))
			addrRecv := receiver.LocalAddr().(types.Addr)

			var nodes []*PacketConn
			nodes = append(nodes, receiver)

			for i := 0; i < senders; i++ {
				_, privS, _ := ed25519.GenerateKey(nil)
				s, _ := NewPacketConn(privS)
				sPub := ed25519.PublicKey(s.LocalAddr().(types.Addr))
				cA, cB := newDummyConn(sPub, recvPub)
				go s.HandleConn(recvPub, cA, 0)
				go receiver.HandleConn(sPub, cB, 0)
				nodes = append(nodes, s)
			}
			waitForRoot(nodes, 30*time.Second)

			msg := make([]byte, 512)
			rxBytes, rxPkts := drainReceiver(receiver, 1024)

			duration := 2 * time.Second
			var txTotal atomic.Int64
			var wg sync.WaitGroup
			start := time.Now()
			for i := 1; i <= senders; i++ {
				wg.Add(1)
				go func(s *PacketConn) {
					defer wg.Done()
					deadline := time.After(duration)
					for {
						select {
						case <-deadline:
							return
						default:
							s.WriteTo(msg, addrRecv)
							txTotal.Add(1)
						}
					}
				}(nodes[i])
			}
			wg.Wait()
			elapsed := time.Since(start)
			time.Sleep(300 * time.Millisecond)

			txMB := float64(txTotal.Load()*512) / (1024 * 1024)
			rxMB := float64(rxBytes.Load()) / (1024 * 1024)
			t.Logf("TX: %d pkts, %.1f MB/s | RX: %d pkts, %.1f MB/s | Loss: %.1f%%",
				txTotal.Load(), txMB/elapsed.Seconds(),
				rxPkts.Load(), rxMB/elapsed.Seconds(),
				(1-float64(rxPkts.Load())/float64(txTotal.Load()))*100)

			for _, n := range nodes {
				n.Close()
			}
		})
	}
}

// =============================================================================
// Benchmark 6: Multi-hop forwarding overhead
// Measures throughput degradation as packets traverse more router actors
// =============================================================================

func TestMultiHopThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	for _, hops := range []int{1, 2, 4, 7} {
		t.Run(fmt.Sprintf("hops=%d", hops), func(t *testing.T) {
			numNodes := hops + 1
			var conns []*PacketConn
			for i := 0; i < numNodes; i++ {
				_, priv, _ := ed25519.GenerateKey(nil)
				c, _ := NewPacketConn(priv)
				conns = append(conns, c)
			}
			wait := make(chan struct{})
			for i := 1; i < numNodes; i++ {
				prev := conns[i-1]
				here := conns[i]
				keyA := ed25519.PublicKey(prev.LocalAddr().(types.Addr))
				keyB := ed25519.PublicKey(here.LocalAddr().(types.Addr))
				cA, cB := newDummyConn(keyA, keyB)
				go func() {
					<-wait
					prev.HandleConn(keyB, cA, 0)
				}()
				go func() {
					<-wait
					here.HandleConn(keyA, cB, 0)
				}()
			}
			close(wait)
			waitForRoot(conns, 30*time.Second)

			sender := conns[0]
			receiver := conns[numNodes-1]
			addrRecv := receiver.LocalAddr().(types.Addr)
			msg := make([]byte, 1024)

			rxBytes, rxPkts := drainReceiver(receiver, 2048)

			duration := 2 * time.Second
			deadline := time.After(duration)
			var txCount int
			start := time.Now()
		loop:
			for {
				select {
				case <-deadline:
					break loop
				default:
					sender.WriteTo(msg, addrRecv)
					txCount++
				}
			}
			elapsed := time.Since(start)
			time.Sleep(500 * time.Millisecond)

			txMB := float64(txCount*1024) / (1024 * 1024)
			rxMB := float64(rxBytes.Load()) / (1024 * 1024)
			t.Logf("TX: %d pkts, %.1f MB/s | RX: %d pkts, %.1f MB/s | Loss: %.1f%%",
				txCount, txMB/elapsed.Seconds(),
				rxPkts.Load(), rxMB/elapsed.Seconds(),
				(1-float64(rxPkts.Load())/float64(txCount))*100)

			for _, c := range conns {
				c.Close()
			}
		})
	}
}

// =============================================================================
// Benchmark 7: Allocation pressure — count allocs per WriteTo
// =============================================================================

func BenchmarkAllocsPerPacket(b *testing.B) {
	sender, receiver, _, addrB, cleanup := setupTwoNodes()
	defer cleanup()

	msg := make([]byte, 512)
	_, _ = drainReceiver(receiver, 1024)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.WriteTo(msg, addrB)
	}
	b.StopTimer()
}

// =============================================================================
// Test: Human-readable throughput report
// =============================================================================

func TestThroughputReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput report in short mode")
	}

	sender, receiver, _, addrB, cleanup := setupTwoNodes()
	defer cleanup()

	msg := make([]byte, 4096)
	rxBytes, rxPkts := drainReceiver(receiver, 8192)

	duration := 3 * time.Second
	deadline := time.After(duration)
	var txCount int
	start := time.Now()
loop:
	for {
		select {
		case <-deadline:
			break loop
		default:
			sender.WriteTo(msg, addrB)
			txCount++
		}
	}
	elapsed := time.Since(start)
	time.Sleep(500 * time.Millisecond)

	txMB := float64(txCount*len(msg)) / (1024 * 1024)
	rxMB := float64(rxBytes.Load()) / (1024 * 1024)
	t.Logf("Duration:    %v", elapsed.Round(time.Millisecond))
	t.Logf("TX:          %d packets, %.1f MB (%.1f MB/s)", txCount, txMB, txMB/elapsed.Seconds())
	t.Logf("RX:          %d packets, %.1f MB (%.1f MB/s)", rxPkts.Load(), rxMB, rxMB/elapsed.Seconds())
	t.Logf("Packet loss: %.1f%%", (1-float64(rxPkts.Load())/float64(txCount))*100)
}

// =============================================================================
// Test: Throughput over simulated WAN latency (200ms, 300ms RTT)
// =============================================================================

func TestLatencyThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	for _, rttMs := range []int{0, 200, 300, 500, 1000} {
		t.Run(fmt.Sprintf("rtt=%dms", rttMs), func(t *testing.T) {
			oneWay := time.Duration(rttMs/2) * time.Millisecond
			var sender, receiver *PacketConn
			var addrB types.Addr
			var cleanup func()
			if oneWay == 0 {
				sender, receiver, _, addrB, cleanup = setupTwoNodes()
			} else {
				sender, receiver, _, addrB, cleanup = setupTwoNodesLatency(oneWay)
			}
			defer cleanup()

			msg := make([]byte, 4096)
			rxBytes, rxPkts := drainReceiver(receiver, 8192)

			duration := 5 * time.Second
			dl := time.After(duration)
			var txCount int
			start := time.Now()
		loop:
			for {
				select {
				case <-dl:
					break loop
				default:
					sender.WriteTo(msg, addrB)
					txCount++
				}
			}
			elapsed := time.Since(start)
			// Give receiver time to drain through the latency pipe
			time.Sleep(time.Duration(rttMs)*time.Millisecond + 500*time.Millisecond)

			txMB := float64(txCount*len(msg)) / (1024 * 1024)
			rxMB := float64(rxBytes.Load()) / (1024 * 1024)
			t.Logf("TX: %d pkts, %.1f MB/s | RX: %d pkts, %.1f MB/s | Loss: %.1f%%",
				txCount, txMB/elapsed.Seconds(),
				rxPkts.Load(), rxMB/elapsed.Seconds(),
				(1-float64(rxPkts.Load())/float64(txCount))*100)
		})
	}
}

// =============================================================================
// Benchmark 8: GC pressure — compare throughput with and without GC
// Run with: go test -bench BenchmarkGCPressure -gcflags='-m' or GOGC=off
// =============================================================================

func BenchmarkGCPressure(b *testing.B) {
	sender, receiver, _, addrB, cleanup := setupTwoNodes()
	defer cleanup()

	msg := make([]byte, 1024)
	_, _ = drainReceiver(receiver, 2048)

	// Force GC before benchmark to get clean state
	runtime.GC()

	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.WriteTo(msg, addrB)
	}
	b.StopTimer()
}
