package network

import (
	"crypto/ed25519"
	"time"
)

// CipherMode selects the symmetric cipher used for session traffic encryption.
type CipherMode int

const (
	// CipherNaCl uses XSalsa20-Poly1305 (software, legacy default).
	CipherNaCl CipherMode = iota
	// CipherAESGCM uses AES-256-GCM (hardware accelerated on modern CPUs).
	CipherAESGCM
)

type config struct {
	cipherMode          CipherMode
	maintenanceInterval time.Duration
	routerRefresh       time.Duration
	routerTimeout       time.Duration
	peerKeepAliveDelay  time.Duration
	peerTimeout         time.Duration
	peerMaxMessageSize  uint64
	peerQueueTimeout    time.Duration
	peerMaxQueueSize    uint64 // max bytes per packet queue before size-based drops
	maxInflightWrites   int    // max packets in WriteTo pipeline; 0 = no limit
	bloomTransform      func(ed25519.PublicKey) ed25519.PublicKey
	pathNotify          func(ed25519.PublicKey)
	pathTimeout         time.Duration
	pathThrottle        time.Duration
}

type Option func(*config)

func configDefaults() Option {
	return func(c *config) {
		c.maintenanceInterval = 10 * time.Millisecond
		c.routerRefresh = 4 * time.Minute
		c.routerTimeout = 5 * time.Minute
		c.peerKeepAliveDelay = time.Second
		c.peerTimeout = 3 * time.Second
		c.peerMaxMessageSize = 1048576 // 1 megabyte
		c.peerQueueTimeout = 5 * time.Second
		c.peerMaxQueueSize = 16 * 1024 * 1024 // 16 MB
		c.maxInflightWrites = 256
		c.bloomTransform = func(key ed25519.PublicKey) ed25519.PublicKey { return key }
		c.pathNotify = func(key ed25519.PublicKey) {}
		c.pathTimeout = time.Minute
		c.pathThrottle = time.Second
	}
}

func WithRouterRefresh(duration time.Duration) Option {
	return func(c *config) {
		c.routerRefresh = duration
	}
}

func WithRouterTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.routerTimeout = duration
	}
}

func WithPeerKeepAliveDelay(duration time.Duration) Option {
	return func(c *config) {
		c.peerKeepAliveDelay = duration
	}
}

func WithPeerTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.peerTimeout = duration
	}
}

func WithPeerMaxMessageSize(size uint64) Option {
	return func(c *config) {
		c.peerMaxMessageSize = size
	}
}

func WithBloomTransform(xform func(key ed25519.PublicKey) ed25519.PublicKey) Option {
	return func(c *config) {
		c.bloomTransform = xform
	}
}

func WithPathNotify(notify func(key ed25519.PublicKey)) Option {
	return func(c *config) {
		c.pathNotify = notify
	}
}

func WithPathTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.pathTimeout = duration
	}
}

func WithPathThrottle(duration time.Duration) Option {
	return func(c *config) {
		c.pathThrottle = duration
	}
}

func WithPeerQueueTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.peerQueueTimeout = duration
	}
}

func WithPeerMaxQueueSize(size uint64) Option {
	return func(c *config) {
		c.peerMaxQueueSize = size
	}
}

func WithMaxInflightWrites(n int) Option {
	return func(c *config) {
		c.maxInflightWrites = n
	}
}

// WithCipherMode selects the symmetric cipher for session traffic.
// Default is CipherNaCl for backwards compatibility.
func WithCipherMode(mode CipherMode) Option {
	return func(c *config) {
		c.cipherMode = mode
	}
}
