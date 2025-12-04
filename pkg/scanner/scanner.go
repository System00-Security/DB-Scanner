package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type PortState int

const (
	PortClosed PortState = iota
	PortOpen
	PortFiltered
)

func (ps PortState) String() string {
	switch ps {
	case PortOpen:
		return "open"
	case PortFiltered:
		return "filtered"
	default:
		return "closed"
	}
}

type ScanResult struct {
	Host      string
	Port      int
	State     PortState
	Banner    string
	Service   string
	Latency   time.Duration
	Timestamp time.Time
	Error     string
}

type ScanConfig struct {
	Timeout        time.Duration
	MaxConcurrency int
	RateLimit      time.Duration
	GrabBanner     bool
	BannerTimeout  time.Duration
}

func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Timeout:        3 * time.Second,
		MaxConcurrency: 100,
		RateLimit:      10 * time.Millisecond,
		GrabBanner:     true,
		BannerTimeout:  2 * time.Second,
	}
}

type Scanner struct {
	config *ScanConfig
}

func NewScanner(config *ScanConfig) *Scanner {
	if config == nil {
		config = DefaultScanConfig()
	}
	return &Scanner{config: config}
}

func (s *Scanner) ScanPort(ctx context.Context, host string, port int) ScanResult {
	result := ScanResult{
		Host:      host,
		Port:      port,
		State:     PortClosed,
		Timestamp: time.Now(),
	}

	address := fmt.Sprintf("%s:%d", host, port)

	dialer := net.Dialer{
		Timeout: s.config.Timeout,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	result.Latency = time.Since(start)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = PortFiltered
			result.Error = "connection timeout"
		} else {
			result.State = PortClosed
			result.Error = err.Error()
		}
		return result
	}
	defer conn.Close()

	result.State = PortOpen

	if s.config.GrabBanner {
		banner, service := s.grabBanner(conn, port)
		result.Banner = banner
		result.Service = service
	}

	return result
}

func (s *Scanner) grabBanner(conn net.Conn, port int) (string, string) {
	conn.SetReadDeadline(time.Now().Add(s.config.BannerTimeout))

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		banner := string(buffer[:n])
		service := identifyServiceFromBanner(banner, port)
		return banner, service
	}

	probes := getServiceProbes(port)
	for _, probe := range probes {
		conn.SetWriteDeadline(time.Now().Add(s.config.BannerTimeout))
		_, err := conn.Write(probe.Data)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(s.config.BannerTimeout))
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			banner := string(buffer[:n])
			if probe.Service != "" {
				return banner, probe.Service
			}
			return banner, identifyServiceFromBanner(banner, port)
		}
	}

	return "", guessServiceByPort(port)
}

type ServiceProbe struct {
	Data    []byte
	Service string
}

func getServiceProbes(port int) []ServiceProbe {
	probes := []ServiceProbe{}

	switch port {
	case 3306, 3307:
		return probes
	case 5432, 5433:
		startupMessage := []byte{
			0x00, 0x00, 0x00, 0x08,
			0x04, 0xd2, 0x16, 0x2f,
		}
		probes = append(probes, ServiceProbe{Data: startupMessage, Service: "postgresql"})
	case 6379, 6380:
		probes = append(probes, ServiceProbe{Data: []byte("PING\r\n"), Service: "redis"})
		probes = append(probes, ServiceProbe{Data: []byte("INFO\r\n"), Service: "redis"})
	case 27017, 27018, 27019:
		return probes
	case 1433, 1434:
		return probes
	}

	probes = append(probes, ServiceProbe{Data: []byte("\r\n"), Service: ""})

	return probes
}

func identifyServiceFromBanner(banner string, port int) string {
	bannerLower := string(banner)

	patterns := map[string][]string{
		"mysql": {
			"mysql",
			"mariadb",
			"\x00\x00\x00\x0a",
		},
		"postgresql": {
			"postgresql",
			"postgres",
		},
		"redis": {
			"+pong",
			"redis",
			"-noauth",
			"$",
		},
		"mongodb": {
			"mongodb",
			"ismaster",
		},
		"mssql": {
			"microsoft sql server",
			"sqlserver",
		},
		"oracle": {
			"oracle",
			"tns",
		},
		"cassandra": {
			"cassandra",
		},
		"elasticsearch": {
			"elasticsearch",
			"lucene",
		},
		"couchdb": {
			"couchdb",
		},
		"neo4j": {
			"neo4j",
		},
		"memcached": {
			"memcached",
			"version",
			"stat",
		},
	}

	for service, keywords := range patterns {
		for _, keyword := range keywords {
			if containsIgnoreCase(bannerLower, keyword) {
				return service
			}
		}
	}

	return guessServiceByPort(port)
}

func containsIgnoreCase(s, substr string) bool {
	sLower := make([]byte, len(s))
	substrLower := make([]byte, len(substr))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		sLower[i] = c
	}

	for i := 0; i < len(substr); i++ {
		c := substr[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		substrLower[i] = c
	}

	return contains(string(sLower), string(substrLower))
}

func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func guessServiceByPort(port int) string {
	portServices := map[int]string{
		3306:  "mysql",
		3307:  "mysql",
		5432:  "postgresql",
		5433:  "postgresql",
		1433:  "mssql",
		1434:  "mssql",
		1521:  "oracle",
		1522:  "oracle",
		1525:  "oracle",
		27017: "mongodb",
		27018: "mongodb",
		27019: "mongodb",
		6379:  "redis",
		6380:  "redis",
		9042:  "cassandra",
		9160:  "cassandra",
		7000:  "cassandra",
		7001:  "cassandra",
		8529:  "arangodb",
		5984:  "couchdb",
		6984:  "couchdb",
		7474:  "neo4j",
		7687:  "neo4j",
		28015: "rethinkdb",
		29015: "rethinkdb",
		8087:  "riak",
		8098:  "riak",
		11211: "memcached",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		5000:  "couchbase",
		26257: "cockroachdb",
		4000:  "tidb",
		6033:  "proxysql",
	}

	if service, ok := portServices[port]; ok {
		return service
	}
	return "unknown"
}

func (s *Scanner) ScanHost(ctx context.Context, host string, ports []int) []ScanResult {
	results := make([]ScanResult, 0, len(ports))
	resultChan := make(chan ScanResult, len(ports))

	semaphore := make(chan struct{}, s.config.MaxConcurrency)
	var wg sync.WaitGroup

	for _, port := range ports {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if s.config.RateLimit > 0 {
				time.Sleep(s.config.RateLimit)
			}

			result := s.ScanPort(ctx, host, p)
			resultChan <- result
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

func (s *Scanner) ScanHosts(ctx context.Context, hosts []string, ports []int) map[string][]ScanResult {
	results := make(map[string][]ScanResult)
	var mu sync.Mutex

	hostSemaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		wg.Add(1)
		go func(h string) {
			defer wg.Done()

			hostSemaphore <- struct{}{}
			defer func() { <-hostSemaphore }()

			hostResults := s.ScanHost(ctx, h, ports)

			mu.Lock()
			results[h] = hostResults
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results
}

func (s *Scanner) GetOpenPorts(results []ScanResult) []ScanResult {
	open := make([]ScanResult, 0)
	for _, r := range results {
		if r.State == PortOpen {
			open = append(open, r)
		}
	}
	return open
}

func IsStandardDBPort(port int) bool {
	standardPorts := map[int]bool{
		3306:  true,
		5432:  true,
		1433:  true,
		1521:  true,
		27017: true,
		6379:  true,
		9042:  true,
		5984:  true,
		7474:  true,
		9200:  true,
		11211: true,
	}
	return standardPorts[port]
}
