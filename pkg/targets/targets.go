package targets

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

type Target struct {
	Host     string
	IsIP     bool
	Original string
}

type TargetExpander struct {
	targets []Target
}

func NewTargetExpander() *TargetExpander {
	return &TargetExpander{
		targets: make([]Target, 0),
	}
}

func (te *TargetExpander) AddHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}

	if strings.Contains(host, "/") {
		return te.expandCIDR(host)
	}

	ip := net.ParseIP(host)
	te.targets = append(te.targets, Target{
		Host:     host,
		IsIP:     ip != nil,
		Original: host,
	})
	return nil
}

func (te *TargetExpander) AddHostList(hosts []string) error {
	for _, host := range hosts {
		if err := te.AddHost(host); err != nil {
			return fmt.Errorf("error adding host %s: %w", host, err)
		}
	}
	return nil
}

func (te *TargetExpander) AddFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open host file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := te.AddHost(line); err != nil {
			return fmt.Errorf("error on line %d: %w", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading host file: %w", err)
	}

	return nil
}

func (te *TargetExpander) expandCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	mask := binary.BigEndian.Uint32(ipnet.Mask)
	start := binary.BigEndian.Uint32(ipnet.IP)
	finish := (start & mask) | (^mask)

	for i := start; i <= finish; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		te.targets = append(te.targets, Target{
			Host:     ip.String(),
			IsIP:     true,
			Original: cidr,
		})
	}

	return nil
}

func (te *TargetExpander) GetTargets() []Target {
	seen := make(map[string]bool)
	unique := make([]Target, 0)

	for _, t := range te.targets {
		if !seen[t.Host] {
			seen[t.Host] = true
			unique = append(unique, t)
		}
	}

	return unique
}

func (te *TargetExpander) Count() int {
	return len(te.GetTargets())
}

func ParsePortRange(portSpec string) ([]int, error) {
	ports := make([]int, 0)
	seen := make(map[int]bool)

	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			var start, end int
			if _, err := fmt.Sscanf(rangeParts[0], "%d", &start); err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			if _, err := fmt.Sscanf(rangeParts[1], "%d", &end); err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			if start > end {
				start, end = end, start
			}

			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range out of bounds: %d-%d", start, end)
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			var port int
			if _, err := fmt.Sscanf(part, "%d", &port); err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of bounds: %d", port)
			}
			if !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}

	return ports, nil
}

func GetDefaultDBPorts() []int {
	return []int{
		3306,
		3307,
		5432,
		5433,
		1433,
		1434,
		1521,
		1522,
		1525,
		27017,
		27018,
		27019,
		6379,
		6380,
		9042,
		9160,
		7000,
		7001,
		8529,
		5984,
		6984,
		7474,
		7687,
		28015,
		29015,
		8087,
		8098,
		11211,
		9200,
		9300,
		5000,
		26257,
		4000,
		6033,
	}
}

func GetMinimalDBPorts() []int {
	return []int{
		3306,
		5432,
		1433,
		1521,
		27017,
		6379,
	}
}
