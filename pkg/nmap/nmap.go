package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type NmapConfig struct {
	BinaryPath     string
	Timing         int
	MaxRetries     int
	HostTimeout    time.Duration
	ScriptTimeout  time.Duration
	ExcludeScripts []string
}

func DefaultNmapConfig() *NmapConfig {
	return &NmapConfig{
		BinaryPath:    "nmap",
		Timing:        3,
		MaxRetries:    2,
		HostTimeout:   10 * time.Minute,
		ScriptTimeout: 5 * time.Minute,
		ExcludeScripts: []string{
			"brute",
			"dos",
			"exploit",
			"intrusive",
			"fuzzer",
		},
	}
}

type NmapRunner struct {
	config *NmapConfig
}

func NewNmapRunner(config *NmapConfig) *NmapRunner {
	if config == nil {
		config = DefaultNmapConfig()
	}
	return &NmapRunner{config: config}
}

type NmapResult struct {
	Host         string
	Port         int
	Protocol     string
	Service      string
	Version      string
	Product      string
	ExtraInfo    string
	Scripts      []ScriptResult
	CVEs         []CVEInfo
	RawXML       string
	ScanTime     time.Duration
	OSMatch      string
	ServiceConf  int
}

type ScriptResult struct {
	ID       string
	Output   string
	Elements map[string]string
}

type CVEInfo struct {
	ID          string
	Severity    string
	Description string
	CVSS        string
	Source      string
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Address nmapAddress `xml:"address"`
	Ports   nmapPorts   `xml:"ports"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Conf      int    `xml:"conf,attr"`
}

type nmapScript struct {
	ID     string        `xml:"id,attr"`
	Output string        `xml:"output,attr"`
	Elems  []nmapElement `xml:"elem"`
	Tables []nmapTable   `xml:"table"`
}

type nmapElement struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type nmapTable struct {
	Key   string        `xml:"key,attr"`
	Elems []nmapElement `xml:"elem"`
}

func (nr *NmapRunner) RunServiceDetection(ctx context.Context, host string, port int) (*NmapResult, error) {
	args := []string{
		"-sV",
		"-Pn",
		"-n",
		fmt.Sprintf("-T%d", nr.config.Timing),
		fmt.Sprintf("--max-retries=%d", nr.config.MaxRetries),
		"-oX", "-",
		"-p", fmt.Sprintf("%d", port),
		host,
	}

	return nr.runNmap(ctx, args, host, port)
}

func (nr *NmapRunner) RunScripts(ctx context.Context, host string, port int, service string) (*NmapResult, error) {
	scripts := nr.getScriptsForService(service)
	if len(scripts) == 0 {
		return nil, fmt.Errorf("no scripts available for service: %s", service)
	}

	scriptArg := strings.Join(scripts, ",")

	args := []string{
		"-sV",
		"-Pn",
		"-n",
		fmt.Sprintf("-T%d", nr.config.Timing),
		fmt.Sprintf("--max-retries=%d", nr.config.MaxRetries),
		"--script", scriptArg,
		"--script-args", "vulns.showall=true",
		"-oX", "-",
		"-p", fmt.Sprintf("%d", port),
		host,
	}

	return nr.runNmap(ctx, args, host, port)
}

func (nr *NmapRunner) RunFullScan(ctx context.Context, host string, port int, service string) (*NmapResult, error) {
	scripts := nr.getScriptsForService(service)
	scriptArg := ""
	if len(scripts) > 0 {
		scriptArg = strings.Join(scripts, ",")
	}

	args := []string{
		"-sV",
		"-sC",
		"-Pn",
		"-n",
		fmt.Sprintf("-T%d", nr.config.Timing),
		fmt.Sprintf("--max-retries=%d", nr.config.MaxRetries),
		"-oX", "-",
		"-p", fmt.Sprintf("%d", port),
	}

	if scriptArg != "" {
		args = append(args, "--script", scriptArg)
	}

	args = append(args, host)

	return nr.runNmap(ctx, args, host, port)
}

func (nr *NmapRunner) getScriptsForService(service string) []string {
	baseScripts := []string{
		"banner",
		"ssl-cert",
		"ssl-enum-ciphers",
	}

	serviceScripts := map[string][]string{
		"mysql": {
			"mysql-info",
			"mysql-enum",
			"mysql-empty-password",
			"mysql-vuln-cve2012-2122",
		},
		"mariadb": {
			"mysql-info",
			"mysql-enum",
			"mysql-empty-password",
		},
		"postgresql": {
			"pgsql-brute",
		},
		"mssql": {
			"ms-sql-info",
			"ms-sql-config",
			"ms-sql-empty-password",
			"ms-sql-ntlm-info",
		},
		"mongodb": {
			"mongodb-info",
			"mongodb-databases",
		},
		"redis": {
			"redis-info",
		},
		"oracle": {
			"oracle-tns-version",
			"oracle-sid-brute",
		},
		"cassandra": {
			"cassandra-info",
		},
		"couchdb": {
			"couchdb-stats",
			"couchdb-databases",
		},
		"elasticsearch": {
			"http-title",
		},
		"memcached": {
			"memcached-info",
		},
	}

	scripts := make([]string, 0)
	scripts = append(scripts, baseScripts...)

	if svcScripts, ok := serviceScripts[strings.ToLower(service)]; ok {
		scripts = append(scripts, svcScripts...)
	}

	filtered := make([]string, 0)
	for _, script := range scripts {
		excluded := false
		for _, exclude := range nr.config.ExcludeScripts {
			if strings.Contains(script, exclude) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, script)
		}
	}

	return filtered
}

func (nr *NmapRunner) runNmap(ctx context.Context, args []string, host string, port int) (*NmapResult, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, nr.config.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nmap scan timed out")
		}
		return nil, fmt.Errorf("nmap execution failed: %w, stderr: %s", err, stderr.String())
	}

	result := &NmapResult{
		Host:     host,
		Port:     port,
		RawXML:   stdout.String(),
		ScanTime: time.Since(start),
		Scripts:  make([]ScriptResult, 0),
		CVEs:     make([]CVEInfo, 0),
	}

	if err := nr.parseNmapXML(stdout.Bytes(), result); err != nil {
		return result, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	nr.extractCVEs(result)

	return result, nil
}

func (nr *NmapRunner) parseNmapXML(data []byte, result *NmapResult) error {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return err
	}

	for _, host := range run.Hosts {
		for _, port := range host.Ports.Ports {
			if port.PortID == result.Port {
				result.Protocol = port.Protocol
				result.Service = port.Service.Name
				result.Product = port.Service.Product
				result.Version = port.Service.Version
				result.ExtraInfo = port.Service.ExtraInfo
				result.ServiceConf = port.Service.Conf

				for _, script := range port.Scripts {
					sr := ScriptResult{
						ID:       script.ID,
						Output:   script.Output,
						Elements: make(map[string]string),
					}

					for _, elem := range script.Elems {
						sr.Elements[elem.Key] = elem.Value
					}

					for _, table := range script.Tables {
						for _, elem := range table.Elems {
							key := table.Key + "." + elem.Key
							sr.Elements[key] = elem.Value
						}
					}

					result.Scripts = append(result.Scripts, sr)
				}
			}
		}
	}

	return nil
}

func (nr *NmapRunner) extractCVEs(result *NmapResult) {
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d+`)

	for _, script := range result.Scripts {
		matches := cvePattern.FindAllString(script.Output, -1)
		for _, cve := range matches {
			cveInfo := CVEInfo{
				ID:     cve,
				Source: script.ID,
			}

			if strings.Contains(strings.ToLower(script.Output), "critical") {
				cveInfo.Severity = "Critical"
			} else if strings.Contains(strings.ToLower(script.Output), "high") {
				cveInfo.Severity = "High"
			} else if strings.Contains(strings.ToLower(script.Output), "medium") {
				cveInfo.Severity = "Medium"
			} else if strings.Contains(strings.ToLower(script.Output), "low") {
				cveInfo.Severity = "Low"
			}

			lines := strings.Split(script.Output, "\n")
			for _, line := range lines {
				if strings.Contains(line, cve) {
					cveInfo.Description = strings.TrimSpace(line)
					break
				}
			}

			result.CVEs = append(result.CVEs, cveInfo)
		}

		if cvss, ok := script.Elements["cvss"]; ok {
			if len(result.CVEs) > 0 {
				result.CVEs[len(result.CVEs)-1].CVSS = cvss
			}
		}
	}

	seen := make(map[string]bool)
	unique := make([]CVEInfo, 0)
	for _, cve := range result.CVEs {
		if !seen[cve.ID] {
			seen[cve.ID] = true
			unique = append(unique, cve)
		}
	}
	result.CVEs = unique
}

func (nr *NmapRunner) IsAvailable() bool {
	cmd := exec.Command(nr.config.BinaryPath, "--version")
	return cmd.Run() == nil
}

func (nr *NmapRunner) GetVersion() (string, error) {
	cmd := exec.Command(nr.config.BinaryPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0]), nil
	}
	return "", fmt.Errorf("unable to parse nmap version")
}
