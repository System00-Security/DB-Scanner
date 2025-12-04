package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"dbscanner/pkg/auth"
	"dbscanner/pkg/configcheck"
	"dbscanner/pkg/fingerprint"
	"dbscanner/pkg/nmap"
	"dbscanner/pkg/report"
	"dbscanner/pkg/scanner"
	"dbscanner/pkg/targets"
)

type Config struct {
	Targets         string
	TargetFile      string
	Ports           string
	Profile         string
	OutputFile      string
	OutputFormat    string
	Timeout         time.Duration
	MaxConcurrency  int
	NmapPath        string
	NmapTiming      int
	SkipNmap        bool
	SkipAuth        bool
	SkipConfig      bool
	Verbose         bool
	WordlistUser    string
	WordlistPass    string
	BruteForce      bool
	AuthUser        string
	AuthPass        string
	AuthDB          string
	MaxAuthAttempts int
}

func main() {
	config := parseFlags()

	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printBanner()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, shutting down gracefully...")
		cancel()
	}()

	if err := run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Targets, "target", "", "Target host(s): IP, hostname, CIDR, or comma-separated list")
	flag.StringVar(&config.Targets, "t", "", "Target host(s) (shorthand)")
	flag.StringVar(&config.TargetFile, "target-file", "", "File containing targets (one per line)")
	flag.StringVar(&config.TargetFile, "iL", "", "File containing targets (shorthand)")
	flag.StringVar(&config.Ports, "ports", "", "Ports to scan (e.g., '3306,5432' or '1-1000')")
	flag.StringVar(&config.Ports, "p", "", "Ports to scan (shorthand)")
	flag.StringVar(&config.Profile, "profile", "default", "Scan profile: fast, default, thorough")
	flag.StringVar(&config.OutputFile, "output", "", "Output file path")
	flag.StringVar(&config.OutputFile, "o", "", "Output file path (shorthand)")
	flag.StringVar(&config.OutputFormat, "format", "text", "Output format: text, json, pdf")
	flag.DurationVar(&config.Timeout, "timeout", 5*time.Second, "Connection timeout")
	flag.IntVar(&config.MaxConcurrency, "concurrency", 50, "Maximum concurrent scans")
	flag.StringVar(&config.NmapPath, "nmap-path", "nmap", "Path to nmap binary")
	flag.IntVar(&config.NmapTiming, "nmap-timing", 3, "Nmap timing template (0-5)")
	flag.BoolVar(&config.SkipNmap, "skip-nmap", false, "Skip Nmap scanning")
	flag.BoolVar(&config.SkipAuth, "skip-auth", false, "Skip authentication checks")
	flag.BoolVar(&config.SkipConfig, "skip-config", false, "Skip configuration checks")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output (shorthand)")
	flag.StringVar(&config.WordlistUser, "wordlist-user", "", "Custom username wordlist file for brute force")
	flag.StringVar(&config.WordlistPass, "wordlist-pass", "", "Custom password wordlist file for brute force")
	flag.BoolVar(&config.BruteForce, "brute", false, "Enable brute force mode with wordlists")
	flag.StringVar(&config.AuthUser, "auth-user", "", "Username for authenticated scanning")
	flag.StringVar(&config.AuthPass, "auth-pass", "", "Password for authenticated scanning")
	flag.StringVar(&config.AuthDB, "auth-db", "", "Database name for authenticated scanning")
	flag.IntVar(&config.MaxAuthAttempts, "max-auth-attempts", 10, "Maximum authentication attempts")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Database Exposure Scanner - Non-destructive security assessment tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -t 192.168.1.100\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -t 10.0.0.0/24 -profile thorough\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -iL hosts.txt -p 3306,5432,27017 -o report.json -format json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -t 192.168.1.100 -auth-user admin -auth-pass secret -auth-db mydb\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -t 192.168.1.100 -brute -wordlist-user users.txt -wordlist-pass pass.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nProfiles:\n")
		fmt.Fprintf(os.Stderr, "  fast      - Quick scan with minimal ports and checks\n")
		fmt.Fprintf(os.Stderr, "  default   - Standard scan with common DB ports\n")
		fmt.Fprintf(os.Stderr, "  thorough  - Full scan with all ports and deep checks\n")
		fmt.Fprintf(os.Stderr, "\nAuthenticated Scanning:\n")
		fmt.Fprintf(os.Stderr, "  Use -auth-user and -auth-pass to perform deep configuration checks\n")
		fmt.Fprintf(os.Stderr, "  with valid credentials. This enables more thorough security analysis.\n")
		fmt.Fprintf(os.Stderr, "\nBrute Force Mode:\n")
		fmt.Fprintf(os.Stderr, "  Use -brute with -wordlist-user and -wordlist-pass for custom wordlists.\n")
		fmt.Fprintf(os.Stderr, "  WARNING: Only use on systems you have permission to test.\n")
	}

	flag.Parse()
	return config
}

func validateConfig(config *Config) error {
	if config.Targets == "" && config.TargetFile == "" {
		return fmt.Errorf("no targets specified. Use -target or -target-file")
	}

	if config.Profile != "fast" && config.Profile != "default" && config.Profile != "thorough" {
		return fmt.Errorf("invalid profile: %s. Must be fast, default, or thorough", config.Profile)
	}

	if config.OutputFormat != "text" && config.OutputFormat != "json" && config.OutputFormat != "pdf" {
		return fmt.Errorf("invalid output format: %s. Must be text, json, or pdf", config.OutputFormat)
	}

	if config.NmapTiming < 0 || config.NmapTiming > 5 {
		return fmt.Errorf("invalid nmap timing: %d. Must be 0-5", config.NmapTiming)
	}

	if config.MaxConcurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}

	if config.BruteForce {
		if config.WordlistUser == "" && config.WordlistPass == "" {
			return fmt.Errorf("brute force mode requires at least one wordlist (-wordlist-user or -wordlist-pass)")
		}
		if config.WordlistUser != "" {
			if _, err := os.Stat(config.WordlistUser); os.IsNotExist(err) {
				return fmt.Errorf("username wordlist file not found: %s", config.WordlistUser)
			}
		}
		if config.WordlistPass != "" {
			if _, err := os.Stat(config.WordlistPass); os.IsNotExist(err) {
				return fmt.Errorf("password wordlist file not found: %s", config.WordlistPass)
			}
		}
	}

	if config.MaxAuthAttempts < 1 {
		return fmt.Errorf("max-auth-attempts must be at least 1")
	}

	return nil
}

func printBanner() {
	fmt.Println(`
  ____  ____    ____                                 
 |  _ \| __ )  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | | | |  _ \  \___ \ / __/ _` + "`" + ` | '_ \| '_ \ / _ \ '__|
 | |_| | |_) |  ___) | (_| (_| | | | | | | |  __/ |   
 |____/|____/  |____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                      
  Database Exposure Scanner v1.0.0
  Non-destructive security assessment tool
  For authorized security testing only
`)
}

func run(ctx context.Context, config *Config) error {
	startTime := time.Now()

	fmt.Println("[*] Initializing scan...")

	targetExpander := targets.NewTargetExpander()

	if config.Targets != "" {
		for _, t := range strings.Split(config.Targets, ",") {
			if err := targetExpander.AddHost(strings.TrimSpace(t)); err != nil {
				return fmt.Errorf("invalid target %s: %w", t, err)
			}
		}
	}

	if config.TargetFile != "" {
		if err := targetExpander.AddFromFile(config.TargetFile); err != nil {
			return fmt.Errorf("failed to load targets from file: %w", err)
		}
	}

	targetList := targetExpander.GetTargets()
	if len(targetList) == 0 {
		return fmt.Errorf("no valid targets found")
	}

	fmt.Printf("[*] Loaded %d target(s)\n", len(targetList))

	var ports []int
	if config.Ports != "" {
		var err error
		ports, err = targets.ParsePortRange(config.Ports)
		if err != nil {
			return fmt.Errorf("invalid port specification: %w", err)
		}
	} else {
		ports = getPortsForProfile(config.Profile)
	}

	fmt.Printf("[*] Scanning %d port(s)\n", len(ports))

	scanConfig := &scanner.ScanConfig{
		Timeout:        config.Timeout,
		MaxConcurrency: config.MaxConcurrency,
		RateLimit:      getRateLimitForProfile(config.Profile),
		GrabBanner:     true,
		BannerTimeout:  2 * time.Second,
	}
	portScanner := scanner.NewScanner(scanConfig)

	var nmapRunner *nmap.NmapRunner
	var nmapVersion string
	if !config.SkipNmap {
		nmapConfig := &nmap.NmapConfig{
			BinaryPath:    config.NmapPath,
			Timing:        config.NmapTiming,
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
		nmapRunner = nmap.NewNmapRunner(nmapConfig)

		if nmapRunner.IsAvailable() {
			nmapVersion, _ = nmapRunner.GetVersion()
			fmt.Printf("[*] Nmap available: %s\n", nmapVersion)
		} else {
			fmt.Println("[!] Nmap not found, skipping Nmap scans")
			nmapRunner = nil
		}
	}

	fp := fingerprint.NewFingerprinter(config.Timeout)

	authConfig := &auth.AuthConfig{
		Timeout:           config.Timeout,
		MaxAttempts:       config.MaxAuthAttempts,
		DelayBetweenTries: 500 * time.Millisecond,
		BruteForce:        config.BruteForce,
		WordlistUser:      config.WordlistUser,
		WordlistPass:      config.WordlistPass,
		AuthCredential:    nil,
	}
	if config.AuthUser != "" {
		authConfig.AuthCredential = &auth.Credential{
			Username: config.AuthUser,
			Password: config.AuthPass,
			Database: config.AuthDB,
		}
	}
	authChecker := auth.NewAuthChecker(authConfig)
	configChecker := configcheck.NewConfigChecker(config.Timeout)

	reportBuilder := report.NewReportBuilder()

	hosts := make([]string, len(targetList))
	for i, t := range targetList {
		hosts[i] = t.Host
	}

	fmt.Println("[*] Starting port scan...")

	allResults := portScanner.ScanHosts(ctx, hosts, ports)

	openServices := make([]scanner.ScanResult, 0)
	for host, results := range allResults {
		openPorts := portScanner.GetOpenPorts(results)
		if config.Verbose && len(openPorts) > 0 {
			fmt.Printf("[+] %s: %d open port(s)\n", host, len(openPorts))
		}
		openServices = append(openServices, openPorts...)
	}

	if len(openServices) == 0 {
		fmt.Println("[*] No open database ports found")
		return nil
	}

	fmt.Printf("[*] Found %d open port(s), analyzing services...\n", len(openServices))

	var wg sync.WaitGroup
	resultChan := make(chan struct {
		ScanResult   scanner.ScanResult
		FPResult     *fingerprint.ServiceInfo
		NmapResult   *nmap.NmapResult
		AuthResult   *auth.AuthResult
		ConfigResult *configcheck.ConfigResult
	}, len(openServices))

	semaphore := make(chan struct{}, config.MaxConcurrency)

	for _, svc := range openServices {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(s scanner.ScanResult) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := struct {
				ScanResult   scanner.ScanResult
				FPResult     *fingerprint.ServiceInfo
				NmapResult   *nmap.NmapResult
				AuthResult   *auth.AuthResult
				ConfigResult *configcheck.ConfigResult
			}{
				ScanResult: s,
			}

			if config.Verbose {
				fmt.Printf("[*] Analyzing %s:%d (%s)...\n", s.Host, s.Port, s.Service)
			}

			fpResult, err := fp.Fingerprint(ctx, s.Host, s.Port, s.Service)
			if err == nil {
				result.FPResult = fpResult
				if fpResult.ServiceType != "" {
					s.Service = fpResult.ServiceType
				}
			}

			if nmapRunner != nil {
				nmapResult, err := nmapRunner.RunFullScan(ctx, s.Host, s.Port, s.Service)
				if err == nil {
					result.NmapResult = nmapResult
				}
			}

			if !config.SkipAuth {
				authResult := authChecker.CheckAuth(ctx, s.Host, s.Port, s.Service)
				result.AuthResult = authResult
			}

			if !config.SkipConfig {
				configResult := configChecker.Check(ctx, s.Host, s.Port, s.Service, nil)
				result.ConfigResult = configResult
			}

			resultChan <- result
		}(svc)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		reportBuilder.AddService(
			result.ScanResult,
			result.FPResult,
			result.NmapResult,
			result.AuthResult,
			result.ConfigResult,
		)
	}

	reportBuilder.SetScanInfo(hosts, ports, config.Profile, time.Since(startTime), nmapVersion)
	scanReport := reportBuilder.Build()

	var output *os.File
	if config.OutputFile != "" {
		var err error
		output, err = os.Create(config.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	fmt.Println("\n[*] Generating report...")

	switch config.OutputFormat {
	case "json":
		if err := scanReport.WriteJSON(output); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
	case "pdf":
		if err := scanReport.WritePDF(output); err != nil {
			return fmt.Errorf("failed to write PDF report: %w", err)
		}
	default:
		if err := scanReport.WriteText(output); err != nil {
			return fmt.Errorf("failed to write text report: %w", err)
		}
	}

	if config.OutputFile != "" {
		fmt.Printf("[*] Report saved to: %s\n", config.OutputFile)
	}

	fmt.Printf("[*] Scan completed in %s\n", time.Since(startTime).Round(time.Second))

	return nil
}

func getPortsForProfile(profile string) []int {
	switch profile {
	case "fast":
		return targets.GetMinimalDBPorts()
	case "thorough":
		return targets.GetDefaultDBPorts()
	default:
		return targets.GetDefaultDBPorts()
	}
}

func getRateLimitForProfile(profile string) time.Duration {
	switch profile {
	case "fast":
		return 5 * time.Millisecond
	case "thorough":
		return 20 * time.Millisecond
	default:
		return 10 * time.Millisecond
	}
}
