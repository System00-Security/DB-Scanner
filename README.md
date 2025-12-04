# Database Exposure Scanner

A non-destructive, production-ready database exposure scanner written in Go. This tool automatically discovers and assesses database services on target hosts, focusing on exposure, misconfiguration, weak authentication, and known vulnerabilities.

**This tool is intended only for authorized security assessments of servers/databases you are permitted to test.**

## Features

- **Target Discovery**: Support for single hosts, host lists, and CIDR ranges
- **Port Scanning**: Scans common database ports with customizable port ranges
- **Service Fingerprinting**: Protocol-specific handshakes for MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Oracle, Cassandra, Elasticsearch, Memcached
- **Version Detection**: Banner grabbing and protocol enumeration
- **Nmap Integration**: Service detection and safe NSE scripts (excludes brute, dos, exploit, intrusive)
- **Authentication Checks**: Anonymous access detection and limited default credential testing
- **Configuration Auditing**: Database-specific dangerous configuration detection
- **TLS/SSL Assessment**: Certificate validation, protocol version checks
- **Vulnerability Mapping**: EOL version detection, known CVE mapping
- **Risk Scoring**: Automatic risk level calculation with remediation recommendations

## Safety Features

- Strictly non-destructive operations
- Limited credential attempts (max 10 per service)
- No brute force or password spraying
- No DoS or stress testing
- Read-only metadata queries only
- Configurable rate limiting
- Safe Nmap script categories only

## Installation

### Prerequisites

- Go 1.21 or later
- Nmap (optional, for enhanced scanning)

### Build from Source

```bash
cd /home/maheer/Dbscanner
go mod tidy
go build -o dbscanner ./cmd/dbscanner
```

### Install Dependencies

```bash
go mod download
```

## Usage

### Basic Usage

```bash
# Scan a single host
./dbscanner -t 192.168.1.100

# Scan multiple hosts
./dbscanner -t 192.168.1.100,192.168.1.101,192.168.1.102

# Scan a CIDR range
./dbscanner -t 10.0.0.0/24

# Scan hosts from a file
./dbscanner -iL hosts.txt
```

### Advanced Usage

```bash
# Thorough scan with custom ports
./dbscanner -t 192.168.1.0/24 -profile thorough -p 3306,5432,27017,6379

# Quick scan with JSON output
./dbscanner -t 10.0.0.1 -profile fast -format json -o report.json

# Verbose scan with custom timeout
./dbscanner -t target.example.com -v -timeout 10s

# Skip certain checks
./dbscanner -t 192.168.1.100 -skip-auth -skip-nmap
```

### Command-Line Options

```
Options:
  -target, -t          Target host(s): IP, hostname, CIDR, or comma-separated list
  -target-file, -iL    File containing targets (one per line)
  -ports, -p           Ports to scan (e.g., '3306,5432' or '1-1000')
  -profile             Scan profile: fast, default, thorough
  -output, -o          Output file path
  -format              Output format: text, json
  -timeout             Connection timeout (default: 5s)
  -concurrency         Maximum concurrent scans (default: 50)
  -nmap-path           Path to nmap binary (default: nmap)
  -nmap-timing         Nmap timing template 0-5 (default: 3)
  -skip-nmap           Skip Nmap scanning
  -skip-auth           Skip authentication checks
  -skip-config         Skip configuration checks
  -verbose, -v         Verbose output
```

### Scan Profiles

| Profile   | Description                                  | Ports        | Rate Limit |
|-----------|----------------------------------------------|--------------|------------|
| fast      | Quick scan with minimal ports and checks     | 6 ports      | 5ms        |
| default   | Standard scan with common DB ports           | 35+ ports    | 10ms       |
| thorough  | Full scan with all ports and deep checks     | 35+ ports    | 20ms       |

## Supported Databases

| Database      | Default Ports | Auth Check | Config Check | Fingerprint |
|---------------|---------------|------------|--------------|-------------|
| MySQL         | 3306, 3307    | Yes        | Yes          | Yes         |
| MariaDB       | 3306, 3307    | Yes        | Yes          | Yes         |
| PostgreSQL    | 5432, 5433    | Yes        | Yes          | Yes         |
| Microsoft SQL | 1433, 1434    | Yes        | Yes          | Yes         |
| MongoDB       | 27017-27019   | Yes        | Yes          | Yes         |
| Redis         | 6379, 6380    | Yes        | Yes          | Yes         |
| Oracle        | 1521, 1522    | Limited    | Limited      | Yes         |
| Cassandra     | 9042, 9160    | Limited    | No           | Yes         |
| Elasticsearch | 9200, 9300    | Yes        | No           | Yes         |
| Memcached     | 11211         | Yes        | No           | Yes         |
| CouchDB       | 5984, 6984    | Limited    | No           | No          |
| Neo4j         | 7474, 7687    | No         | No           | No          |
| ArangoDB      | 8529          | No         | No           | No          |
| RethinkDB     | 28015, 29015  | No         | No           | No          |

## Output

### Text Report

The text report includes:
- Scan information (targets, ports, duration)
- Summary of findings by severity
- Per-service details:
  - Identification (host, port, service type)
  - Version and transport security
  - Authentication results
  - Configuration issues
  - Vulnerabilities and CVEs
  - Risk assessment and recommendations

### JSON Report

Structured JSON output suitable for integration with other tools and systems.

## Security Checks

### Authentication Checks

- Anonymous/no-auth access detection
- Default credential testing (limited, curated list)
- Privilege level assessment
- Read-only metadata queries

### Configuration Checks

| Database   | Checks                                           |
|------------|--------------------------------------------------|
| MySQL      | local_infile, remote root, empty passwords       |
| PostgreSQL | SSL config, superuser count, log settings        |
| MSSQL      | xp_cmdshell, OLE automation, CLR, remote admin   |
| MongoDB    | Authentication enabled                           |
| Redis      | requirepass, protected-mode, bind address        |

### TLS/SSL Checks

- TLS support detection
- Protocol version validation (flags TLS 1.0/1.1)
- Certificate expiry
- Self-signed certificate detection
- Cipher suite analysis

### Vulnerability Checks

- End-of-life version detection
- Known vulnerable version mapping
- Nmap NSE vulnerability scripts
- CVE extraction from scan results

## Risk Levels

| Level    | Criteria                                                    |
|----------|-------------------------------------------------------------|
| Critical | No auth, default creds with high privileges, remote code exec |
| High     | Weak auth, unencrypted, public exposure, EOL versions        |
| Medium   | Self-signed certs, weak protocols, risky configurations      |
| Low      | Minor misconfigurations, informational findings              |

## Project Structure

```
Dbscanner/
├── cmd/
│   └── dbscanner/
│       └── main.go           # CLI entry point
├── pkg/
│   ├── targets/
│   │   └── targets.go        # Target parsing and expansion
│   ├── scanner/
│   │   └── scanner.go        # Port scanning and service detection
│   ├── fingerprint/
│   │   └── fingerprint.go    # Protocol fingerprinting
│   ├── nmap/
│   │   ├── nmap.go           # Nmap integration
│   │   └── vulndb.go         # Vulnerability database
│   ├── auth/
│   │   ├── auth.go           # Authentication checking
│   │   └── drivers.go        # Database driver implementations
│   ├── configcheck/
│   │   └── configcheck.go    # Configuration auditing
│   └── report/
│       └── report.go         # Report generation
├── go.mod
└── README.md
```

## Disclaimer

This tool is provided for authorized security testing and assessment purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors assume no liability for misuse or damage caused by this tool.

## License

MIT License
