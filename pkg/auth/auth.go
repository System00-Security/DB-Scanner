package auth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type AuthResult struct {
	ServiceType         string
	Host                string
	Port                int
	AnonymousAccess     bool
	AuthRequired        bool
	SuccessfulLogin     bool
	Credential          *Credential
	PrivilegeLevel      string
	Metadata            map[string]string
	VerificationSQL     string
	Error               string
	AttemptsMade        int
	MaxAttempts         int
	ErrorAnalysis       *ErrorAnalysis
	ProtocolIssues      []ProtocolIssue
	SecondaryServices   []SecondaryService
}

type ErrorAnalysis struct {
	LeaksUserExists      bool
	LeaksPasswordWrong   bool
	LeaksAuthCodes       bool
	CleartextEnabled     bool
	SpecificErrors       []string
	ErrorPatterns        map[string]string
}

type ProtocolIssue struct {
	Protocol     string
	Issue        string
	Risk         string
	Description  string
	Remediation  string
}

type SecondaryService struct {
	Name         string
	Host         string
	Port         int
	Type         string
	Accessible   bool
	AuthRequired bool
	Description  string
	Risk         string
}

type Credential struct {
	Username  string
	Password  string
	Obfuscate bool
}

func (c *Credential) String() string {
	if c.Obfuscate {
		passLen := len(c.Password)
		if passLen == 0 {
			return fmt.Sprintf("%s:<empty>", c.Username)
		}
		return fmt.Sprintf("%s:***(%d chars)", c.Username, passLen)
	}
	return fmt.Sprintf("%s:%s", c.Username, c.Password)
}

type AuthConfig struct {
	Timeout           time.Duration
	MaxAttempts       int
	DelayBetweenTries time.Duration
}

func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Timeout:           5 * time.Second,
		MaxAttempts:       10,
		DelayBetweenTries: 500 * time.Millisecond,
	}
}

type AuthChecker struct {
	config      *AuthConfig
	credentials map[string][]Credential
}

func NewAuthChecker(config *AuthConfig) *AuthChecker {
	if config == nil {
		config = DefaultAuthConfig()
	}
	ac := &AuthChecker{
		config:      config,
		credentials: make(map[string][]Credential),
	}
	ac.loadDefaultCredentials()
	return ac
}

func (ac *AuthChecker) loadDefaultCredentials() {
	ac.credentials["mysql"] = []Credential{
		{Username: "root", Password: "", Obfuscate: true},
		{Username: "root", Password: "root", Obfuscate: true},
		{Username: "root", Password: "mysql", Obfuscate: true},
		{Username: "root", Password: "password", Obfuscate: true},
		{Username: "mysql", Password: "mysql", Obfuscate: true},
		{Username: "admin", Password: "admin", Obfuscate: true},
	}

	ac.credentials["mariadb"] = ac.credentials["mysql"]

	ac.credentials["postgresql"] = []Credential{
		{Username: "postgres", Password: "", Obfuscate: true},
		{Username: "postgres", Password: "postgres", Obfuscate: true},
		{Username: "postgres", Password: "password", Obfuscate: true},
		{Username: "admin", Password: "admin", Obfuscate: true},
		{Username: "pgsql", Password: "pgsql", Obfuscate: true},
	}

	ac.credentials["mssql"] = []Credential{
		{Username: "sa", Password: "", Obfuscate: true},
		{Username: "sa", Password: "sa", Obfuscate: true},
		{Username: "sa", Password: "password", Obfuscate: true},
		{Username: "sa", Password: "Password1", Obfuscate: true},
		{Username: "admin", Password: "admin", Obfuscate: true},
	}

	ac.credentials["mongodb"] = []Credential{
		{Username: "", Password: "", Obfuscate: true},
		{Username: "admin", Password: "admin", Obfuscate: true},
		{Username: "root", Password: "root", Obfuscate: true},
		{Username: "mongodb", Password: "mongodb", Obfuscate: true},
	}

	ac.credentials["redis"] = []Credential{
		{Username: "", Password: "", Obfuscate: true},
		{Username: "", Password: "redis", Obfuscate: true},
		{Username: "", Password: "password", Obfuscate: true},
		{Username: "", Password: "admin", Obfuscate: true},
	}

	ac.credentials["oracle"] = []Credential{
		{Username: "system", Password: "manager", Obfuscate: true},
		{Username: "system", Password: "oracle", Obfuscate: true},
		{Username: "sys", Password: "change_on_install", Obfuscate: true},
		{Username: "scott", Password: "tiger", Obfuscate: true},
	}

	ac.credentials["cassandra"] = []Credential{
		{Username: "cassandra", Password: "cassandra", Obfuscate: true},
	}

	ac.credentials["elasticsearch"] = []Credential{
		{Username: "", Password: "", Obfuscate: true},
		{Username: "elastic", Password: "changeme", Obfuscate: true},
		{Username: "elastic", Password: "elastic", Obfuscate: true},
	}

	ac.credentials["memcached"] = []Credential{
		{Username: "", Password: "", Obfuscate: true},
	}

	ac.credentials["couchdb"] = []Credential{
		{Username: "admin", Password: "admin", Obfuscate: true},
		{Username: "admin", Password: "password", Obfuscate: true},
	}
}

func (ac *AuthChecker) CheckAuth(ctx context.Context, host string, port int, service string) *AuthResult {
	result := &AuthResult{
		ServiceType:       service,
		Host:              host,
		Port:              port,
		Metadata:          make(map[string]string),
		MaxAttempts:       ac.config.MaxAttempts,
		ErrorAnalysis:     &ErrorAnalysis{
			ErrorPatterns: make(map[string]string),
		},
		ProtocolIssues:    make([]ProtocolIssue, 0),
		SecondaryServices: make([]SecondaryService, 0),
	}

	ac.checkSecondaryServices(ctx, host, port, service, result)

	switch strings.ToLower(service) {
	case "mysql", "mariadb":
		ac.checkMySQLAuth(ctx, result)
		ac.checkMySQLProtocolIssues(ctx, result)
	case "postgresql", "postgres":
		ac.checkPostgreSQLAuth(ctx, result)
		ac.checkPostgreSQLProtocolIssues(ctx, result)
	case "mssql":
		ac.checkMSSQLAuth(ctx, result)
	case "mongodb":
		ac.checkMongoDBAuth(ctx, result)
		ac.checkMongoDBProtocolIssues(ctx, result)
	case "redis":
		ac.checkRedisAuth(ctx, result)
		ac.checkRedisProtocolIssues(ctx, result)
	case "oracle":
		ac.checkOracleAuth(ctx, result)
	case "cassandra":
		ac.checkCassandraAuth(ctx, result)
	case "elasticsearch":
		ac.checkElasticsearchAuth(ctx, result)
	case "memcached":
		ac.checkMemcachedAuth(ctx, result)
	default:
		result.Error = fmt.Sprintf("unsupported service type: %s", service)
	}

	return result
}

func (ac *AuthChecker) checkMySQLAuth(ctx context.Context, result *AuthResult) {
	creds := ac.credentials["mysql"]
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)

	for i, cred := range creds {
		if i >= ac.config.MaxAttempts {
			break
		}
		result.AttemptsMade++

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return
		default:
		}

		success, privLevel, metadata, err := tryMySQLConnection(addr, cred.Username, cred.Password, ac.config.Timeout)
		if err != nil {
			if strings.Contains(err.Error(), "Access denied") {
				result.AuthRequired = true
				continue
			}
		}

		if success {
			result.SuccessfulLogin = true
			result.Credential = &Credential{
				Username:  cred.Username,
				Password:  cred.Password,
				Obfuscate: true,
			}
			result.PrivilegeLevel = privLevel
			for k, v := range metadata {
				result.Metadata[k] = v
			}

			if cred.Username == "" && cred.Password == "" {
				result.AnonymousAccess = true
			}

			return
		}

		time.Sleep(ac.config.DelayBetweenTries)
	}

	result.AuthRequired = true
}

func tryMySQLConnection(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
	metadata := make(map[string]string)
	return false, "", metadata, fmt.Errorf("mysql driver not available - use go-sql-driver/mysql")
}

func (ac *AuthChecker) checkPostgreSQLAuth(ctx context.Context, result *AuthResult) {
	creds := ac.credentials["postgresql"]
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)

	for i, cred := range creds {
		if i >= ac.config.MaxAttempts {
			break
		}
		result.AttemptsMade++

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return
		default:
		}

		success, privLevel, metadata, err := tryPostgreSQLConnection(addr, cred.Username, cred.Password, ac.config.Timeout)
		if err != nil {
			if strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), "password") {
				result.AuthRequired = true
				continue
			}
		}

		if success {
			result.SuccessfulLogin = true
			result.Credential = &Credential{
				Username:  cred.Username,
				Password:  cred.Password,
				Obfuscate: true,
			}
			result.PrivilegeLevel = privLevel
			for k, v := range metadata {
				result.Metadata[k] = v
			}

			if cred.Password == "" {
				result.AnonymousAccess = true
			}

			return
		}

		time.Sleep(ac.config.DelayBetweenTries)
	}

	result.AuthRequired = true
}

func tryPostgreSQLConnection(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
	metadata := make(map[string]string)
	return false, "", metadata, fmt.Errorf("postgresql driver not available - use lib/pq")
}

func (ac *AuthChecker) checkMSSQLAuth(ctx context.Context, result *AuthResult) {
	creds := ac.credentials["mssql"]
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)

	for i, cred := range creds {
		if i >= ac.config.MaxAttempts {
			break
		}
		result.AttemptsMade++

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return
		default:
		}

		success, privLevel, metadata, err := tryMSSQLConnection(addr, cred.Username, cred.Password, ac.config.Timeout)
		if err != nil {
			if strings.Contains(err.Error(), "Login failed") {
				result.AuthRequired = true
				continue
			}
		}

		if success {
			result.SuccessfulLogin = true
			result.Credential = &Credential{
				Username:  cred.Username,
				Password:  cred.Password,
				Obfuscate: true,
			}
			result.PrivilegeLevel = privLevel
			for k, v := range metadata {
				result.Metadata[k] = v
			}
			return
		}

		time.Sleep(ac.config.DelayBetweenTries)
	}

	result.AuthRequired = true
}

func tryMSSQLConnection(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
	metadata := make(map[string]string)
	return false, "", metadata, fmt.Errorf("mssql driver not available - use go-mssqldb")
}

func (ac *AuthChecker) checkMongoDBAuth(ctx context.Context, result *AuthResult) {
	creds := ac.credentials["mongodb"]

	for i, cred := range creds {
		if i >= ac.config.MaxAttempts {
			break
		}
		result.AttemptsMade++

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return
		default:
		}

		success, privLevel, metadata, err := tryMongoDBConnection(result.Host, result.Port, cred.Username, cred.Password, ac.config.Timeout)
		if err != nil {
			if strings.Contains(err.Error(), "authentication failed") {
				result.AuthRequired = true
				continue
			}
		}

		if success {
			result.SuccessfulLogin = true
			result.Credential = &Credential{
				Username:  cred.Username,
				Password:  cred.Password,
				Obfuscate: true,
			}
			result.PrivilegeLevel = privLevel
			for k, v := range metadata {
				result.Metadata[k] = v
			}

			if cred.Username == "" && cred.Password == "" {
				result.AnonymousAccess = true
			}

			return
		}

		time.Sleep(ac.config.DelayBetweenTries)
	}

	result.AuthRequired = true
}

func tryMongoDBConnection(host string, port int, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
	metadata := make(map[string]string)
	return false, "", metadata, fmt.Errorf("mongodb driver not available - use mongo-driver")
}

func (ac *AuthChecker) checkRedisAuth(ctx context.Context, result *AuthResult) {
	creds := ac.credentials["redis"]

	for i, cred := range creds {
		if i >= ac.config.MaxAttempts {
			break
		}
		result.AttemptsMade++

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return
		default:
		}

		success, privLevel, metadata, err := tryRedisConnection(result.Host, result.Port, cred.Password, ac.config.Timeout)
		if err != nil {
			if strings.Contains(err.Error(), "NOAUTH") || strings.Contains(err.Error(), "AUTH") {
				result.AuthRequired = true
				continue
			}
		}

		if success {
			result.SuccessfulLogin = true
			result.Credential = &Credential{
				Username:  "",
				Password:  cred.Password,
				Obfuscate: true,
			}
			result.PrivilegeLevel = privLevel
			for k, v := range metadata {
				result.Metadata[k] = v
			}

			if cred.Password == "" {
				result.AnonymousAccess = true
			}

			return
		}

		time.Sleep(ac.config.DelayBetweenTries)
	}

	result.AuthRequired = true
}

func tryRedisConnection(host string, port int, password string, timeout time.Duration) (bool, string, map[string]string, error) {
	metadata := make(map[string]string)
	return false, "", metadata, fmt.Errorf("redis driver not available - use go-redis")
}

func (ac *AuthChecker) checkOracleAuth(ctx context.Context, result *AuthResult) {
	result.AuthRequired = true
	result.Error = "Oracle authentication check requires Oracle client libraries"
}

func (ac *AuthChecker) checkCassandraAuth(ctx context.Context, result *AuthResult) {
	result.AuthRequired = true
	result.Error = "Cassandra authentication check requires gocql driver"
}

func (ac *AuthChecker) checkElasticsearchAuth(ctx context.Context, result *AuthResult) {
	creds := ac.credentials["elasticsearch"]

	for i, cred := range creds {
		if i >= ac.config.MaxAttempts {
			break
		}
		result.AttemptsMade++

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return
		default:
		}

		success, privLevel, metadata, err := tryElasticsearchConnection(result.Host, result.Port, cred.Username, cred.Password, ac.config.Timeout)
		if err != nil {
			if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
				result.AuthRequired = true
				continue
			}
		}

		if success {
			result.SuccessfulLogin = true
			result.Credential = &Credential{
				Username:  cred.Username,
				Password:  cred.Password,
				Obfuscate: true,
			}
			result.PrivilegeLevel = privLevel
			for k, v := range metadata {
				result.Metadata[k] = v
			}

			if cred.Username == "" && cred.Password == "" {
				result.AnonymousAccess = true
			}

			return
		}

		time.Sleep(ac.config.DelayBetweenTries)
	}

	result.AuthRequired = true
}

func tryElasticsearchConnection(host string, port int, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
	metadata := make(map[string]string)
	return false, "", metadata, fmt.Errorf("elasticsearch check not implemented")
}

func (ac *AuthChecker) checkMemcachedAuth(ctx context.Context, result *AuthResult) {
	success, metadata, err := tryMemcachedConnection(result.Host, result.Port, ac.config.Timeout)
	result.AttemptsMade = 1

	if err != nil {
		result.Error = err.Error()
		return
	}

	if success {
		result.AnonymousAccess = true
		result.SuccessfulLogin = true
		result.PrivilegeLevel = "full"
		for k, v := range metadata {
			result.Metadata[k] = v
		}
	}
}

func tryMemcachedConnection(host string, port int, timeout time.Duration) (bool, map[string]string, error) {
	metadata := make(map[string]string)
	return false, metadata, fmt.Errorf("memcached check not implemented")
}

func (ac *AuthChecker) checkSecondaryServices(ctx context.Context, host string, port int, service string, result *AuthResult) {
	secondaryPorts := getSecondaryPorts(service, port)

	for _, sp := range secondaryPorts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		accessible, authRequired := ac.probeSecondaryService(host, sp.Port, sp.Type, ac.config.Timeout)
		if accessible {
			riskLevel := "Medium"
			if !authRequired {
				riskLevel = "High"
			}
			result.SecondaryServices = append(result.SecondaryServices, SecondaryService{
				Name:         sp.Name,
				Host:         host,
				Port:         sp.Port,
				Type:         sp.Type,
				Accessible:   true,
				AuthRequired: authRequired,
				Description:  fmt.Sprintf("%s service", sp.Name),
				Risk:         riskLevel,
			})
		}
	}
}

type secondaryPortInfo struct {
	Name string
	Port int
	Type string
}

func getSecondaryPorts(service string, primaryPort int) []secondaryPortInfo {
	ports := make([]secondaryPortInfo, 0)

	switch strings.ToLower(service) {
	case "mysql", "mariadb":
		ports = append(ports,
			secondaryPortInfo{"MySQL X Protocol", 33060, "admin"},
			secondaryPortInfo{"MySQL Admin", 33062, "admin"},
			secondaryPortInfo{"MySQL Router RW", 6446, "proxy"},
			secondaryPortInfo{"MySQL Router RO", 6447, "proxy"},
			secondaryPortInfo{"MySQL Group Replication", 33061, "replication"},
		)
	case "postgresql", "postgres":
		ports = append(ports,
			secondaryPortInfo{"PgBouncer", 6432, "proxy"},
			secondaryPortInfo{"Pgpool-II", 9999, "proxy"},
			secondaryPortInfo{"Patroni REST API", 8008, "cluster"},
			secondaryPortInfo{"PostgreSQL Metrics", 9187, "metrics"},
		)
	case "mongodb":
		ports = append(ports,
			secondaryPortInfo{"MongoDB Shard", 27018, "replication"},
			secondaryPortInfo{"MongoDB Config", 27019, "cluster"},
			secondaryPortInfo{"MongoDB Web Status", 28017, "admin"},
		)
	case "redis":
		ports = append(ports,
			secondaryPortInfo{"Redis Sentinel", 26379, "cluster"},
			secondaryPortInfo{"Redis Cluster Bus", primaryPort+10000, "cluster"},
		)
	case "mssql":
		ports = append(ports,
			secondaryPortInfo{"SQL Browser", 1434, "discovery"},
			secondaryPortInfo{"SQL DAC", 1434, "admin"},
			secondaryPortInfo{"SSRS", 80, "reporting"},
			secondaryPortInfo{"SSAS", 2383, "analysis"},
		)
	case "oracle":
		ports = append(ports,
			secondaryPortInfo{"Oracle EM Express", 5500, "admin"},
			secondaryPortInfo{"Oracle XDB HTTP", 8080, "admin"},
			secondaryPortInfo{"Oracle XDB FTP", 2100, "admin"},
		)
	case "elasticsearch":
		ports = append(ports,
			secondaryPortInfo{"ES Transport", 9300, "cluster"},
			secondaryPortInfo{"Kibana", 5601, "admin"},
		)
	case "cassandra":
		ports = append(ports,
			secondaryPortInfo{"Cassandra JMX", 7199, "admin"},
			secondaryPortInfo{"Cassandra Inter-node", 7000, "cluster"},
			secondaryPortInfo{"Cassandra SSL Inter-node", 7001, "cluster"},
		)
	}

	return ports
}

func (ac *AuthChecker) probeSecondaryService(host string, port int, serviceType string, timeout time.Duration) (bool, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	authRequired := true

	switch serviceType {
	case "admin", "metrics":
		conn.SetWriteDeadline(time.Now().Add(timeout))
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			response := string(buf[:n])
			if strings.Contains(response, "200 OK") && !strings.Contains(response, "401") && !strings.Contains(response, "403") {
				authRequired = false
			}
		}
	case "cluster", "replication":
		authRequired = true
	}

	return true, authRequired
}

func AnalyzeAuthError(service, errorMsg string, result *AuthResult) {
	errorLower := strings.ToLower(errorMsg)

	userExistsPatterns := map[string][]string{
		"mysql": {
			"access denied for user",
			"using password: yes",
			"using password: no",
		},
		"postgresql": {
			"password authentication failed for user",
			"no pg_hba.conf entry for",
		},
		"mssql": {
			"login failed for user",
			"password did not match",
		},
		"mongodb": {
			"authentication failed",
			"auth failed",
		},
		"oracle": {
			"ora-01017",
			"invalid username/password",
		},
	}

	userNotFoundPatterns := map[string][]string{
		"mysql": {
			"unknown user",
		},
		"postgresql": {
			"role .* does not exist",
			"no such user",
		},
		"mssql": {
			"cannot open database",
			"login failed",
		},
		"oracle": {
			"ora-01017",
		},
	}

	for svc, patterns := range userExistsPatterns {
		if strings.Contains(strings.ToLower(service), svc) {
			for _, pattern := range patterns {
				if strings.Contains(errorLower, pattern) {
					result.ErrorAnalysis.LeaksUserExists = true
					result.ErrorAnalysis.SpecificErrors = append(result.ErrorAnalysis.SpecificErrors,
						fmt.Sprintf("Error message indicates whether user exists: %s", pattern))
				}
			}
		}
	}

	for svc, patterns := range userNotFoundPatterns {
		if strings.Contains(strings.ToLower(service), svc) {
			for _, pattern := range patterns {
				if strings.Contains(errorLower, pattern) {
					result.ErrorAnalysis.LeaksPasswordWrong = true
					result.ErrorAnalysis.SpecificErrors = append(result.ErrorAnalysis.SpecificErrors,
						fmt.Sprintf("Error distinguishes user not found vs wrong password: %s", pattern))
				}
			}
		}
	}

	authCodePatterns := []string{
		"error code",
		"errno",
		"sqlstate",
		"ora-",
		"#",
	}

	for _, pattern := range authCodePatterns {
		if strings.Contains(errorLower, pattern) {
			result.ErrorAnalysis.LeaksAuthCodes = true
			result.ErrorAnalysis.ErrorPatterns[pattern] = errorMsg
		}
	}
}

func (ac *AuthChecker) checkMySQLProtocolIssues(ctx context.Context, result *AuthResult) {
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)
	conn, err := net.DialTimeout("tcp", addr, ac.config.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n < 5 {
		return
	}

	if n > 4 {
		protocolVersion := buffer[4]

		if protocolVersion == 9 {
			result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
				Protocol:    "MySQL Protocol v9",
				Issue:       "old_password_protocol",
				Risk:        "Critical",
				Description: "MySQL is using the deprecated old password protocol (protocol version 9) which is cryptographically weak",
				Remediation: "Upgrade MySQL and set old_passwords=0, use mysql_native_password or caching_sha2_password",
			})
		}

		if n > 32 {
			nullPos := 5
			for nullPos < n && buffer[nullPos] != 0 {
				nullPos++
			}

			if nullPos+30 < n {
				capOffset := nullPos + 1 + 4 + 8 + 1
				if capOffset+2 <= n {
					capFlags := uint16(buffer[capOffset]) | uint16(buffer[capOffset+1])<<8

					if capFlags&0x0800 == 0 {
						result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
							Protocol:    "MySQL",
							Issue:       "ssl_not_supported",
							Risk:        "High",
							Description: "MySQL server does not support SSL/TLS connections",
							Remediation: "Enable SSL in MySQL configuration with ssl-ca, ssl-cert, ssl-key options",
						})
						result.ErrorAnalysis.CleartextEnabled = true
					}

					if capFlags&0x0001 != 0 {
						result.Metadata["long_password_support"] = "true"
					}

					extCapOffset := capOffset + 2 + 1 + 2 + 2 + 1 + 10
					if extCapOffset+4 <= n {
						extCaps := uint32(buffer[extCapOffset]) | uint32(buffer[extCapOffset+1])<<8 |
							uint32(buffer[extCapOffset+2])<<16 | uint32(buffer[extCapOffset+3])<<24

						if extCaps&0x00200000 == 0 {
							result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
								Protocol:    "MySQL",
								Issue:       "deprecated_auth_plugin",
								Risk:        "Medium",
								Description: "Server may be using deprecated mysql_old_password authentication",
								Remediation: "Use mysql_native_password or caching_sha2_password authentication plugin",
							})
						}
					}
				}
			}
		}
	}

	versionStr := result.Metadata["version"]
	if strings.Contains(versionStr, "4.0") || strings.Contains(versionStr, "4.1") {
		result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
			Protocol:    "MySQL",
			Issue:       "ancient_version",
			Risk:        "Critical",
			Description: "MySQL 4.x uses weak password hashing and has numerous security vulnerabilities",
			Remediation: "Upgrade to MySQL 5.7+ or 8.0+",
		})
	}
}

func (ac *AuthChecker) checkPostgreSQLProtocolIssues(ctx context.Context, result *AuthResult) {
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)
	conn, err := net.DialTimeout("tcp", addr, ac.config.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	sslRequest := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	conn.SetWriteDeadline(time.Now().Add(ac.config.Timeout))
	_, err = conn.Write(sslRequest)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
	response := make([]byte, 1)
	_, err = conn.Read(response)
	if err != nil {
		return
	}

	if response[0] == 'N' {
		result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
			Protocol:    "PostgreSQL",
			Issue:       "ssl_disabled",
			Risk:        "High",
			Description: "PostgreSQL server has SSL disabled - all connections are unencrypted",
			Remediation: "Enable SSL in postgresql.conf: ssl = on, and configure ssl_cert_file, ssl_key_file",
		})
		result.ErrorAnalysis.CleartextEnabled = true
	}

	if result.Metadata["password_encryption"] == "md5" {
		result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
			Protocol:    "PostgreSQL",
			Issue:       "weak_password_hash",
			Risk:        "Medium",
			Description: "PostgreSQL is using MD5 password hashing which is considered weak",
			Remediation: "Set password_encryption = 'scram-sha-256' in postgresql.conf",
		})
	}

	if result.Metadata["ssl_required"] == "false" {
		result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
			Protocol:    "PostgreSQL",
			Issue:       "ssl_not_required",
			Risk:        "Medium",
			Description: "PostgreSQL allows non-SSL connections even though SSL is available",
			Remediation: "Configure pg_hba.conf to require hostssl for remote connections",
		})
	}
}

func (ac *AuthChecker) checkMongoDBProtocolIssues(ctx context.Context, result *AuthResult) {
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)
	conn, err := net.DialTimeout("tcp", addr, ac.config.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	isMasterCmd := buildMongoGetCmdLineOpts()
	conn.SetWriteDeadline(time.Now().Add(ac.config.Timeout))
	_, err = conn.Write(isMasterCmd)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])

	if !strings.Contains(response, "unauthorized") {
		if strings.Contains(response, "authenticationMechanisms") {
			if strings.Contains(response, "MONGODB-CR") {
				result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
					Protocol:    "MongoDB",
					Issue:       "mongodb_cr_enabled",
					Risk:        "High",
					Description: "MongoDB-CR authentication mechanism is enabled - this is deprecated and weak",
					Remediation: "Disable MONGODB-CR and use SCRAM-SHA-256: setParameter authenticationMechanisms: ['SCRAM-SHA-256']",
				})
			}

			if !strings.Contains(response, "SCRAM-SHA-256") && !strings.Contains(response, "SCRAM-SHA-1") {
				result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
					Protocol:    "MongoDB",
					Issue:       "scram_disabled",
					Risk:        "Critical",
					Description: "SCRAM authentication is disabled - MongoDB may be using weak or no authentication",
					Remediation: "Enable SCRAM-SHA-256 authentication",
				})
			}
		}

		if !strings.Contains(response, "authorization") || strings.Contains(response, "authorization.*disabled") {
			result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
				Protocol:    "MongoDB",
				Issue:       "no_auth_required",
				Risk:        "Critical",
				Description: "MongoDB is running without authentication enabled",
				Remediation: "Enable authentication: security.authorization: enabled in mongod.conf",
			})
		}

		if !strings.Contains(response, "tls") && !strings.Contains(response, "ssl") {
			result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
				Protocol:    "MongoDB",
				Issue:       "tls_disabled",
				Risk:        "High",
				Description: "MongoDB TLS/SSL is not enabled - connections are unencrypted",
				Remediation: "Enable TLS: net.tls.mode: requireTLS in mongod.conf",
			})
			result.ErrorAnalysis.CleartextEnabled = true
		}
	}
}

func buildMongoGetCmdLineOpts() []byte {
	document := []byte{
		0x21, 0x00, 0x00, 0x00,
		0x02,
		0x67, 0x65, 0x74, 0x43, 0x6d, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x4f, 0x70, 0x74, 0x73, 0x00,
		0x02, 0x00, 0x00, 0x00,
		0x31, 0x00,
		0x00,
	}

	header := make([]byte, 16)
	msgLen := 16 + len(document) + 4 + 15 + 4 + 4
	header[0] = byte(msgLen)
	header[1] = byte(msgLen >> 8)
	header[2] = byte(msgLen >> 16)
	header[3] = byte(msgLen >> 24)
	header[4] = 0x01
	header[5] = 0x00
	header[6] = 0x00
	header[7] = 0x00
	header[8] = 0x00
	header[9] = 0x00
	header[10] = 0x00
	header[11] = 0x00
	header[12] = 0xd4
	header[13] = 0x07
	header[14] = 0x00
	header[15] = 0x00

	var result []byte
	result = append(result, header...)
	result = append(result, 0x00, 0x00, 0x00, 0x00)
	result = append(result, []byte("admin.$cmd")...)
	result = append(result, 0x00)
	result = append(result, 0x00, 0x00, 0x00, 0x00)
	result = append(result, 0x01, 0x00, 0x00, 0x00)
	result = append(result, document...)

	return result
}

func (ac *AuthChecker) checkRedisProtocolIssues(ctx context.Context, result *AuthResult) {
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)
	conn, err := net.DialTimeout("tcp", addr, ac.config.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(ac.config.Timeout))
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])

	if strings.HasPrefix(response, "+PONG") {
		result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
			Protocol:    "Redis",
			Issue:       "no_auth_required",
			Risk:        "Critical",
			Description: "Redis is accessible without authentication (requirepass not set)",
			Remediation: "Set requirepass in redis.conf or use ACL with Redis 6+",
		})

		conn.SetWriteDeadline(time.Now().Add(ac.config.Timeout))
		_, err = conn.Write([]byte("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$12\r\nrequirepass\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
			n, err = conn.Read(buffer)
			if err == nil {
				configResp := string(buffer[:n])
				if !strings.Contains(configResp, "ERR") && strings.Count(configResp, "$") <= 2 {
					result.Metadata["requirepass"] = "not_set"
				}
			}
		}

		conn.SetWriteDeadline(time.Now().Add(ac.config.Timeout))
		_, err = conn.Write([]byte("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$14\r\nprotected-mode\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
			n, err = conn.Read(buffer)
			if err == nil {
				if strings.Contains(string(buffer[:n]), "no") {
					result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
						Protocol:    "Redis",
						Issue:       "protected_mode_disabled",
						Risk:        "Critical",
						Description: "Redis protected-mode is disabled allowing remote unauthenticated access",
						Remediation: "Set protected-mode yes in redis.conf or enable authentication",
					})
				}
			}
		}

		conn.SetWriteDeadline(time.Now().Add(ac.config.Timeout))
		_, err = conn.Write([]byte("*2\r\n$3\r\nACL\r\n$4\r\nLIST\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(ac.config.Timeout))
			n, err = conn.Read(buffer)
			if err == nil {
				aclResp := string(buffer[:n])
				if strings.Contains(aclResp, "ERR") && strings.Contains(aclResp, "unknown command") {
					result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
						Protocol:    "Redis",
						Issue:       "no_acl_support",
						Risk:        "Medium",
						Description: "Redis version does not support ACL (< 6.0) - limited access control",
						Remediation: "Upgrade to Redis 6.0+ for ACL support",
					})
				}
			}
		}
	}

	result.ErrorAnalysis.CleartextEnabled = true
	result.ProtocolIssues = append(result.ProtocolIssues, ProtocolIssue{
		Protocol:    "Redis",
		Issue:       "cleartext_protocol",
		Risk:        "High",
		Description: "Redis RESP protocol is unencrypted by default",
		Remediation: "Enable TLS with tls-port and tls-cert-file options (Redis 6+) or use stunnel",
	})
}
