package configcheck

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"
)

type ConfigResult struct {
	ServiceType       string
	Host              string
	Port              int
	TLSInfo           *TLSInfo
	DangerousSettings []DangerousSetting
	ExposureInfo      *ExposureInfo
	Metadata          map[string]string
	Error             string
}

type TLSInfo struct {
	Supported         bool
	Required          bool
	Version           string
	CipherSuite       string
	CertSubject       string
	CertIssuer        string
	CertExpiry        time.Time
	CertNotBefore     time.Time
	SelfSigned        bool
	Expired           bool
	WeakProtocol      bool
	KeySize           int
	SupportedVersions []string
	CipherSuites      []CipherSuiteInfo
	CertChain         []CertInfo
	OCSP              string
	CertSAN           []string
}

type CipherSuiteInfo struct {
	ID       uint16
	Name     string
	Strength string
	Secure   bool
}

type CertInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	KeyType    string
	KeySize    int
	SelfSigned bool
}

type DangerousSetting struct {
	Name        string
	Value       string
	Risk        string
	Description string
	Remediation string
}

type ExposureInfo struct {
	PubliclyAccessible   bool
	NonStandardPort      bool
	BindAddress          string
	RemoteAccessEnabled  bool
}

type ConfigChecker struct {
	Timeout   time.Duration
	TLSConfig *tls.Config
}

func NewConfigChecker(timeout time.Duration) *ConfigChecker {
	return &ConfigChecker{
		Timeout: timeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionSSL30,
		},
	}
}

func (cc *ConfigChecker) Check(ctx context.Context, host string, port int, service string, db *sql.DB) *ConfigResult {
	result := &ConfigResult{
		ServiceType:       service,
		Host:              host,
		Port:              port,
		DangerousSettings: make([]DangerousSetting, 0),
		Metadata:          make(map[string]string),
	}

	result.ExposureInfo = cc.checkExposure(host, port, service)

	switch strings.ToLower(service) {
	case "mysql", "mariadb":
		cc.checkMySQLConfig(ctx, result, db)
		cc.checkMySQLTLS(ctx, result, host, port)
	case "postgresql", "postgres":
		cc.checkPostgreSQLConfig(ctx, result, db)
		cc.checkPostgreSQLTLS(ctx, result, host, port)
	case "mssql":
		cc.checkMSSQLConfig(ctx, result, db)
	case "mongodb":
		cc.checkMongoDBConfig(ctx, result, host, port)
	case "redis":
		cc.checkRedisConfig(ctx, result, host, port)
	case "oracle":
		cc.checkOracleConfig(ctx, result, db)
	default:
		cc.checkGenericTLS(ctx, result, host, port)
	}

	return result
}

func (cc *ConfigChecker) checkExposure(host string, port int, service string) *ExposureInfo {
	info := &ExposureInfo{}

	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsPrivate() && !ip.IsLoopback() {
			info.PubliclyAccessible = true
		}
	} else {
		addrs, err := net.LookupIP(host)
		if err == nil {
			for _, addr := range addrs {
				if !addr.IsPrivate() && !addr.IsLoopback() {
					info.PubliclyAccessible = true
					break
				}
			}
		}
	}

	standardPorts := map[string][]int{
		"mysql":         {3306},
		"mariadb":       {3306},
		"postgresql":    {5432},
		"postgres":      {5432},
		"mssql":         {1433},
		"mongodb":       {27017},
		"redis":         {6379},
		"oracle":        {1521},
		"cassandra":     {9042},
		"elasticsearch": {9200},
		"memcached":     {11211},
	}

	if ports, ok := standardPorts[strings.ToLower(service)]; ok {
		isStandard := false
		for _, p := range ports {
			if p == port {
				isStandard = true
				break
			}
		}
		info.NonStandardPort = !isStandard
	}

	return info
}

func (cc *ConfigChecker) checkMySQLConfig(ctx context.Context, result *ConfigResult, db *sql.DB) {
	if db == nil {
		return
	}

	dangerousVars := map[string]struct {
		Risk        string
		Description string
		Remediation string
	}{
		"local_infile": {
			Risk:        "High",
			Description: "Allows reading local files through SQL queries, potential data exfiltration",
			Remediation: "SET GLOBAL local_infile = 0",
		},
		"secure_file_priv": {
			Risk:        "Medium",
			Description: "Empty value allows file operations from any directory",
			Remediation: "Set secure_file_priv to a specific directory or NULL",
		},
		"log_raw": {
			Risk:        "Medium",
			Description: "Logs passwords in plain text",
			Remediation: "SET GLOBAL log_raw = OFF",
		},
		"symbolic_links": {
			Risk:        "Medium",
			Description: "Allows symbolic links which can be exploited for file access",
			Remediation: "SET GLOBAL symbolic_links = 0",
		},
		"skip_grant_tables": {
			Risk:        "Critical",
			Description: "Authentication is completely disabled",
			Remediation: "Restart MySQL without --skip-grant-tables",
		},
	}

	rows, err := db.QueryContext(ctx, "SHOW VARIABLES")
	if err != nil {
		result.Error = fmt.Sprintf("failed to query variables: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			continue
		}

		result.Metadata[name] = value

		if info, isDangerous := dangerousVars[name]; isDangerous {
			if name == "local_infile" && (value == "ON" || value == "1") {
				result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
					Name:        name,
					Value:       value,
					Risk:        info.Risk,
					Description: info.Description,
					Remediation: info.Remediation,
				})
			}
			if name == "secure_file_priv" && value == "" {
				result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
					Name:        name,
					Value:       "(empty - unrestricted)",
					Risk:        info.Risk,
					Description: info.Description,
					Remediation: info.Remediation,
				})
			}
			if name == "log_raw" && (value == "ON" || value == "1") {
				result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
					Name:        name,
					Value:       value,
					Risk:        info.Risk,
					Description: info.Description,
					Remediation: info.Remediation,
				})
			}
		}
	}

	var hasRemoteRoot bool
	err = db.QueryRowContext(ctx,
		"SELECT COUNT(*) > 0 FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')").
		Scan(&hasRemoteRoot)
	if err == nil && hasRemoteRoot {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "remote_root_access",
			Value:       "enabled",
			Risk:        "Critical",
			Description: "Root user can connect from remote hosts",
			Remediation: "Remove remote root access: DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')",
		})
	}

	var emptyPassCount int
	err = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM mysql.user WHERE authentication_string = '' OR authentication_string IS NULL").
		Scan(&emptyPassCount)
	if err == nil && emptyPassCount > 0 {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "empty_passwords",
			Value:       fmt.Sprintf("%d users", emptyPassCount),
			Risk:        "Critical",
			Description: "Users with empty passwords exist",
			Remediation: "Set passwords for all users or remove unused accounts",
		})
	}
}

func (cc *ConfigChecker) checkMySQLTLS(ctx context.Context, result *ConfigResult, host string, port int) {
	result.TLSInfo = &TLSInfo{}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, cc.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(cc.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	if n > 32 {
		offset := 5 + nullIndex(buffer[5:]) + 1 + 4 + 8 + 1
		if offset+2 <= n {
			capFlags := uint16(buffer[offset]) | uint16(buffer[offset+1])<<8
			if capFlags&0x0800 != 0 {
				result.TLSInfo.Supported = true
			}
		}
	}

	if result.TLSInfo.Supported {
		cc.checkTLSDetails(result, host, port)
	}
}

func nullIndex(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

func (cc *ConfigChecker) checkPostgreSQLConfig(ctx context.Context, result *ConfigResult, db *sql.DB) {
	if db == nil {
		return
	}

	rows, err := db.QueryContext(ctx, "SHOW ALL")
	if err != nil {
		result.Error = fmt.Sprintf("failed to query settings: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, value, description string
		if err := rows.Scan(&name, &value, &description); err != nil {
			continue
		}
		result.Metadata[name] = value
	}

	if result.Metadata["ssl"] == "off" {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "ssl",
			Value:       "off",
			Risk:        "High",
			Description: "SSL/TLS is disabled, connections are unencrypted",
			Remediation: "Enable SSL in postgresql.conf: ssl = on",
		})
	}

	if result.Metadata["log_statement"] == "none" {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "log_statement",
			Value:       "none",
			Risk:        "Low",
			Description: "SQL statements are not being logged",
			Remediation: "Set log_statement = 'ddl' or 'all' for audit purposes",
		})
	}

	var superuserCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pg_roles WHERE rolsuper = true").Scan(&superuserCount)
	if err == nil && superuserCount > 2 {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "superuser_count",
			Value:       fmt.Sprintf("%d", superuserCount),
			Risk:        "Medium",
			Description: "Multiple superuser accounts exist",
			Remediation: "Review and reduce the number of superuser accounts",
		})
	}
}

func (cc *ConfigChecker) checkPostgreSQLTLS(ctx context.Context, result *ConfigResult, host string, port int) {
	result.TLSInfo = &TLSInfo{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, cc.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	sslRequest := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	conn.SetWriteDeadline(time.Now().Add(cc.Timeout))
	_, err = conn.Write(sslRequest)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(cc.Timeout))
	response := make([]byte, 1)
	_, err = conn.Read(response)
	if err != nil {
		return
	}

	if response[0] == 'S' {
		result.TLSInfo.Supported = true
		cc.checkTLSDetailsOnConn(result, conn)
	} else if response[0] == 'N' {
		result.TLSInfo.Supported = false
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "ssl_connection",
			Value:       "not supported",
			Risk:        "High",
			Description: "Server does not support SSL/TLS connections",
			Remediation: "Configure SSL in postgresql.conf",
		})
	}
}

func (cc *ConfigChecker) checkMSSQLConfig(ctx context.Context, result *ConfigResult, db *sql.DB) {
	if db == nil {
		return
	}

	var xpCmdshellEnabled int
	err := db.QueryRowContext(ctx, `
		SELECT CONVERT(INT, ISNULL(value, value_in_use)) 
		FROM sys.configurations 
		WHERE name = 'xp_cmdshell'
	`).Scan(&xpCmdshellEnabled)
	if err == nil && xpCmdshellEnabled == 1 {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "xp_cmdshell",
			Value:       "enabled",
			Risk:        "Critical",
			Description: "xp_cmdshell allows execution of operating system commands",
			Remediation: "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;",
		})
	}

	var oleAutomationEnabled int
	err = db.QueryRowContext(ctx, `
		SELECT CONVERT(INT, ISNULL(value, value_in_use)) 
		FROM sys.configurations 
		WHERE name = 'Ole Automation Procedures'
	`).Scan(&oleAutomationEnabled)
	if err == nil && oleAutomationEnabled == 1 {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "ole_automation",
			Value:       "enabled",
			Risk:        "High",
			Description: "OLE Automation Procedures can be used for malicious purposes",
			Remediation: "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;",
		})
	}

	var clrEnabled int
	err = db.QueryRowContext(ctx, `
		SELECT CONVERT(INT, ISNULL(value, value_in_use)) 
		FROM sys.configurations 
		WHERE name = 'clr enabled'
	`).Scan(&clrEnabled)
	if err == nil && clrEnabled == 1 {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "clr_enabled",
			Value:       "enabled",
			Risk:        "Medium",
			Description: "CLR integration allows running .NET code which could be malicious",
			Remediation: "EXEC sp_configure 'clr enabled', 0; RECONFIGURE; (if not needed)",
		})
	}

	var remoteAdminEnabled int
	err = db.QueryRowContext(ctx, `
		SELECT CONVERT(INT, ISNULL(value, value_in_use)) 
		FROM sys.configurations 
		WHERE name = 'remote admin connections'
	`).Scan(&remoteAdminEnabled)
	if err == nil && remoteAdminEnabled == 1 {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "remote_admin_connections",
			Value:       "enabled",
			Risk:        "Medium",
			Description: "Remote DAC connections are enabled",
			Remediation: "EXEC sp_configure 'remote admin connections', 0; RECONFIGURE;",
		})
	}

	var saEnabled int
	err = db.QueryRowContext(ctx, `
		SELECT is_disabled 
		FROM sys.sql_logins 
		WHERE name = 'sa'
	`).Scan(&saEnabled)
	if err == nil && saEnabled == 0 {
		result.Metadata["sa_account"] = "enabled"
	}
}

func (cc *ConfigChecker) checkMongoDBConfig(ctx context.Context, result *ConfigResult, host string, port int) {
	result.TLSInfo = &TLSInfo{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, cc.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	isMasterCmd := buildMongoIsMaster()
	conn.SetWriteDeadline(time.Now().Add(cc.Timeout))
	_, err = conn.Write(isMasterCmd)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(cc.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])

	if strings.Contains(response, "ok") && !strings.Contains(response, "unauthorized") {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "authentication",
			Value:       "disabled or not enforced",
			Risk:        "Critical",
			Description: "MongoDB is accessible without authentication",
			Remediation: "Enable authentication in mongod.conf: security.authorization: enabled",
		})
	}
}

func buildMongoIsMaster() []byte {
	return []byte{
		0x3f, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xd4, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x13, 0x00, 0x00, 0x00,
		0x10,
		0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00,
	}
}

func (cc *ConfigChecker) checkRedisConfig(ctx context.Context, result *ConfigResult, host string, port int) {
	result.TLSInfo = &TLSInfo{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, cc.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(cc.Timeout))
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(cc.Timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])

	if strings.HasPrefix(response, "+PONG") {
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "requirepass",
			Value:       "not set",
			Risk:        "Critical",
			Description: "Redis is accessible without authentication",
			Remediation: "Set requirepass in redis.conf",
		})

		conn.SetWriteDeadline(time.Now().Add(cc.Timeout))
		_, err = conn.Write([]byte("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$10\r\nprotected-mode\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(cc.Timeout))
			n, err = conn.Read(buffer)
			if err == nil {
				configResponse := string(buffer[:n])
				if strings.Contains(configResponse, "no") {
					result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
						Name:        "protected-mode",
						Value:       "no",
						Risk:        "High",
						Description: "Protected mode is disabled, allowing remote connections without auth",
						Remediation: "Set protected-mode yes in redis.conf or enable authentication",
					})
				}
			}
		}

		conn.SetWriteDeadline(time.Now().Add(cc.Timeout))
		_, err = conn.Write([]byte("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$4\r\nbind\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(cc.Timeout))
			n, err = conn.Read(buffer)
			if err == nil {
				configResponse := string(buffer[:n])
				if strings.Contains(configResponse, "0.0.0.0") {
					result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
						Name:        "bind",
						Value:       "0.0.0.0",
						Risk:        "High",
						Description: "Redis is bound to all interfaces",
						Remediation: "Bind to localhost only: bind 127.0.0.1",
					})
				}
			}
		}
	}
}

func (cc *ConfigChecker) checkOracleConfig(ctx context.Context, result *ConfigResult, db *sql.DB) {
	if db == nil {
		return
	}
}

func (cc *ConfigChecker) checkGenericTLS(ctx context.Context, result *ConfigResult, host string, port int) {
	result.TLSInfo = &TLSInfo{}
	cc.checkTLSDetails(result, host, port)
}

func (cc *ConfigChecker) checkTLSDetails(result *ConfigResult, host string, port int) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: cc.Timeout}, "tcp", addr, cc.TLSConfig)
	if err != nil {
		return
	}
	defer conn.Close()

	cc.extractTLSInfo(result, conn.ConnectionState())

	// Enumerate supported TLS versions
	cc.enumerateTLSVersions(result, addr)

	// Enumerate cipher suites (limited to avoid too many connections)
	cc.enumerateCipherSuites(result, addr)
}

func (cc *ConfigChecker) checkTLSDetailsOnConn(result *ConfigResult, conn net.Conn) {
	tlsConn := tls.Client(conn, cc.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	cc.extractTLSInfo(result, tlsConn.ConnectionState())
}

func (cc *ConfigChecker) extractTLSInfo(result *ConfigResult, state tls.ConnectionState) {
	result.TLSInfo.Supported = true
	result.TLSInfo.Version = getTLSVersionString(state.Version)
	result.TLSInfo.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if state.Version < tls.VersionTLS12 {
		result.TLSInfo.WeakProtocol = true
		result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
			Name:        "tls_version",
			Value:       result.TLSInfo.Version,
			Risk:        "High",
			Description: "Weak TLS version in use (TLS 1.1 or below)",
			Remediation: "Configure server to use TLS 1.2 or higher",
		})
	}

	// Analyze the certificate chain
	cc.analyzeCertificateChain(result, state)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.TLSInfo.CertSubject = cert.Subject.String()
		result.TLSInfo.CertIssuer = cert.Issuer.String()
		result.TLSInfo.CertExpiry = cert.NotAfter
		result.TLSInfo.CertNotBefore = cert.NotBefore

		if cert.Issuer.String() == cert.Subject.String() {
			result.TLSInfo.SelfSigned = true
			result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
				Name:        "certificate",
				Value:       "self-signed",
				Risk:        "Medium",
				Description: "Certificate is self-signed",
				Remediation: "Use a certificate from a trusted CA",
			})
		}

		if cert.NotAfter.Before(time.Now()) {
			result.TLSInfo.Expired = true
			result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
				Name:        "certificate",
				Value:       "expired",
				Risk:        "High",
				Description: "Certificate has expired",
				Remediation: "Renew the SSL/TLS certificate",
			})
		}
	}
}

func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", version)
	}
}

// enumerateTLSVersions tests which TLS versions are supported by the target
func (cc *ConfigChecker) enumerateTLSVersions(result *ConfigResult, addr string) {
	versions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionSSL30, "SSLv3"},
		{tls.VersionTLS10, "TLSv1.0"},
		{tls.VersionTLS11, "TLSv1.1"},
		{tls.VersionTLS12, "TLSv1.2"},
		{tls.VersionTLS13, "TLSv1.3"},
	}

	for _, v := range versions {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.version,
			MaxVersion:         v.version,
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: cc.Timeout}, "tcp", addr, config)
		if err == nil {
			result.TLSInfo.SupportedVersions = append(result.TLSInfo.SupportedVersions, v.name)
			conn.Close()

			// Flag deprecated versions
			if v.version <= tls.VersionTLS11 {
				result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
					Name:        "deprecated_tls",
					Value:       v.name,
					Risk:        "High",
					Description: fmt.Sprintf("Server supports deprecated TLS version: %s", v.name),
					Remediation: "Disable support for TLS 1.1 and below",
				})
			}
		}
	}
}

// enumerateCipherSuites tests which cipher suites are supported
func (cc *ConfigChecker) enumerateCipherSuites(result *ConfigResult, addr string) {
	// Test TLS 1.2 ciphers (most comprehensive)
	allCiphers := tls.CipherSuites()
	insecureCiphers := tls.InsecureCipherSuites()

	// Build a map of secure ciphers
	secureCipherMap := make(map[uint16]bool)
	for _, c := range allCiphers {
		secureCipherMap[c.ID] = true
	}

	// Test each cipher suite
	for _, cipher := range append(allCiphers, insecureCiphers...) {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{cipher.ID},
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: cc.Timeout}, "tcp", addr, config)
		if err == nil {
			isSecure := secureCipherMap[cipher.ID]
			strength := classifyCipherStrength(cipher.Name)

			result.TLSInfo.CipherSuites = append(result.TLSInfo.CipherSuites, CipherSuiteInfo{
				ID:       cipher.ID,
				Name:     cipher.Name,
				Strength: strength,
				Secure:   isSecure,
			})
			conn.Close()

			if !isSecure {
				result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
					Name:        "weak_cipher",
					Value:       cipher.Name,
					Risk:        "Medium",
					Description: fmt.Sprintf("Server supports insecure cipher suite: %s", cipher.Name),
					Remediation: "Disable weak cipher suites in server configuration",
				})
			}
		}
	}
}

// classifyCipherStrength categorizes cipher suite strength
func classifyCipherStrength(cipherName string) string {
	name := strings.ToUpper(cipherName)

	// Strong ciphers (AES-GCM, ChaCha20)
	if strings.Contains(name, "GCM") || strings.Contains(name, "CHACHA20") {
		if strings.Contains(name, "256") {
			return "Strong"
		}
		return "Good"
	}

	// Weak ciphers
	if strings.Contains(name, "RC4") ||
		strings.Contains(name, "DES") ||
		strings.Contains(name, "NULL") ||
		strings.Contains(name, "EXPORT") ||
		strings.Contains(name, "ANON") ||
		strings.Contains(name, "MD5") {
		return "Weak"
	}

	// CBC mode ciphers (vulnerable to BEAST/POODLE in certain configs)
	if strings.Contains(name, "CBC") {
		return "Medium"
	}

	return "Unknown"
}

// analyzeCertificateChain extracts detailed certificate chain information
func (cc *ConfigChecker) analyzeCertificateChain(result *ConfigResult, state tls.ConnectionState) {
	for _, cert := range state.PeerCertificates {
		keyType := "Unknown"
		keySize := 0

		if cert.PublicKeyAlgorithm.String() != "" {
			keyType = cert.PublicKeyAlgorithm.String()
		}

		// Extract key size based on algorithm
		switch keyType {
		case "RSA":
			if cert.PublicKey != nil {
				if rsaKey, ok := cert.PublicKey.(interface{ Size() int }); ok {
					keySize = rsaKey.Size() * 8
				}
			}
		case "ECDSA":
			if cert.PublicKey != nil {
				// ECDSA keys report bit size differently
				keySize = 256 // Typical, actual varies
			}
		}

		certInfo := CertInfo{
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
			KeyType:    keyType,
			KeySize:    keySize,
			SelfSigned: cert.Subject.String() == cert.Issuer.String(),
		}

		result.TLSInfo.CertChain = append(result.TLSInfo.CertChain, certInfo)

		// Extract Subject Alternative Names
		for _, dns := range cert.DNSNames {
			result.TLSInfo.CertSAN = append(result.TLSInfo.CertSAN, "DNS:"+dns)
		}
		for _, ip := range cert.IPAddresses {
			result.TLSInfo.CertSAN = append(result.TLSInfo.CertSAN, "IP:"+ip.String())
		}
		for _, email := range cert.EmailAddresses {
			result.TLSInfo.CertSAN = append(result.TLSInfo.CertSAN, "Email:"+email)
		}

		// Check for weak key sizes
		if keyType == "RSA" && keySize > 0 && keySize < 2048 {
			result.DangerousSettings = append(result.DangerousSettings, DangerousSetting{
				Name:        "weak_key",
				Value:       fmt.Sprintf("%s %d-bit", keyType, keySize),
				Risk:        "High",
				Description: "RSA key size is less than 2048 bits",
				Remediation: "Use RSA keys with at least 2048 bits",
			})
		}
	}

	// Check OCSP stapling
	if len(state.OCSPResponse) > 0 {
		result.TLSInfo.OCSP = "Stapled"
	} else {
		result.TLSInfo.OCSP = "Not Stapled"
	}
}
