package auth

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func init() {
	initMySQLDriver()
	initPostgreSQLDriver()
	initMSSQLDriver()
	initRedisDriver()
	initMongoDBDriver()
	initElasticsearchDriver()
	initMemcachedDriver()
}

func initMySQLDriver() {
	tryMySQLConnectionFunc = func(addr, username, password, database string, timeout time.Duration) (bool, string, map[string]string, error) {
		metadata := make(map[string]string)

		dbName := "mysql"
		if database != "" {
			dbName = database
		}

		dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?timeout=%s&readTimeout=%s",
			username, password, addr, dbName, timeout.String(), timeout.String())

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return false, "", metadata, err
		}
		defer db.Close()

		db.SetConnMaxLifetime(timeout)
		db.SetMaxOpenConns(1)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			return false, "", metadata, err
		}

		var version string
		if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err == nil {
			metadata["version"] = version
		}

		var user string
		if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); err == nil {
			metadata["current_user"] = user
		}

		privLevel := "user"
		rows, err := db.QueryContext(ctx, "SHOW GRANTS")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var grant string
				if err := rows.Scan(&grant); err == nil {
					grantLower := strings.ToLower(grant)
					if strings.Contains(grantLower, "all privileges on *.*") ||
						strings.Contains(grantLower, "super") ||
						strings.Contains(grantLower, "grant option") {
						privLevel = "superuser"
					} else if strings.Contains(grantLower, "create user") ||
						strings.Contains(grantLower, "reload") {
						if privLevel != "superuser" {
							privLevel = "admin"
						}
					}
				}
			}
		}

		return true, privLevel, metadata, nil
	}
}

var tryMySQLConnectionFunc func(addr, username, password, database string, timeout time.Duration) (bool, string, map[string]string, error)

func initPostgreSQLDriver() {
	tryPostgreSQLConnectionFunc = func(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
		metadata := make(map[string]string)

		host, port, _ := net.SplitHostPort(addr)

		connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
			host, port, username, password, int(timeout.Seconds()))

		db, err := sql.Open("postgres", connStr)
		if err != nil {
			return false, "", metadata, err
		}
		defer db.Close()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			return false, "", metadata, err
		}

		var version string
		if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err == nil {
			metadata["version"] = version
		}

		var user string
		if err := db.QueryRowContext(ctx, "SELECT current_user").Scan(&user); err == nil {
			metadata["current_user"] = user
		}

		privLevel := "user"
		var isSuper bool
		err = db.QueryRowContext(ctx, "SELECT usesuper FROM pg_user WHERE usename = current_user").Scan(&isSuper)
		if err == nil && isSuper {
			privLevel = "superuser"
		}

		var rolSuper, rolCreateRole, rolCreateDB bool
		err = db.QueryRowContext(ctx,
			"SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user").
			Scan(&rolSuper, &rolCreateRole, &rolCreateDB)
		if err == nil {
			if rolSuper {
				privLevel = "superuser"
			} else if rolCreateRole || rolCreateDB {
				if privLevel != "superuser" {
					privLevel = "admin"
				}
			}
		}

		return true, privLevel, metadata, nil
	}
}

var tryPostgreSQLConnectionFunc func(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error)

func initMSSQLDriver() {
	tryMSSQLConnectionFunc = func(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
		metadata := make(map[string]string)

		host, port, _ := net.SplitHostPort(addr)

		connStr := fmt.Sprintf("server=%s;port=%s;user id=%s;password=%s;connection timeout=%d",
			host, port, username, password, int(timeout.Seconds()))

		db, err := sql.Open("mssql", connStr)
		if err != nil {
			return false, "", metadata, err
		}
		defer db.Close()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			return false, "", metadata, err
		}

		var version string
		if err := db.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&version); err == nil {
			metadata["version"] = version
		}

		var user string
		if err := db.QueryRowContext(ctx, "SELECT SYSTEM_USER").Scan(&user); err == nil {
			metadata["current_user"] = user
		}

		privLevel := "user"
		var isSysadmin int
		err = db.QueryRowContext(ctx, "SELECT IS_SRVROLEMEMBER('sysadmin')").Scan(&isSysadmin)
		if err == nil && isSysadmin == 1 {
			privLevel = "sysadmin"
		} else {
			var isSecurityAdmin int
			err = db.QueryRowContext(ctx, "SELECT IS_SRVROLEMEMBER('securityadmin')").Scan(&isSecurityAdmin)
			if err == nil && isSecurityAdmin == 1 {
				privLevel = "securityadmin"
			}
		}

		return true, privLevel, metadata, nil
	}
}

var tryMSSQLConnectionFunc func(addr, username, password string, timeout time.Duration) (bool, string, map[string]string, error)

func initRedisDriver() {
	tryRedisConnectionFunc = func(host string, port int, password string, timeout time.Duration) (bool, string, map[string]string, error) {
		metadata := make(map[string]string)

		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false, "", metadata, err
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(timeout))

		if password != "" {
			authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
			_, err = conn.Write([]byte(authCmd))
			if err != nil {
				return false, "", metadata, err
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				return false, "", metadata, err
			}

			response := string(buf[:n])
			if strings.HasPrefix(response, "-ERR") || strings.HasPrefix(response, "-WRONGPASS") {
				return false, "", metadata, fmt.Errorf("authentication failed")
			}
		}

		_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
		if err != nil {
			return false, "", metadata, err
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return false, "", metadata, err
		}

		response := string(buf[:n])
		if strings.HasPrefix(response, "-NOAUTH") {
			return false, "", metadata, fmt.Errorf("NOAUTH Authentication required")
		}

		if !strings.HasPrefix(response, "+PONG") && !strings.HasPrefix(response, "+OK") {
			return false, "", metadata, fmt.Errorf("unexpected response: %s", response)
		}

		_, err = conn.Write([]byte("*1\r\n$4\r\nINFO\r\n"))
		if err == nil {
			buf = make([]byte, 8192)
			n, err = conn.Read(buf)
			if err == nil {
				infoStr := string(buf[:n])

				if idx := strings.Index(infoStr, "redis_version:"); idx != -1 {
					end := strings.Index(infoStr[idx:], "\r\n")
					if end != -1 {
						metadata["version"] = strings.TrimPrefix(infoStr[idx:idx+end], "redis_version:")
					}
				}

				if idx := strings.Index(infoStr, "redis_mode:"); idx != -1 {
					end := strings.Index(infoStr[idx:], "\r\n")
					if end != -1 {
						metadata["mode"] = strings.TrimPrefix(infoStr[idx:idx+end], "redis_mode:")
					}
				}
			}
		}

		return true, "full", metadata, nil
	}
}

var tryRedisConnectionFunc func(host string, port int, password string, timeout time.Duration) (bool, string, map[string]string, error)

func initMongoDBDriver() {
	tryMongoDBConnectionFunc = func(host string, port int, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
		metadata := make(map[string]string)

		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false, "", metadata, err
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(timeout))

		isMasterCmd := buildMongoIsMasterCommand()
		_, err = conn.Write(isMasterCmd)
		if err != nil {
			return false, "", metadata, err
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return false, "", metadata, err
		}

		response := string(buf[:n])

		if strings.Contains(response, "ismaster") || strings.Contains(response, "maxWireVersion") {
			if username == "" && password == "" {
				metadata["auth_status"] = "no_auth_required"
				return true, "unknown", metadata, nil
			}
		}

		if strings.Contains(response, "unauthorized") || strings.Contains(response, "auth") {
			return false, "", metadata, fmt.Errorf("authentication failed")
		}

		return true, "user", metadata, nil
	}
}

func buildMongoIsMasterCommand() []byte {
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

var tryMongoDBConnectionFunc func(host string, port int, username, password string, timeout time.Duration) (bool, string, map[string]string, error)

func initElasticsearchDriver() {
	tryElasticsearchConnectionFunc = func(host string, port int, username, password string, timeout time.Duration) (bool, string, map[string]string, error) {
		metadata := make(map[string]string)

		client := &http.Client{
			Timeout: timeout,
		}

		url := fmt.Sprintf("http://%s:%d/", host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return false, "", metadata, err
		}

		if username != "" && password != "" {
			req.SetBasicAuth(username, password)
		}

		resp, err := client.Do(req)
		if err != nil {
			return false, "", metadata, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return false, "", metadata, fmt.Errorf("HTTP %d: authentication required", resp.StatusCode)
		}

		if resp.StatusCode == 200 {
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			if strings.Contains(body, "cluster_name") || strings.Contains(body, "elasticsearch") {
				if idx := strings.Index(body, `"number"`); idx != -1 {
					start := idx + 12
					end := strings.Index(body[start:], `"`)
					if end > 0 && start+end < len(body) {
						metadata["version"] = body[start : start+end]
					}
				}

				if idx := strings.Index(body, `"cluster_name"`); idx != -1 {
					start := idx + 17
					end := strings.Index(body[start:], `"`)
					if end > 0 && start+end < len(body) {
						metadata["cluster_name"] = body[start : start+end]
					}
				}

				return true, "full", metadata, nil
			}
		}

		return false, "", metadata, fmt.Errorf("unexpected response")
	}
}

var tryElasticsearchConnectionFunc func(host string, port int, username, password string, timeout time.Duration) (bool, string, map[string]string, error)

func initMemcachedDriver() {
	tryMemcachedConnectionFunc = func(host string, port int, timeout time.Duration) (bool, map[string]string, error) {
		metadata := make(map[string]string)

		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false, metadata, err
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(timeout))

		_, err = conn.Write([]byte("version\r\n"))
		if err != nil {
			return false, metadata, err
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return false, metadata, err
		}

		response := string(buf[:n])
		if strings.HasPrefix(response, "VERSION ") {
			metadata["version"] = strings.TrimSpace(strings.TrimPrefix(response, "VERSION "))
			return true, metadata, nil
		}

		if strings.Contains(response, "ERROR") {
			return false, metadata, fmt.Errorf("memcached error: %s", response)
		}

		return true, metadata, nil
	}
}

var tryMemcachedConnectionFunc func(host string, port int, timeout time.Duration) (bool, map[string]string, error)
