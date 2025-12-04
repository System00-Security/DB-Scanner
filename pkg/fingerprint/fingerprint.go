package fingerprint

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type ServiceInfo struct {
	ServiceType     string
	Version         string
	ProtocolVersion string
	Edition         string
	IsTLS           bool
	TLSVersion      string
	Banner          string
	RawResponse     []byte
	Fingerprint     string
	Confidence      int
	ExtraInfo       map[string]string
}

type Fingerprinter struct {
	Timeout    time.Duration
	TLSConfig  *tls.Config
}

func NewFingerprinter(timeout time.Duration) *Fingerprinter {
	return &Fingerprinter{
		Timeout: timeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
}

func (f *Fingerprinter) Fingerprint(ctx context.Context, host string, port int, serviceName string) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: serviceName,
		ExtraInfo:   make(map[string]string),
	}

	switch serviceName {
	case "mysql", "mariadb":
		return f.fingerprintMySQL(ctx, host, port)
	case "postgresql", "postgres":
		return f.fingerprintPostgreSQL(ctx, host, port)
	case "mssql":
		return f.fingerprintMSSQL(ctx, host, port)
	case "mongodb":
		return f.fingerprintMongoDB(ctx, host, port)
	case "redis":
		return f.fingerprintRedis(ctx, host, port)
	case "oracle":
		return f.fingerprintOracle(ctx, host, port)
	case "cassandra":
		return f.fingerprintCassandra(ctx, host, port)
	case "elasticsearch":
		return f.fingerprintElasticsearch(ctx, host, port)
	case "memcached":
		return f.fingerprintMemcached(ctx, host, port)
	default:
		return f.fingerprintGeneric(ctx, host, port, info)
	}
}

func (f *Fingerprinter) fingerprintMySQL(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "mysql",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(f.Timeout))

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake: %w", err)
	}

	if n < 5 {
		return nil, fmt.Errorf("invalid MySQL handshake packet")
	}

	info.RawResponse = buffer[:n]

	if n > 4 {
		protocolVersion := buffer[4]
		info.ProtocolVersion = fmt.Sprintf("%d", protocolVersion)

		if protocolVersion == 10 || protocolVersion == 9 {
			nullPos := bytes.IndexByte(buffer[5:], 0)
			if nullPos > 0 {
				versionStr := string(buffer[5 : 5+nullPos])
				info.Version = versionStr
				info.Banner = versionStr

				if strings.Contains(strings.ToLower(versionStr), "mariadb") {
					info.ServiceType = "mariadb"
				}

				if strings.Contains(versionStr, "Enterprise") {
					info.Edition = "Enterprise"
				} else if strings.Contains(versionStr, "Community") {
					info.Edition = "Community"
				}

				info.Confidence = 95
			}
		}

		if n > 5+nullPos(buffer[5:])+1+4+8+1+2+1+2+2+1+10+1 {
			offset := 5 + nullPos(buffer[5:]) + 1 + 4 + 8 + 1
			if offset+2 <= n {
				capFlags := binary.LittleEndian.Uint16(buffer[offset : offset+2])
				if capFlags&0x0800 != 0 {
					info.ExtraInfo["ssl_capable"] = "true"
				}
			}
		}
	}

	if info.ExtraInfo["ssl_capable"] == "true" {
		tlsInfo, _ := f.checkTLS(ctx, host, port, "mysql")
		if tlsInfo != nil {
			info.IsTLS = true
			info.TLSVersion = tlsInfo.TLSVersion
			for k, v := range tlsInfo.ExtraInfo {
				info.ExtraInfo[k] = v
			}
		}
	}

	return info, nil
}

func nullPos(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

func (f *Fingerprinter) fingerprintPostgreSQL(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "postgresql",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	sslRequest := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write(sslRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send SSL request: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	response := make([]byte, 1)
	_, err = conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSL response: %w", err)
	}

	if response[0] == 'S' {
		info.IsTLS = true
		info.ExtraInfo["ssl_supported"] = "true"

		tlsConn := tls.Client(conn, f.TLSConfig)
		if err := tlsConn.Handshake(); err == nil {
			state := tlsConn.ConnectionState()
			info.TLSVersion = getTLSVersionString(state.Version)
			info.ExtraInfo["tls_cipher"] = tls.CipherSuiteName(state.CipherSuite)
			conn = tlsConn
		}
	} else if response[0] == 'N' {
		info.ExtraInfo["ssl_supported"] = "false"
	}

	startupMessage := buildPostgreSQLStartup("postgres", "postgres")
	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write(startupMessage)
	if err != nil {
		return info, nil
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return info, nil
	}

	info.RawResponse = buffer[:n]

	if n > 0 {
		msgType := buffer[0]
		switch msgType {
		case 'R':
			info.Confidence = 90
			info.ExtraInfo["auth_required"] = "true"
		case 'E':
			info.Confidence = 90
			if n > 5 {
				errorMsg := extractPostgreSQLError(buffer[:n])
				info.ExtraInfo["error"] = errorMsg
				if strings.Contains(errorMsg, "server version") {
					parts := strings.Split(errorMsg, "server version")
					if len(parts) > 1 {
						info.Version = strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}

	return info, nil
}

func buildPostgreSQLStartup(user, database string) []byte {
	params := map[string]string{
		"user":             user,
		"database":         database,
		"client_encoding":  "UTF8",
		"application_name": "dbscanner",
	}

	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	binary.Write(&buf, binary.BigEndian, int32(196608))

	for k, v := range params {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(v)
		buf.WriteByte(0)
	}
	buf.WriteByte(0)

	msgLen := buf.Len()
	msg := buf.Bytes()
	binary.BigEndian.PutUint32(msg[0:4], uint32(msgLen))

	return msg
}

func extractPostgreSQLError(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	var msg strings.Builder
	i := 5
	for i < len(data) {
		if data[i] == 0 {
			break
		}
		fieldType := data[i]
		i++
		end := i
		for end < len(data) && data[end] != 0 {
			end++
		}
		fieldValue := string(data[i:end])
		i = end + 1

		if fieldType == 'M' {
			msg.WriteString(fieldValue)
		}
	}

	return msg.String()
}

func (f *Fingerprinter) fingerprintMSSQL(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "mssql",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	prelogin := buildMSSQLPrelogin()
	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write(prelogin)
	if err != nil {
		return nil, fmt.Errorf("failed to send prelogin: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read prelogin response: %w", err)
	}

	info.RawResponse = buffer[:n]

	if n >= 8 && buffer[0] == 0x04 {
		info.Confidence = 85
		info.ExtraInfo["prelogin_response"] = "valid"

		versionOffset := 8
		if n > versionOffset+6 {
			major := buffer[versionOffset]
			minor := buffer[versionOffset+1]
			build := binary.BigEndian.Uint16(buffer[versionOffset+2 : versionOffset+4])
			info.Version = fmt.Sprintf("%d.%d.%d", major, minor, build)

			if major >= 15 {
				info.Edition = "SQL Server 2019+"
			} else if major >= 14 {
				info.Edition = "SQL Server 2017"
			} else if major >= 13 {
				info.Edition = "SQL Server 2016"
			} else if major >= 12 {
				info.Edition = "SQL Server 2014"
			} else if major >= 11 {
				info.Edition = "SQL Server 2012"
			}
		}

		for i := 8; i < n-1; i++ {
			if buffer[i] == 0x01 {
				encOption := buffer[i+1]
				switch encOption {
				case 0x00:
					info.ExtraInfo["encryption"] = "off"
				case 0x01:
					info.ExtraInfo["encryption"] = "on"
					info.IsTLS = true
				case 0x02:
					info.ExtraInfo["encryption"] = "not_supported"
				case 0x03:
					info.ExtraInfo["encryption"] = "required"
					info.IsTLS = true
				}
				break
			}
		}
	}

	return info, nil
}

func buildMSSQLPrelogin() []byte {
	prelogin := []byte{
		0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06,
		0x01, 0x00, 0x20, 0x00, 0x01,
		0x02, 0x00, 0x21, 0x00, 0x01,
		0x03, 0x00, 0x22, 0x00, 0x04,
		0x04, 0x00, 0x26, 0x00, 0x01,
		0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00,
	}
	return prelogin
}

func (f *Fingerprinter) fingerprintMongoDB(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "mongodb",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	isMasterCmd := buildMongoDBIsMaster()
	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write(isMasterCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to send isMaster: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	info.RawResponse = buffer[:n]
	info.Confidence = 80

	responseStr := string(buffer[:n])
	if strings.Contains(responseStr, "maxWireVersion") {
		info.ExtraInfo["wire_protocol"] = "detected"
	}

	if idx := strings.Index(responseStr, "version"); idx != -1 {
		start := idx + 8
		end := start
		for end < len(responseStr) && (responseStr[end] == '.' || (responseStr[end] >= '0' && responseStr[end] <= '9')) {
			end++
		}
		if end > start {
			info.Version = responseStr[start:end]
		}
	}

	return info, nil
}

func buildMongoDBIsMaster() []byte {
	document := []byte{
		0x13, 0x00, 0x00, 0x00,
		0x10,
		0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00,
	}

	header := make([]byte, 16)
	msgLen := 16 + len(document) + 4 + 4
	binary.LittleEndian.PutUint32(header[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(header[4:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], 0)
	binary.LittleEndian.PutUint32(header[12:16], 2004)

	var buf bytes.Buffer
	buf.Write(header)
	binary.Write(&buf, binary.LittleEndian, int32(0))
	buf.WriteString("admin.$cmd")
	buf.WriteByte(0)
	binary.Write(&buf, binary.LittleEndian, int32(0))
	binary.Write(&buf, binary.LittleEndian, int32(1))
	buf.Write(document)

	return buf.Bytes()
}

func (f *Fingerprinter) fingerprintRedis(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "redis",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send PING: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response := string(buffer[:n])
	info.RawResponse = buffer[:n]

	if strings.HasPrefix(response, "+PONG") {
		info.Confidence = 95
		info.ExtraInfo["auth_required"] = "false"
	} else if strings.HasPrefix(response, "-NOAUTH") {
		info.Confidence = 95
		info.ExtraInfo["auth_required"] = "true"
	} else if strings.HasPrefix(response, "-ERR") {
		info.Confidence = 85
	}

	if info.ExtraInfo["auth_required"] == "false" {
		conn.SetWriteDeadline(time.Now().Add(f.Timeout))
		_, err = conn.Write([]byte("*1\r\n$4\r\nINFO\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(f.Timeout))
			n, err = conn.Read(buffer)
			if err == nil {
				infoResponse := string(buffer[:n])
				if idx := strings.Index(infoResponse, "redis_version:"); idx != -1 {
					end := strings.Index(infoResponse[idx:], "\r\n")
					if end != -1 {
						info.Version = strings.TrimPrefix(infoResponse[idx:idx+end], "redis_version:")
					}
				}
				if strings.Contains(infoResponse, "redis_mode:cluster") {
					info.ExtraInfo["mode"] = "cluster"
				} else if strings.Contains(infoResponse, "redis_mode:sentinel") {
					info.ExtraInfo["mode"] = "sentinel"
				} else {
					info.ExtraInfo["mode"] = "standalone"
				}
			}
		}
	}

	tlsInfo, _ := f.checkTLS(ctx, host, port, "redis")
	if tlsInfo != nil && tlsInfo.IsTLS {
		info.IsTLS = true
		info.TLSVersion = tlsInfo.TLSVersion
	}

	return info, nil
}

func (f *Fingerprinter) fingerprintOracle(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "oracle",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	tnsConnect := buildOracleTNSConnect()
	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write(tnsConnect)
	if err != nil {
		return nil, fmt.Errorf("failed to send TNS connect: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	info.RawResponse = buffer[:n]

	if n >= 2 {
		packetType := buffer[4]
		switch packetType {
		case 2:
			info.Confidence = 90
			info.ExtraInfo["tns_response"] = "accept"
		case 4:
			info.Confidence = 90
			info.ExtraInfo["tns_response"] = "refuse"
			if n > 12 {
				refuseData := string(buffer[12:n])
				info.ExtraInfo["refuse_reason"] = refuseData
			}
		case 11:
			info.Confidence = 90
			info.ExtraInfo["tns_response"] = "resend"
		}
	}

	responseStr := string(buffer[:n])
	versionPatterns := []string{"Version ", "TNSLSNR for", "Oracle Database"}
	for _, pattern := range versionPatterns {
		if idx := strings.Index(responseStr, pattern); idx != -1 {
			end := idx + len(pattern)
			for end < len(responseStr) && responseStr[end] != ')' && responseStr[end] != '\n' && responseStr[end] != 0 {
				end++
			}
			info.Version = strings.TrimSpace(responseStr[idx+len(pattern) : end])
			break
		}
	}

	return info, nil
}

func buildOracleTNSConnect() []byte {
	connectData := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=)(CID=(PROGRAM=dbscanner)(HOST=localhost)(USER=scan))))"

	packet := make([]byte, 58+len(connectData))

	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[2:4], 0)
	packet[4] = 1
	packet[5] = 0
	binary.BigEndian.PutUint16(packet[6:8], 0x0136)
	binary.BigEndian.PutUint16(packet[8:10], 0x0139)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[24:26], 0x0001)
	binary.BigEndian.PutUint16(packet[26:28], uint16(len(connectData)))
	binary.BigEndian.PutUint16(packet[28:30], 58)

	copy(packet[58:], connectData)

	return packet
}

func (f *Fingerprinter) fingerprintCassandra(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "cassandra",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	options := []byte{
		0x04,
		0x00,
		0x00, 0x00,
		0x05,
		0x00, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write(options)
	if err != nil {
		return nil, fmt.Errorf("failed to send OPTIONS: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	info.RawResponse = buffer[:n]

	if n >= 9 && (buffer[0] == 0x84 || buffer[0] == 0x83) {
		info.Confidence = 90
		info.ProtocolVersion = fmt.Sprintf("%d", buffer[0]&0x7f)

		if buffer[4] == 0x06 {
			info.ExtraInfo["response_type"] = "supported"
		}
	}

	return info, nil
}

func (f *Fingerprinter) fingerprintElasticsearch(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "elasticsearch",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	httpRequest := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response := string(buffer[:n])
	info.RawResponse = buffer[:n]

	if strings.Contains(response, "elasticsearch") || strings.Contains(response, "lucene") {
		info.Confidence = 95

		if idx := strings.Index(response, `"number" : "`); idx != -1 {
			start := idx + 12
			end := strings.Index(response[start:], `"`)
			if end != -1 {
				info.Version = response[start : start+end]
			}
		}

		if idx := strings.Index(response, `"cluster_name" : "`); idx != -1 {
			start := idx + 18
			end := strings.Index(response[start:], `"`)
			if end != -1 {
				info.ExtraInfo["cluster_name"] = response[start : start+end]
			}
		}
	}

	return info, nil
}

func (f *Fingerprinter) fingerprintMemcached(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ServiceType: "memcached",
		ExtraInfo:   make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(f.Timeout))
	_, err = conn.Write([]byte("version\r\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send version: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response := string(buffer[:n])
	info.RawResponse = buffer[:n]

	if strings.HasPrefix(response, "VERSION ") {
		info.Confidence = 95
		info.Version = strings.TrimSpace(strings.TrimPrefix(response, "VERSION "))
	}

	return info, nil
}

func (f *Fingerprinter) fingerprintGeneric(ctx context.Context, host string, port int, info *ServiceInfo) (*ServiceInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := f.dialWithContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(f.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		info.Banner = string(buffer[:n])
		info.RawResponse = buffer[:n]
	}

	probes := [][]byte{
		[]byte("\r\n"),
		[]byte("HELP\r\n"),
		[]byte("INFO\r\n"),
	}

	for _, probe := range probes {
		conn.SetWriteDeadline(time.Now().Add(f.Timeout))
		conn.Write(probe)
		conn.SetReadDeadline(time.Now().Add(f.Timeout))
		n, err = conn.Read(buffer)
		if err == nil && n > 0 {
			info.Banner = string(buffer[:n])
			info.RawResponse = buffer[:n]
			break
		}
	}

	info.Confidence = 30

	return info, nil
}

func (f *Fingerprinter) checkTLS(ctx context.Context, host string, port int, service string) (*ServiceInfo, error) {
	info := &ServiceInfo{
		ExtraInfo: make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: f.Timeout}, "tcp", addr, f.TLSConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.IsTLS = true
	info.TLSVersion = getTLSVersionString(state.Version)
	info.ExtraInfo["tls_cipher"] = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.ExtraInfo["cert_subject"] = cert.Subject.String()
		info.ExtraInfo["cert_issuer"] = cert.Issuer.String()
		info.ExtraInfo["cert_not_before"] = cert.NotBefore.String()
		info.ExtraInfo["cert_not_after"] = cert.NotAfter.String()
		info.ExtraInfo["cert_key_size"] = fmt.Sprintf("%d", cert.PublicKey)

		if cert.NotAfter.Before(time.Now()) {
			info.ExtraInfo["cert_expired"] = "true"
		}
		if cert.NotBefore.After(time.Now()) {
			info.ExtraInfo["cert_not_yet_valid"] = "true"
		}
		if cert.Issuer.String() == cert.Subject.String() {
			info.ExtraInfo["cert_self_signed"] = "true"
		}
	}

	return info, nil
}

func (f *Fingerprinter) dialWithContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: f.Timeout}
	return dialer.DialContext(ctx, network, addr)
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
