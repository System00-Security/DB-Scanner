package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"dbscanner/pkg/auth"
	"dbscanner/pkg/configcheck"
	"dbscanner/pkg/fingerprint"
	"dbscanner/pkg/nmap"
	"dbscanner/pkg/scanner"
)

type RiskLevel string

const (
	RiskCritical RiskLevel = "Critical"
	RiskHigh     RiskLevel = "High"
	RiskMedium   RiskLevel = "Medium"
	RiskLow      RiskLevel = "Low"
	RiskInfo     RiskLevel = "Info"
)

type ScanReport struct {
	ScanInfo   ScanInfo        `json:"scan_info"`
	Summary    ScanSummary     `json:"summary"`
	Services   []ServiceReport `json:"services"`
	GeneratedAt time.Time      `json:"generated_at"`
}

type ScanInfo struct {
	Targets        []string      `json:"targets"`
	PortsScanned   []int         `json:"ports_scanned"`
	ScanProfile    string        `json:"scan_profile"`
	ScanDuration   time.Duration `json:"scan_duration"`
	NmapVersion    string        `json:"nmap_version,omitempty"`
}

type ScanSummary struct {
	TotalHosts       int            `json:"total_hosts"`
	TotalPorts       int            `json:"total_ports"`
	OpenPorts        int            `json:"open_ports"`
	ServicesFound    int            `json:"services_found"`
	CriticalFindings int            `json:"critical_findings"`
	HighFindings     int            `json:"high_findings"`
	MediumFindings   int            `json:"medium_findings"`
	LowFindings      int            `json:"low_findings"`
	ServiceTypes     map[string]int `json:"service_types"`
}

type ServiceReport struct {
	Identification   Identification   `json:"identification"`
	VersionTransport VersionTransport `json:"version_transport"`
	Authentication   AuthReport       `json:"authentication"`
	Configuration    ConfigReport     `json:"configuration"`
	Vulnerabilities  VulnReport       `json:"vulnerabilities"`
	RiskAssessment   RiskAssessment   `json:"risk_assessment"`
}

type Identification struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	ServiceType     string `json:"service_type"`
	StandardPort    bool   `json:"standard_port"`
	NonStandardNote string `json:"non_standard_note,omitempty"`
}

type VersionTransport struct {
	Version         string            `json:"version"`
	Edition         string            `json:"edition,omitempty"`
	ProtocolVersion string            `json:"protocol_version,omitempty"`
	TLSEnabled      bool              `json:"tls_enabled"`
	TLSVersion      string            `json:"tls_version,omitempty"`
	TLSDetails      *TLSDetails       `json:"tls_details,omitempty"`
	ExtraInfo       map[string]string `json:"extra_info,omitempty"`
}

type TLSDetails struct {
	CipherSuite       string               `json:"cipher_suite,omitempty"`
	CertSubject       string               `json:"cert_subject,omitempty"`
	CertIssuer        string               `json:"cert_issuer,omitempty"`
	CertExpiry        time.Time            `json:"cert_expiry,omitempty"`
	SelfSigned        bool                 `json:"self_signed"`
	Expired           bool                 `json:"expired"`
	WeakProtocol      bool                 `json:"weak_protocol"`
	SupportedVersions []string             `json:"supported_versions,omitempty"`
	CipherSuites      []CipherSuiteReport  `json:"cipher_suites,omitempty"`
	CertChain         []CertInfoReport     `json:"cert_chain,omitempty"`
	CertSAN           []string             `json:"cert_san,omitempty"`
	OCSPStatus        string               `json:"ocsp_status,omitempty"`
}

type CipherSuiteReport struct {
	Name     string `json:"name"`
	Strength string `json:"strength"`
	Secure   bool   `json:"secure"`
}

type CertInfoReport struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	KeyType    string    `json:"key_type"`
	KeySize    int       `json:"key_size"`
	SelfSigned bool      `json:"self_signed"`
}

type AuthReport struct {
	AnonymousAccess      bool                    `json:"anonymous_access"`
	AuthRequired         bool                    `json:"auth_required"`
	DefaultCredentials   bool                    `json:"default_credentials"`
	CredentialPattern    string                  `json:"credential_pattern,omitempty"`
	PrivilegeLevel       string                  `json:"privilege_level,omitempty"`
	AttemptsMade         int                     `json:"attempts_made"`
	MaxAttempts          int                     `json:"max_attempts"`
	Metadata             map[string]string       `json:"metadata,omitempty"`
	ErrorAnalysis        *ErrorAnalysisReport    `json:"error_analysis,omitempty"`
	ProtocolIssues       []ProtocolIssueReport   `json:"protocol_issues,omitempty"`
	SecondaryServices    []SecondaryServiceReport `json:"secondary_services,omitempty"`
}

type ErrorAnalysisReport struct {
	LeaksUserExists     bool   `json:"leaks_user_exists"`
	LeaksPasswordWrong  bool   `json:"leaks_password_wrong"`
	LeaksAuthCodes      bool   `json:"leaks_auth_codes"`
	CleartextEnabled    bool   `json:"cleartext_enabled"`
	DetailedErrors      bool   `json:"detailed_errors"`
}

type ProtocolIssueReport struct {
	Issue       string `json:"issue"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type SecondaryServiceReport struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Accessible  bool   `json:"accessible"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

type ConfigReport struct {
	DangerousSettings []DangerousSettingReport `json:"dangerous_settings,omitempty"`
	ExposureInfo      *ExposureReport          `json:"exposure_info,omitempty"`
}

type DangerousSettingReport struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type ExposureReport struct {
	PubliclyAccessible  bool `json:"publicly_accessible"`
	NonStandardPort     bool `json:"non_standard_port"`
	RemoteAccessEnabled bool `json:"remote_access_enabled"`
}

type VulnReport struct {
	CVEs             []CVEReport           `json:"cves,omitempty"`
	EOLVersion       *EOLReport            `json:"eol_version,omitempty"`
	NmapScriptOutput []NmapScriptReport    `json:"nmap_scripts,omitempty"`
	KnownVulnerable  []KnownVulnReport     `json:"known_vulnerable,omitempty"`
}

type CVEReport struct {
	ID          string `json:"id"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	CVSS        string `json:"cvss,omitempty"`
	Source      string `json:"source,omitempty"`
}

type EOLReport struct {
	Version     string `json:"version"`
	EOLDate     string `json:"eol_date"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
}

type NmapScriptReport struct {
	ScriptID string `json:"script_id"`
	Output   string `json:"output"`
}

type KnownVulnReport struct {
	Pattern     string   `json:"pattern"`
	CVEs        []string `json:"cves"`
	RiskLevel   string   `json:"risk_level"`
	Description string   `json:"description"`
}

type RiskAssessment struct {
	OverallRisk   RiskLevel       `json:"overall_risk"`
	RiskFactors   []RiskFactor    `json:"risk_factors"`
	Recommendations []string      `json:"recommendations"`
}

type RiskFactor struct {
	Factor      string    `json:"factor"`
	Risk        RiskLevel `json:"risk"`
	Description string    `json:"description"`
}

type ReportBuilder struct {
	scanInfo ScanInfo
	services []ServiceReport
	vulnDB   *nmap.VulnerabilityDB
}

func NewReportBuilder() *ReportBuilder {
	return &ReportBuilder{
		services: make([]ServiceReport, 0),
		vulnDB:   nmap.NewVulnerabilityDB(),
	}
}

func (rb *ReportBuilder) SetScanInfo(targets []string, ports []int, profile string, duration time.Duration, nmapVersion string) {
	rb.scanInfo = ScanInfo{
		Targets:      targets,
		PortsScanned: ports,
		ScanProfile:  profile,
		ScanDuration: duration,
		NmapVersion:  nmapVersion,
	}
}

func (rb *ReportBuilder) AddService(
	scanResult scanner.ScanResult,
	fpResult *fingerprint.ServiceInfo,
	nmapResult *nmap.NmapResult,
	authResult *auth.AuthResult,
	configResult *configcheck.ConfigResult,
) {
	svc := ServiceReport{}

	svc.Identification = Identification{
		Host:         scanResult.Host,
		Port:         scanResult.Port,
		Protocol:     "tcp",
		ServiceType:  scanResult.Service,
		StandardPort: scanner.IsStandardDBPort(scanResult.Port),
	}

	if !svc.Identification.StandardPort {
		svc.Identification.NonStandardNote = fmt.Sprintf("Service running on non-standard port %d", scanResult.Port)
	}

	if fpResult != nil {
		svc.Identification.ServiceType = fpResult.ServiceType
		svc.VersionTransport = VersionTransport{
			Version:         fpResult.Version,
			Edition:         fpResult.Edition,
			ProtocolVersion: fpResult.ProtocolVersion,
			TLSEnabled:      fpResult.IsTLS,
			TLSVersion:      fpResult.TLSVersion,
			ExtraInfo:       fpResult.ExtraInfo,
		}
	}

	if nmapResult != nil {
		if nmapResult.Version != "" && svc.VersionTransport.Version == "" {
			svc.VersionTransport.Version = nmapResult.Version
		}
		if nmapResult.Product != "" {
			svc.VersionTransport.ExtraInfo["product"] = nmapResult.Product
		}

		for _, cve := range nmapResult.CVEs {
			svc.Vulnerabilities.CVEs = append(svc.Vulnerabilities.CVEs, CVEReport{
				ID:          cve.ID,
				Severity:    cve.Severity,
				Description: cve.Description,
				CVSS:        cve.CVSS,
				Source:      cve.Source,
			})
		}

		for _, script := range nmapResult.Scripts {
			svc.Vulnerabilities.NmapScriptOutput = append(svc.Vulnerabilities.NmapScriptOutput, NmapScriptReport{
				ScriptID: script.ID,
				Output:   script.Output,
			})
		}
	}

	if authResult != nil {
		svc.Authentication = AuthReport{
			AnonymousAccess:    authResult.AnonymousAccess,
			AuthRequired:       authResult.AuthRequired,
			DefaultCredentials: authResult.SuccessfulLogin && authResult.Credential != nil,
			PrivilegeLevel:     authResult.PrivilegeLevel,
			AttemptsMade:       authResult.AttemptsMade,
			MaxAttempts:        authResult.MaxAttempts,
			Metadata:           authResult.Metadata,
		}

		if authResult.Credential != nil {
			svc.Authentication.CredentialPattern = authResult.Credential.String()
		}

		// Include error analysis
		if authResult.ErrorAnalysis != nil {
			svc.Authentication.ErrorAnalysis = &ErrorAnalysisReport{
				LeaksUserExists:    authResult.ErrorAnalysis.LeaksUserExists,
				LeaksPasswordWrong: authResult.ErrorAnalysis.LeaksPasswordWrong,
				LeaksAuthCodes:     authResult.ErrorAnalysis.LeaksAuthCodes,
				CleartextEnabled:   authResult.ErrorAnalysis.CleartextEnabled,
				DetailedErrors:     authResult.ErrorAnalysis.LeaksUserExists || authResult.ErrorAnalysis.LeaksPasswordWrong,
			}
		}

		// Include protocol issues
		for _, pi := range authResult.ProtocolIssues {
			svc.Authentication.ProtocolIssues = append(svc.Authentication.ProtocolIssues, ProtocolIssueReport{
				Issue:       pi.Issue,
				Risk:        pi.Risk,
				Description: pi.Description,
				Remediation: pi.Remediation,
			})
		}

		// Include secondary services
		for _, ss := range authResult.SecondaryServices {
			svc.Authentication.SecondaryServices = append(svc.Authentication.SecondaryServices, SecondaryServiceReport{
				Name:        ss.Name,
				Host:        ss.Host,
				Port:        ss.Port,
				Accessible:  ss.Accessible,
				Description: ss.Description,
				Risk:        ss.Risk,
			})
		}
	}

	if configResult != nil {
		svc.Configuration = ConfigReport{
			DangerousSettings: make([]DangerousSettingReport, 0),
		}

		for _, ds := range configResult.DangerousSettings {
			svc.Configuration.DangerousSettings = append(svc.Configuration.DangerousSettings, DangerousSettingReport{
				Name:        ds.Name,
				Value:       ds.Value,
				Risk:        ds.Risk,
				Description: ds.Description,
				Remediation: ds.Remediation,
			})
		}

		if configResult.ExposureInfo != nil {
			svc.Configuration.ExposureInfo = &ExposureReport{
				PubliclyAccessible:  configResult.ExposureInfo.PubliclyAccessible,
				NonStandardPort:     configResult.ExposureInfo.NonStandardPort,
				RemoteAccessEnabled: configResult.ExposureInfo.RemoteAccessEnabled,
			}
		}

		if configResult.TLSInfo != nil && configResult.TLSInfo.Supported {
			svc.VersionTransport.TLSEnabled = true
			svc.VersionTransport.TLSVersion = configResult.TLSInfo.Version
			svc.VersionTransport.TLSDetails = &TLSDetails{
				CipherSuite:       configResult.TLSInfo.CipherSuite,
				CertSubject:       configResult.TLSInfo.CertSubject,
				CertIssuer:        configResult.TLSInfo.CertIssuer,
				CertExpiry:        configResult.TLSInfo.CertExpiry,
				SelfSigned:        configResult.TLSInfo.SelfSigned,
				Expired:           configResult.TLSInfo.Expired,
				WeakProtocol:      configResult.TLSInfo.WeakProtocol,
				SupportedVersions: configResult.TLSInfo.SupportedVersions,
				CertSAN:           configResult.TLSInfo.CertSAN,
				OCSPStatus:        configResult.TLSInfo.OCSP,
			}

			// Add cipher suites
			for _, cs := range configResult.TLSInfo.CipherSuites {
				svc.VersionTransport.TLSDetails.CipherSuites = append(svc.VersionTransport.TLSDetails.CipherSuites, CipherSuiteReport{
					Name:     cs.Name,
					Strength: cs.Strength,
					Secure:   cs.Secure,
				})
			}

			// Add certificate chain
			for _, cert := range configResult.TLSInfo.CertChain {
				svc.VersionTransport.TLSDetails.CertChain = append(svc.VersionTransport.TLSDetails.CertChain, CertInfoReport{
					Subject:    cert.Subject,
					Issuer:     cert.Issuer,
					NotBefore:  cert.NotBefore,
					NotAfter:   cert.NotAfter,
					KeyType:    cert.KeyType,
					KeySize:    cert.KeySize,
					SelfSigned: cert.SelfSigned,
				})
			}
		}
	}

	if svc.VersionTransport.Version != "" {
		eol := rb.vulnDB.CheckEOL(svc.Identification.ServiceType, svc.VersionTransport.Version)
		if eol != nil {
			svc.Vulnerabilities.EOLVersion = &EOLReport{
				Version:     eol.Version,
				EOLDate:     eol.EOLDate,
				RiskLevel:   eol.RiskLevel,
				Description: eol.Description,
			}
		}

		vulns := rb.vulnDB.CheckKnownVulnerable(svc.Identification.ServiceType, svc.VersionTransport.Version)
		for _, v := range vulns {
			svc.Vulnerabilities.KnownVulnerable = append(svc.Vulnerabilities.KnownVulnerable, KnownVulnReport{
				Pattern:     v.VersionPattern,
				CVEs:        v.CVEs,
				RiskLevel:   v.RiskLevel,
				Description: v.Description,
			})
		}
	}

	svc.RiskAssessment = rb.calculateRisk(svc)

	rb.services = append(rb.services, svc)
}

func (rb *ReportBuilder) calculateRisk(svc ServiceReport) RiskAssessment {
	assessment := RiskAssessment{
		OverallRisk:     RiskInfo,
		RiskFactors:     make([]RiskFactor, 0),
		Recommendations: make([]string, 0),
	}

	if svc.Authentication.AnonymousAccess {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "Anonymous Access",
			Risk:        RiskCritical,
			Description: "Database is accessible without authentication",
		})
		assessment.Recommendations = append(assessment.Recommendations, "Enable authentication immediately")
	}

	if svc.Authentication.DefaultCredentials {
		risk := RiskHigh
		if svc.Authentication.PrivilegeLevel == "superuser" ||
			svc.Authentication.PrivilegeLevel == "sysadmin" ||
			svc.Authentication.PrivilegeLevel == "admin" {
			risk = RiskCritical
			assessment.Recommendations = append(assessment.Recommendations, "Change default credentials immediately - high privilege access detected")
		} else {
			assessment.Recommendations = append(assessment.Recommendations, "Change default credentials")
		}
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "Default Credentials",
			Risk:        risk,
			Description: fmt.Sprintf("Default credentials work with %s privilege level", svc.Authentication.PrivilegeLevel),
		})
	}

	if !svc.VersionTransport.TLSEnabled {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "Unencrypted Connection",
			Risk:        RiskHigh,
			Description: "Database connections are not encrypted",
		})
		assessment.Recommendations = append(assessment.Recommendations, "Enable TLS/SSL for database connections")
	}

	if svc.VersionTransport.TLSDetails != nil {
		if svc.VersionTransport.TLSDetails.WeakProtocol {
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "Weak TLS Protocol",
				Risk:        RiskHigh,
				Description: "Using outdated TLS protocol version",
			})
			assessment.Recommendations = append(assessment.Recommendations, "Upgrade to TLS 1.2 or higher")
		}
		if svc.VersionTransport.TLSDetails.Expired {
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "Expired Certificate",
				Risk:        RiskHigh,
				Description: "TLS certificate has expired",
			})
			assessment.Recommendations = append(assessment.Recommendations, "Renew TLS certificate")
		}
		if svc.VersionTransport.TLSDetails.SelfSigned {
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "Self-Signed Certificate",
				Risk:        RiskMedium,
				Description: "Using self-signed certificate",
			})
			assessment.Recommendations = append(assessment.Recommendations, "Consider using a certificate from a trusted CA")
		}
	}

	if svc.Configuration.ExposureInfo != nil && svc.Configuration.ExposureInfo.PubliclyAccessible {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "Public Exposure",
			Risk:        RiskHigh,
			Description: "Database is accessible from public IP addresses",
		})
		assessment.Recommendations = append(assessment.Recommendations, "Restrict access to trusted networks only")
	}

	// Error analysis risks
	if svc.Authentication.ErrorAnalysis != nil {
		ea := svc.Authentication.ErrorAnalysis
		if ea.LeaksUserExists {
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "Username Enumeration",
				Risk:        RiskMedium,
				Description: "Error messages reveal whether usernames exist",
			})
			assessment.Recommendations = append(assessment.Recommendations, "Configure database to return generic authentication error messages")
		}
		if ea.LeaksPasswordWrong {
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "Password Disclosure",
				Risk:        RiskMedium,
				Description: "Error messages confirm password validation separately from username",
			})
			assessment.Recommendations = append(assessment.Recommendations, "Use consistent error messages for all authentication failures")
		}
		if ea.CleartextEnabled {
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "Cleartext Authentication",
				Risk:        RiskHigh,
				Description: "Server allows cleartext authentication without encryption",
			})
			assessment.Recommendations = append(assessment.Recommendations, "Disable cleartext authentication and require TLS")
		}
	}

	// Protocol issues
	for _, pi := range svc.Authentication.ProtocolIssues {
		risk := RiskMedium
		if pi.Risk == "Critical" {
			risk = RiskCritical
		} else if pi.Risk == "High" {
			risk = RiskHigh
		}
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      pi.Issue,
			Risk:        risk,
			Description: pi.Description,
		})
		assessment.Recommendations = append(assessment.Recommendations, pi.Remediation)
	}

	// Secondary services
	for _, ss := range svc.Authentication.SecondaryServices {
		if ss.Accessible {
			risk := RiskMedium
			if ss.Risk == "Critical" {
				risk = RiskCritical
			} else if ss.Risk == "High" {
				risk = RiskHigh
			}
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      fmt.Sprintf("Exposed %s", ss.Name),
				Risk:        risk,
				Description: fmt.Sprintf("%s accessible on port %d", ss.Description, ss.Port),
			})
			assessment.Recommendations = append(assessment.Recommendations, fmt.Sprintf("Restrict access to %s (port %d)", ss.Name, ss.Port))
		}
	}

	if svc.Vulnerabilities.EOLVersion != nil {
		risk := RiskHigh
		if svc.Vulnerabilities.EOLVersion.RiskLevel == "Critical" {
			risk = RiskCritical
		}
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "End-of-Life Version",
			Risk:        risk,
			Description: svc.Vulnerabilities.EOLVersion.Description,
		})
		assessment.Recommendations = append(assessment.Recommendations, "Upgrade to a supported version")
	}

	for _, v := range svc.Vulnerabilities.KnownVulnerable {
		risk := RiskHigh
		if v.RiskLevel == "Critical" {
			risk = RiskCritical
		}
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "Known Vulnerabilities",
			Risk:        risk,
			Description: fmt.Sprintf("%s: %s", strings.Join(v.CVEs, ", "), v.Description),
		})
	}

	for _, cve := range svc.Vulnerabilities.CVEs {
		risk := RiskMedium
		if cve.Severity == "Critical" {
			risk = RiskCritical
		} else if cve.Severity == "High" {
			risk = RiskHigh
		}
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      cve.ID,
			Risk:        risk,
			Description: cve.Description,
		})
	}

	for _, ds := range svc.Configuration.DangerousSettings {
		risk := RiskMedium
		if ds.Risk == "Critical" {
			risk = RiskCritical
		} else if ds.Risk == "High" {
			risk = RiskHigh
		}
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      ds.Name,
			Risk:        risk,
			Description: ds.Description,
		})
		assessment.Recommendations = append(assessment.Recommendations, ds.Remediation)
	}

	assessment.OverallRisk = RiskInfo
	for _, rf := range assessment.RiskFactors {
		if rf.Risk == RiskCritical {
			assessment.OverallRisk = RiskCritical
			break
		} else if rf.Risk == RiskHigh && assessment.OverallRisk != RiskCritical {
			assessment.OverallRisk = RiskHigh
		} else if rf.Risk == RiskMedium && assessment.OverallRisk != RiskCritical && assessment.OverallRisk != RiskHigh {
			assessment.OverallRisk = RiskMedium
		} else if rf.Risk == RiskLow && assessment.OverallRisk == RiskInfo {
			assessment.OverallRisk = RiskLow
		}
	}

	return assessment
}

func (rb *ReportBuilder) Build() *ScanReport {
	report := &ScanReport{
		ScanInfo:    rb.scanInfo,
		Services:    rb.services,
		GeneratedAt: time.Now(),
	}

	report.Summary = rb.calculateSummary()

	return report
}

func (rb *ReportBuilder) calculateSummary() ScanSummary {
	summary := ScanSummary{
		ServiceTypes: make(map[string]int),
	}

	hosts := make(map[string]bool)
	for _, svc := range rb.services {
		hosts[svc.Identification.Host] = true
		summary.ServiceTypes[svc.Identification.ServiceType]++
		summary.OpenPorts++

		switch svc.RiskAssessment.OverallRisk {
		case RiskCritical:
			summary.CriticalFindings++
		case RiskHigh:
			summary.HighFindings++
		case RiskMedium:
			summary.MediumFindings++
		case RiskLow:
			summary.LowFindings++
		}
	}

	summary.TotalHosts = len(hosts)
	summary.TotalPorts = len(rb.scanInfo.PortsScanned) * summary.TotalHosts
	summary.ServicesFound = len(rb.services)

	return summary
}

func (r *ScanReport) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func (r *ScanReport) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║              DATABASE EXPOSURE SCANNER REPORT                    ║\n")
	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════════════╝\n\n")

	fmt.Fprintf(w, "SCAN INFORMATION\n")
	fmt.Fprintf(w, "────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(w, "  Targets:       %s\n", strings.Join(r.ScanInfo.Targets, ", "))
	fmt.Fprintf(w, "  Ports:         %d ports scanned\n", len(r.ScanInfo.PortsScanned))
	fmt.Fprintf(w, "  Profile:       %s\n", r.ScanInfo.ScanProfile)
	fmt.Fprintf(w, "  Duration:      %s\n", r.ScanInfo.ScanDuration.Round(time.Second))
	if r.ScanInfo.NmapVersion != "" {
		fmt.Fprintf(w, "  Nmap:          %s\n", r.ScanInfo.NmapVersion)
	}
	fmt.Fprintf(w, "  Generated:     %s\n\n", r.GeneratedAt.Format(time.RFC3339))

	fmt.Fprintf(w, "SUMMARY\n")
	fmt.Fprintf(w, "────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(w, "  Hosts Scanned:     %d\n", r.Summary.TotalHosts)
	fmt.Fprintf(w, "  Open Ports:        %d\n", r.Summary.OpenPorts)
	fmt.Fprintf(w, "  Services Found:    %d\n", r.Summary.ServicesFound)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  FINDINGS BY SEVERITY:\n")
	fmt.Fprintf(w, "    Critical:  %d\n", r.Summary.CriticalFindings)
	fmt.Fprintf(w, "    High:      %d\n", r.Summary.HighFindings)
	fmt.Fprintf(w, "    Medium:    %d\n", r.Summary.MediumFindings)
	fmt.Fprintf(w, "    Low:       %d\n", r.Summary.LowFindings)
	fmt.Fprintf(w, "\n")

	if len(r.Summary.ServiceTypes) > 0 {
		fmt.Fprintf(w, "  SERVICE TYPES:\n")
		types := make([]string, 0, len(r.Summary.ServiceTypes))
		for t := range r.Summary.ServiceTypes {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			fmt.Fprintf(w, "    %-15s %d\n", t+":", r.Summary.ServiceTypes[t])
		}
		fmt.Fprintf(w, "\n")
	}

	for i, svc := range r.Services {
		fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
		fmt.Fprintf(w, "SERVICE %d: %s:%d (%s)\n", i+1, svc.Identification.Host, svc.Identification.Port, svc.Identification.ServiceType)
		fmt.Fprintf(w, "Risk Level: %s\n", svc.RiskAssessment.OverallRisk)
		fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n\n")

		fmt.Fprintf(w, "  IDENTIFICATION\n")
		fmt.Fprintf(w, "  ──────────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(w, "    Host:           %s\n", svc.Identification.Host)
		fmt.Fprintf(w, "    Port:           %d/%s\n", svc.Identification.Port, svc.Identification.Protocol)
		fmt.Fprintf(w, "    Service:        %s\n", svc.Identification.ServiceType)
		if !svc.Identification.StandardPort {
			fmt.Fprintf(w, "    Warning:        %s\n", svc.Identification.NonStandardNote)
		}
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "  VERSION & TRANSPORT\n")
		fmt.Fprintf(w, "  ──────────────────────────────────────────────────────────────────\n")
		if svc.VersionTransport.Version != "" {
			fmt.Fprintf(w, "    Version:        %s\n", svc.VersionTransport.Version)
		}
		if svc.VersionTransport.Edition != "" {
			fmt.Fprintf(w, "    Edition:        %s\n", svc.VersionTransport.Edition)
		}
		if svc.VersionTransport.TLSEnabled {
			fmt.Fprintf(w, "    TLS:            Enabled (%s)\n", svc.VersionTransport.TLSVersion)
			if svc.VersionTransport.TLSDetails != nil {
				td := svc.VersionTransport.TLSDetails
				if td.CipherSuite != "" {
					fmt.Fprintf(w, "    Cipher Suite:   %s\n", td.CipherSuite)
				}
				if len(td.SupportedVersions) > 0 {
					fmt.Fprintf(w, "    Supported TLS:  %s\n", strings.Join(td.SupportedVersions, ", "))
				}
				if td.OCSPStatus != "" {
					fmt.Fprintf(w, "    OCSP:           %s\n", td.OCSPStatus)
				}
				if td.CertSubject != "" {
					fmt.Fprintf(w, "    Cert Subject:   %s\n", td.CertSubject)
				}
				if td.CertIssuer != "" {
					fmt.Fprintf(w, "    Cert Issuer:    %s\n", td.CertIssuer)
				}
				if !td.CertExpiry.IsZero() {
					expiryStatus := ""
					if td.Expired {
						expiryStatus = " (EXPIRED!)"
					} else if td.CertExpiry.Before(time.Now().AddDate(0, 1, 0)) {
						expiryStatus = " (expires soon!)"
					}
					fmt.Fprintf(w, "    Cert Expiry:    %s%s\n", td.CertExpiry.Format("2006-01-02"), expiryStatus)
				}
				if td.SelfSigned {
					fmt.Fprintf(w, "    Self-Signed:    YES\n")
				}
				if td.WeakProtocol {
					fmt.Fprintf(w, "    Weak Protocol:  YES\n")
				}
				if len(td.CertSAN) > 0 {
					fmt.Fprintf(w, "    Cert SANs:      %s\n", strings.Join(td.CertSAN[:min(5, len(td.CertSAN))], ", "))
					if len(td.CertSAN) > 5 {
						fmt.Fprintf(w, "                    ... and %d more\n", len(td.CertSAN)-5)
					}
				}
				// Show weak ciphers if any
				weakCiphers := []string{}
				for _, cs := range td.CipherSuites {
					if !cs.Secure || cs.Strength == "Weak" {
						weakCiphers = append(weakCiphers, cs.Name)
					}
				}
				if len(weakCiphers) > 0 {
					fmt.Fprintf(w, "    Weak Ciphers:   %d found\n", len(weakCiphers))
					for _, wc := range weakCiphers[:min(3, len(weakCiphers))] {
						fmt.Fprintf(w, "                    - %s\n", wc)
					}
					if len(weakCiphers) > 3 {
						fmt.Fprintf(w, "                    ... and %d more\n", len(weakCiphers)-3)
					}
				}
			}
		} else {
			fmt.Fprintf(w, "    TLS:            Disabled (UNENCRYPTED)\n")
		}
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "  AUTHENTICATION\n")
		fmt.Fprintf(w, "  ──────────────────────────────────────────────────────────────────\n")
		if svc.Authentication.AnonymousAccess {
			fmt.Fprintf(w, "    Anonymous:      YES (CRITICAL)\n")
		} else if svc.Authentication.AuthRequired {
			fmt.Fprintf(w, "    Anonymous:      No (auth required)\n")
		}
		if svc.Authentication.DefaultCredentials {
			fmt.Fprintf(w, "    Default Creds:  YES - %s\n", svc.Authentication.CredentialPattern)
			fmt.Fprintf(w, "    Privilege:      %s\n", svc.Authentication.PrivilegeLevel)
		}
		fmt.Fprintf(w, "    Attempts:       %d/%d\n", svc.Authentication.AttemptsMade, svc.Authentication.MaxAttempts)

		// Error analysis
		if svc.Authentication.ErrorAnalysis != nil {
			ea := svc.Authentication.ErrorAnalysis
			if ea.LeaksUserExists || ea.LeaksPasswordWrong || ea.CleartextEnabled {
				fmt.Fprintf(w, "\n    Error Analysis:\n")
				if ea.LeaksUserExists {
					fmt.Fprintf(w, "      [WARN] Username enumeration possible via error messages\n")
				}
				if ea.LeaksPasswordWrong {
					fmt.Fprintf(w, "      [WARN] Password validation leakage in error messages\n")
				}
				if ea.CleartextEnabled {
					fmt.Fprintf(w, "      [HIGH] Cleartext authentication enabled\n")
				}
			}
		}

		// Protocol issues
		if len(svc.Authentication.ProtocolIssues) > 0 {
			fmt.Fprintf(w, "\n    Protocol Issues:\n")
			for _, pi := range svc.Authentication.ProtocolIssues {
				fmt.Fprintf(w, "      [%s] %s\n", pi.Risk, pi.Issue)
				fmt.Fprintf(w, "             %s\n", pi.Description)
			}
		}

		// Secondary services
		if len(svc.Authentication.SecondaryServices) > 0 {
			fmt.Fprintf(w, "\n    Secondary Services:\n")
			for _, ss := range svc.Authentication.SecondaryServices {
				status := "Closed"
				if ss.Accessible {
					status = "OPEN"
				}
				fmt.Fprintf(w, "      [%s] %s (port %d) - %s\n", ss.Risk, ss.Name, ss.Port, status)
				fmt.Fprintf(w, "             %s\n", ss.Description)
			}
		}
		fmt.Fprintf(w, "\n")

		if len(svc.Configuration.DangerousSettings) > 0 {
			fmt.Fprintf(w, "  CONFIGURATION ISSUES\n")
			fmt.Fprintf(w, "  ──────────────────────────────────────────────────────────────────\n")
			for _, ds := range svc.Configuration.DangerousSettings {
				fmt.Fprintf(w, "    [%s] %s = %s\n", ds.Risk, ds.Name, ds.Value)
				fmt.Fprintf(w, "           %s\n", ds.Description)
			}
			fmt.Fprintf(w, "\n")
		}

		if len(svc.Vulnerabilities.CVEs) > 0 || svc.Vulnerabilities.EOLVersion != nil || len(svc.Vulnerabilities.KnownVulnerable) > 0 {
			fmt.Fprintf(w, "  VULNERABILITIES\n")
			fmt.Fprintf(w, "  ──────────────────────────────────────────────────────────────────\n")

			if svc.Vulnerabilities.EOLVersion != nil {
				fmt.Fprintf(w, "    [EOL] %s\n", svc.Vulnerabilities.EOLVersion.Description)
			}

			for _, v := range svc.Vulnerabilities.KnownVulnerable {
				fmt.Fprintf(w, "    [%s] %s\n", v.RiskLevel, v.Description)
				fmt.Fprintf(w, "           CVEs: %s\n", strings.Join(v.CVEs, ", "))
			}

			for _, cve := range svc.Vulnerabilities.CVEs {
				fmt.Fprintf(w, "    [%s] %s\n", cve.Severity, cve.ID)
				if cve.Description != "" {
					fmt.Fprintf(w, "           %s\n", cve.Description)
				}
			}
			fmt.Fprintf(w, "\n")
		}

		if len(svc.RiskAssessment.Recommendations) > 0 {
			fmt.Fprintf(w, "  RECOMMENDATIONS\n")
			fmt.Fprintf(w, "  ──────────────────────────────────────────────────────────────────\n")
			for _, rec := range svc.RiskAssessment.Recommendations {
				fmt.Fprintf(w, "    • %s\n", rec)
			}
			fmt.Fprintf(w, "\n")
		}
	}

	fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║                         END OF REPORT                            ║\n")
	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════════════╝\n")

	return nil
}
