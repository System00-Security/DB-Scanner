package nmap

type VulnerabilityDB struct {
	EOLVersions      map[string][]EOLVersion
	KnownVulnerable  map[string][]VulnerableVersion
}

type EOLVersion struct {
	Version     string
	EOLDate     string
	RiskLevel   string
	Description string
}

type VulnerableVersion struct {
	VersionPattern string
	CVEs           []string
	RiskLevel      string
	Description    string
}

func NewVulnerabilityDB() *VulnerabilityDB {
	db := &VulnerabilityDB{
		EOLVersions:     make(map[string][]EOLVersion),
		KnownVulnerable: make(map[string][]VulnerableVersion),
	}

	db.loadEOLVersions()
	db.loadKnownVulnerable()

	return db
}

func (db *VulnerabilityDB) loadEOLVersions() {
	db.EOLVersions["mysql"] = []EOLVersion{
		{Version: "5.0", EOLDate: "2012-01-09", RiskLevel: "Critical", Description: "MySQL 5.0 is end-of-life since January 2012"},
		{Version: "5.1", EOLDate: "2013-12-31", RiskLevel: "Critical", Description: "MySQL 5.1 is end-of-life since December 2013"},
		{Version: "5.5", EOLDate: "2018-12-31", RiskLevel: "Critical", Description: "MySQL 5.5 is end-of-life since December 2018"},
		{Version: "5.6", EOLDate: "2021-02-05", RiskLevel: "High", Description: "MySQL 5.6 is end-of-life since February 2021"},
		{Version: "5.7", EOLDate: "2023-10-31", RiskLevel: "High", Description: "MySQL 5.7 is end-of-life since October 2023"},
	}

	db.EOLVersions["mariadb"] = []EOLVersion{
		{Version: "5.5", EOLDate: "2020-04-11", RiskLevel: "Critical", Description: "MariaDB 5.5 is end-of-life since April 2020"},
		{Version: "10.0", EOLDate: "2019-03-31", RiskLevel: "Critical", Description: "MariaDB 10.0 is end-of-life since March 2019"},
		{Version: "10.1", EOLDate: "2020-10-17", RiskLevel: "Critical", Description: "MariaDB 10.1 is end-of-life since October 2020"},
		{Version: "10.2", EOLDate: "2022-05-23", RiskLevel: "High", Description: "MariaDB 10.2 is end-of-life since May 2022"},
		{Version: "10.3", EOLDate: "2023-05-25", RiskLevel: "High", Description: "MariaDB 10.3 is end-of-life since May 2023"},
	}

	db.EOLVersions["postgresql"] = []EOLVersion{
		{Version: "9.0", EOLDate: "2015-10-08", RiskLevel: "Critical", Description: "PostgreSQL 9.0 is end-of-life since October 2015"},
		{Version: "9.1", EOLDate: "2016-10-27", RiskLevel: "Critical", Description: "PostgreSQL 9.1 is end-of-life since October 2016"},
		{Version: "9.2", EOLDate: "2017-11-09", RiskLevel: "Critical", Description: "PostgreSQL 9.2 is end-of-life since November 2017"},
		{Version: "9.3", EOLDate: "2018-11-08", RiskLevel: "Critical", Description: "PostgreSQL 9.3 is end-of-life since November 2018"},
		{Version: "9.4", EOLDate: "2020-02-13", RiskLevel: "Critical", Description: "PostgreSQL 9.4 is end-of-life since February 2020"},
		{Version: "9.5", EOLDate: "2021-02-11", RiskLevel: "Critical", Description: "PostgreSQL 9.5 is end-of-life since February 2021"},
		{Version: "9.6", EOLDate: "2021-11-11", RiskLevel: "High", Description: "PostgreSQL 9.6 is end-of-life since November 2021"},
		{Version: "10", EOLDate: "2022-11-10", RiskLevel: "High", Description: "PostgreSQL 10 is end-of-life since November 2022"},
		{Version: "11", EOLDate: "2023-11-09", RiskLevel: "High", Description: "PostgreSQL 11 is end-of-life since November 2023"},
	}

	db.EOLVersions["mssql"] = []EOLVersion{
		{Version: "2008", EOLDate: "2019-07-09", RiskLevel: "Critical", Description: "SQL Server 2008 is end-of-life since July 2019"},
		{Version: "2008 R2", EOLDate: "2019-07-09", RiskLevel: "Critical", Description: "SQL Server 2008 R2 is end-of-life since July 2019"},
		{Version: "2012", EOLDate: "2022-07-12", RiskLevel: "High", Description: "SQL Server 2012 is end-of-life since July 2022"},
		{Version: "2014", EOLDate: "2024-07-09", RiskLevel: "Medium", Description: "SQL Server 2014 extended support ends July 2024"},
	}

	db.EOLVersions["mongodb"] = []EOLVersion{
		{Version: "2.6", EOLDate: "2016-10-01", RiskLevel: "Critical", Description: "MongoDB 2.6 is end-of-life since October 2016"},
		{Version: "3.0", EOLDate: "2018-02-01", RiskLevel: "Critical", Description: "MongoDB 3.0 is end-of-life since February 2018"},
		{Version: "3.2", EOLDate: "2018-09-01", RiskLevel: "Critical", Description: "MongoDB 3.2 is end-of-life since September 2018"},
		{Version: "3.4", EOLDate: "2020-01-31", RiskLevel: "Critical", Description: "MongoDB 3.4 is end-of-life since January 2020"},
		{Version: "3.6", EOLDate: "2021-04-30", RiskLevel: "Critical", Description: "MongoDB 3.6 is end-of-life since April 2021"},
		{Version: "4.0", EOLDate: "2022-04-30", RiskLevel: "High", Description: "MongoDB 4.0 is end-of-life since April 2022"},
		{Version: "4.2", EOLDate: "2023-04-30", RiskLevel: "High", Description: "MongoDB 4.2 is end-of-life since April 2023"},
	}

	db.EOLVersions["redis"] = []EOLVersion{
		{Version: "2.", EOLDate: "2015-01-01", RiskLevel: "Critical", Description: "Redis 2.x is severely outdated and unsupported"},
		{Version: "3.", EOLDate: "2018-01-01", RiskLevel: "Critical", Description: "Redis 3.x is outdated and unsupported"},
		{Version: "4.", EOLDate: "2020-01-01", RiskLevel: "High", Description: "Redis 4.x is outdated"},
		{Version: "5.", EOLDate: "2022-01-01", RiskLevel: "Medium", Description: "Redis 5.x is approaching end-of-life"},
	}

	db.EOLVersions["oracle"] = []EOLVersion{
		{Version: "11.2", EOLDate: "2020-12-31", RiskLevel: "Critical", Description: "Oracle Database 11g R2 is end-of-life since December 2020"},
		{Version: "12.1", EOLDate: "2022-07-31", RiskLevel: "High", Description: "Oracle Database 12c R1 is end-of-life since July 2022"},
	}

	db.EOLVersions["elasticsearch"] = []EOLVersion{
		{Version: "5.", EOLDate: "2019-03-11", RiskLevel: "Critical", Description: "Elasticsearch 5.x is end-of-life since March 2019"},
		{Version: "6.", EOLDate: "2022-02-10", RiskLevel: "High", Description: "Elasticsearch 6.x is end-of-life since February 2022"},
	}
}

func (db *VulnerabilityDB) loadKnownVulnerable() {
	db.KnownVulnerable["mysql"] = []VulnerableVersion{
		{
			VersionPattern: "5.5.",
			CVEs:           []string{"CVE-2012-2122", "CVE-2016-6662", "CVE-2016-6663"},
			RiskLevel:      "Critical",
			Description:    "Multiple critical vulnerabilities including authentication bypass",
		},
		{
			VersionPattern: "5.6.0",
			CVEs:           []string{"CVE-2016-6662"},
			RiskLevel:      "Critical",
			Description:    "Remote code execution vulnerability",
		},
	}

	db.KnownVulnerable["postgresql"] = []VulnerableVersion{
		{
			VersionPattern: "9.3",
			CVEs:           []string{"CVE-2019-10164"},
			RiskLevel:      "High",
			Description:    "Stack buffer overflow vulnerability",
		},
	}

	db.KnownVulnerable["mongodb"] = []VulnerableVersion{
		{
			VersionPattern: "2.6",
			CVEs:           []string{"CVE-2015-1609", "CVE-2015-7882"},
			RiskLevel:      "Critical",
			Description:    "Multiple vulnerabilities including authentication bypass",
		},
		{
			VersionPattern: "3.4",
			CVEs:           []string{"CVE-2019-2389"},
			RiskLevel:      "High",
			Description:    "Incorrect scoping of kill operations",
		},
	}

	db.KnownVulnerable["redis"] = []VulnerableVersion{
		{
			VersionPattern: "3.2",
			CVEs:           []string{"CVE-2018-11218", "CVE-2018-11219"},
			RiskLevel:      "Critical",
			Description:    "Integer overflow and heap corruption vulnerabilities",
		},
		{
			VersionPattern: "5.0",
			CVEs:           []string{"CVE-2020-14147"},
			RiskLevel:      "High",
			Description:    "Integer overflow vulnerability",
		},
	}

	db.KnownVulnerable["mssql"] = []VulnerableVersion{
		{
			VersionPattern: "2008",
			CVEs:           []string{"CVE-2012-2122", "CVE-2014-1820"},
			RiskLevel:      "Critical",
			Description:    "Multiple critical vulnerabilities in outdated version",
		},
	}

	db.KnownVulnerable["elasticsearch"] = []VulnerableVersion{
		{
			VersionPattern: "1.",
			CVEs:           []string{"CVE-2014-3120", "CVE-2015-1427"},
			RiskLevel:      "Critical",
			Description:    "Remote code execution via dynamic scripting",
		},
		{
			VersionPattern: "5.",
			CVEs:           []string{"CVE-2018-3831"},
			RiskLevel:      "High",
			Description:    "Path traversal vulnerability",
		},
	}
}

func (db *VulnerabilityDB) CheckEOL(service, version string) *EOLVersion {
	if version == "" {
		return nil
	}

	eolVersions, ok := db.EOLVersions[service]
	if !ok {
		return nil
	}

	for _, eol := range eolVersions {
		if versionMatches(version, eol.Version) {
			return &eol
		}
	}

	return nil
}

func (db *VulnerabilityDB) CheckKnownVulnerable(service, version string) []VulnerableVersion {
	if version == "" {
		return nil
	}

	vulnVersions, ok := db.KnownVulnerable[service]
	if !ok {
		return nil
	}

	matches := make([]VulnerableVersion, 0)
	for _, vuln := range vulnVersions {
		if versionMatches(version, vuln.VersionPattern) {
			matches = append(matches, vuln)
		}
	}

	return matches
}

func versionMatches(version, pattern string) bool {
	if len(pattern) == 0 {
		return false
	}

	if pattern[len(pattern)-1] == '.' {
		return len(version) >= len(pattern) && version[:len(pattern)] == pattern
	}

	return version == pattern || (len(version) > len(pattern) && version[:len(pattern)+1] == pattern+".")
}
