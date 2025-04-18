package gogrype

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/govex"
	"github.com/grokify/mogo/errors/errorsutil"
	"github.com/grokify/mogo/text/markdown"
)

type GrypeOutputJSON struct {
	Matches Matches `json:"matches"`
}

func ReadFileGrypeOutputJSON(filename string) (*GrypeOutputJSON, error) {
	out := GrypeOutputJSON{}
	if b, err := os.ReadFile(filename); err != nil {
		return nil, errorsutil.Wrapf(err, "ReadFileGrypeOutputJSON{os.ReadFile(\"%s\")}", filename)
	} else if err := json.Unmarshal(b, &out); err != nil {
		return nil, errorsutil.Wrapf(err, "ReadFileGrypeOutputJSON{json.Unmarshal} - filename: %s", filename)
	} else {
		return &out, nil
	}
}

func (out GrypeOutputJSON) Len() int {
	return len(out.Matches)
}

func (out GrypeOutputJSON) GoVEXes() govex.Vulnerabilities {
	vulns := govex.Vulnerabilities{}
	for _, m := range out.Matches {
		vulns = append(vulns, m.GoVex())
	}
	return vulns
}

type Matches []Match

func (ms Matches) Table(colDefs *table.ColumnDefinitionSet) *table.Table {
	if colDefs == nil || len(colDefs.Definitions) == 0 {
		cds := DefaultTableColumnDefinitionSet()
		colDefs = &cds
	}
	tbl := table.NewTable("")
	tbl.LoadColumnDefinitionSet(*colDefs)

	for _, m := range ms {
		tbl.Rows = append(tbl.Rows, m.Slice(tbl.Columns))
	}
	return &tbl
}

func (ms Matches) WriteFileXLSX(filename string, colDefs *table.ColumnDefinitionSet) error {
	tbl := ms.Table(colDefs)
	if tbl == nil {
		return errors.New("table cannot be nil")
	}
	return tbl.WriteXLSX(filename, "Vulnerabilities")
}

type Match struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Artifact      Artifact      `json:"artifact"`
}

func (m Match) GoVex() govex.Vulnerability {
	vn := govex.Vulnerability{
		ID:       m.Vulnerability.ID,
		Name:     m.Vulnerability.Description,
		Severity: m.Vulnerability.Severity,
		Library: govex.Library{
			Name:    strings.TrimSpace(m.Artifact.Name),
			Version: strings.TrimSpace(m.Artifact.Version),
			Type:    strings.TrimSpace(m.Artifact.Type),
		},
	}
	if vn.Library.Name != "" {
		vn.Category = govex.CategorySCA
	}
	for _, u := range m.Vulnerability.URLs {
		vn.ReferenceURL = u
		break
	}
	for _, ver := range m.Vulnerability.Fix.Versions {
		vn.Library.VersionFixed = ver
		break
	}
	for i, cvss := range m.Vulnerability.CVSS {
		if i == len(m.Vulnerability.CVSS)-1 {
			vn.CVSS3Vector = cvss.Vector
			vn.CVSS3Score = &cvss.Metrics.BaseScore
			break
		}
	}
	return vn
}

type Vulnerability struct {
	ID          string   `json:"id"`
	CVSS        []CVSS   `json:"cvss"`
	DataSource  string   `json:"dataSource"`
	Description string   `json:"description"`
	Fix         Fix      `json:"fix"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	URLs        []string `json:"urls"`
}

func (v Vulnerability) IDLinkMarkdown() string {
	id := strings.TrimSpace(v.ID)
	if id == "" {
		return ""
	}
	u := strings.TrimSpace(v.DataSource)
	if u == "" {
		return id
	}
	return markdown.Linkify(u, id)
}

const StateFixed = "fixed"

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

func (f Fix) VersionsFixed() []string {
	if f.State == StateFixed {
		return slices.Clone(f.Versions)
	} else {
		return []string{}
	}
}

type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func DefaultTableColumnDefinitionSet() table.ColumnDefinitionSet {
	return table.BuildColumnDefinitionSet(
		[]string{
			KeyArtifactName,
			KeyArtifactVersion,
			KeyVulnerabilityFixVersions,
			KeyArtifactType,
			KeyVulnerabilityIDLinkMD,
			KeyVulnerabilitySeverity,
		},
		map[int]string{
			-1: table.FormatString,
			4:  table.FormatURL,
		},
	)
}

const (
	KeyArtifactName             = "artifact_name"
	KeyArtifactVersion          = "artifact_version"
	KeyArtifactType             = "artifact_type"
	KeyVulnerabilityID          = "vulnerability_id"
	KeyVulnerabilityIDLinkMD    = "vulnerability_id_link_markdown"
	KeyVulnerabilityFixVersions = "vulnerability_fix_versions"
	KeyVulnerabiltyNVDURL       = "vulnerability_nvd_url"
	KeyVulnerabilitySeverity    = "vulnerability_severity"
)

func (m Match) Slice(keys []string) []string {
	var s []string
	for _, key := range keys {
		s = append(s, m.Get(key))
	}
	return s
}

func (m Match) Get(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case KeyArtifactName:
		return m.Artifact.Name
	case KeyArtifactVersion:
		return m.Artifact.Version
	case KeyVulnerabilityFixVersions:
		return strings.Join(m.Vulnerability.Fix.VersionsFixed(), ", ")
	case KeyArtifactType:
		return m.Artifact.Type
	case KeyVulnerabilityID:
		return m.Vulnerability.ID
	case KeyVulnerabilityIDLinkMD:
		return m.Vulnerability.IDLinkMarkdown()
	case KeyVulnerabiltyNVDURL:
		return m.Vulnerability.DataSource
	case KeyVulnerabilitySeverity:
		return m.Vulnerability.Severity
	default:
		return ""
	}
}
