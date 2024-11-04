package gogrype

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/grokify/gocharts/v2/data/table"
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

type Matches []Match

func (ms Matches) Table(colDefs *table.ColumnDefinitions) *table.Table {
	if colDefs == nil || len(colDefs.Definitions) == 0 {
		cds := DefaultTableColumnDefinitions()
		colDefs = &cds
	}
	tbl := table.NewTable("")
	tbl.LoadColumnDefinitions(colDefs)

	for _, m := range ms {
		tbl.Rows = append(tbl.Rows, m.Slice(tbl.Columns))
	}
	return &tbl
}

func (ms Matches) WriteFileXLSX(filename string, colDefs *table.ColumnDefinitions) error {
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

type Vulnerability struct {
	ID          string   `json:"id"`
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

func DefaultTableColumnDefinitions() table.ColumnDefinitions {
	return table.BuildColumnDefinitions(
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
