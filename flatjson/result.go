package flatjson

import (
	"sort"
	"strings"

	"github.com/grokify/mogo/type/maputil"
	"github.com/grokify/mogo/type/slicesutil"
)

type Results []Result

func (res Results) LocationVulnerabilityIDs() []string {
	locvulns := []string{}
	for _, r := range res {
		locvulns = append(locvulns, r.LocationVulnerabilityID())
	}
	locvulns = slicesutil.Dedupe(locvulns)
	sort.Strings(locvulns)
	return locvulns
}

// VulnerabilityIDCounts count of unique VulerabiltyIDs
func (res Results) VulnerabilityIDCounts() map[string]int {
	out := map[string]int{}
	for _, r := range res {
		out[r.VulnerabilityID]++
	}
	return out
}

func (res Results) UniqueCount() int {
	out := 0
	seen := map[string]int{}
	for _, r := range res {
		if _, ok := seen[r.VulnerabilityID]; ok {
			out++
		}
		seen[r.VulnerabilityID]++
	}
	return out
}

func (res Results) SeverityCounts(unique bool) map[string]int {
	seen := map[string]int{}
	out := map[string]int{}
	for _, r := range res {
		if unique {
			if _, ok := seen[r.VulnerabilityID]; ok {
				continue
			}
		}
		out[r.Severity]++
		seen[r.VulnerabilityID]++
	}
	return out
}

func (res Results) SeverityCountsByLocationVulnerabilityID() map[string]int {
	m1 := map[string]map[string]int{}
	m2 := map[string]int{}
	for _, r := range res {
		sev := r.Severity
		lvid := r.LocationVulnerabilityID()
		if _, ok := m1[sev]; !ok {
			m1[sev] = map[string]int{}
		}
		m1[sev][lvid]++
	}
	for sev, mx := range m1 {
		m2[sev] = len(mx)
	}
	return m2
}

func (res Results) SeverityNames() []string {
	m := map[string]int{}
	for _, r := range res {
		m[r.Severity]++
	}
	return maputil.Keys(m)
}

func (res Results) Stats() Stats {
	return Stats{
		TotalCount:                    len(res),
		UniqueCountVulnID:             len(res.VulnerabilityIDCounts()),
		UniqueCountLocVulnID:          len(res.LocationVulnerabilityIDs()),
		SeverityCounts:                res.SeverityCounts(false),
		SeverityCountsUniqueVulnID:    res.SeverityCounts(true),
		SeverityCountsUniqueLocVulnID: res.SeverityCountsByLocationVulnerabilityID(),
	}
}

type Result struct {
	VulnerabilityID   string `json:"vulnerabilityId"`
	CVE               string `json:"cve"`
	Context           string `json:"context"`
	Digest            string `json:"digest"`
	LastSeen          string `json:"lastSeen"`
	Tags              string `json:"tags"`
	Link              string `json:"link"`
	ArtifactName      string `json:"artifactName"`
	ArtifactVersion   string `json:"artifactVersion"`
	ArtifactType      string `json:"artifactType"`
	ArtifactLocation  string `json:"artifactLocation"`
	Namespace         string `json:"namespace"`
	Severity          string `json:"severity"`
	FixedIn           string `json:"fixedIn"`
	FixObservedAt     string `json:"fixObservedAt"`
	InventoryType     string `json:"inventoryType"`
	InheritedFromBase bool   `json:"inheritedFromBase"`
	Account           string `json:"account"`
}

func (r Result) LocationVulnerabilityID() string {
	return strings.Join(
		[]string{
			strings.TrimSpace(r.ArtifactLocation),
			strings.TrimSpace(r.VulnerabilityID)},
		"#")
}
