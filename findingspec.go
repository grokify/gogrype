package gogrype

import (
	"fmt"
	"strings"

	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// FindingSpecOptions configures conversion of Grype output to findingspec.
type FindingSpecOptions struct {
	// Image, when set, marks findings as a container scan (type "container")
	// and is recorded on each finding's artifact. Empty means a dependency
	// (SCA) scan (type "sca").
	Image string
	// ImageDigest is the scanned image digest (e.g. "sha256:…"), optional.
	ImageDigest string
	// Repo sets Location.Repo for multi-repo/workspace sweeps, optional.
	Repo string
}

// Findings converts the Grype output into a findingspec.FindingSet of normalized
// security vulnerability findings.
func (g *GrypeOutputJSON) Findings(opts FindingSpecOptions) *findingspec.FindingSet {
	set := findingspec.NewFindingSet()
	for _, m := range g.Matches {
		set.Add(m.ToFinding(opts))
	}
	return set
}

// ToFinding converts a single Grype match into a findingspec.Finding.
func (m Match) ToFinding(opts FindingSpecOptions) findingspec.Finding {
	v := m.Vulnerability
	a := m.Artifact
	cvss := bestCVSS(v.CVSS)

	var score float64
	if cvss != nil {
		score = cvss.Score
	}

	vuln := security.Vulnerability{
		ID:          fmt.Sprintf("%s:%s@%s", v.ID, a.Name, a.Version),
		Title:       vulnTitle(v.ID, a.Name),
		Description: v.Description,
		CVEs:        cveIDs(v.ID),
		CVSS:        cvss,
		Severity:    security.SeverityOrCVSS(v.Severity, score),
		Package: &security.Package{
			Name:      a.Name,
			Version:   a.Version,
			Ecosystem: a.Type,
		},
		Fix:        fixFrom(v.Fix),
		Component:  a.Name + "@" + a.Version,
		References: referencesFrom(v),
	}
	if opts.Repo != "" {
		vuln.Location = &findingspec.Location{Repo: opts.Repo}
	}
	if opts.Image != "" {
		vuln.Artifact = &security.Artifact{Image: opts.Image, ImageDigest: opts.ImageDigest}
		vuln.Type = security.TypeContainer
	} else {
		vuln.Type = security.TypeSCA
	}

	f := vuln.ToFinding()
	f.RuleID = v.ID // preserve the scanner's vuln ID (CVE, GHSA, ALAS, …)
	f.Source = findingspec.Source{Tool: "grype", RuleSet: v.Namespace}
	return f
}

func vulnTitle(id, pkg string) string {
	switch {
	case id != "" && pkg != "":
		return fmt.Sprintf("%s in %s", id, pkg)
	case id != "":
		return id
	default:
		return "Vulnerability"
	}
}

// cveIDs returns the vuln ID as a CVE list only when it is a CVE identifier.
func cveIDs(id string) []string {
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return []string{id}
	}
	return nil
}

// bestCVSS selects the highest-scoring CVSS entry and maps it to security.CVSS.
func bestCVSS(list []CVSS) *security.CVSS {
	var best *CVSS
	for i := range list {
		if best == nil || list[i].Metrics.BaseScore > best.Metrics.BaseScore {
			best = &list[i]
		}
	}
	if best == nil {
		return nil
	}
	return &security.CVSS{
		Version: best.Version,
		Vector:  best.Vector,
		Score:   float64(best.Metrics.BaseScore),
	}
}

func fixFrom(fix Fix) *security.Fix {
	if len(fix.Versions) == 0 && fix.State == "" {
		return nil
	}
	return &security.Fix{
		State:    fixState(fix.State),
		Versions: fix.Versions,
	}
}

func fixState(s string) security.FixState {
	switch strings.ToLower(s) {
	case "fixed":
		return security.FixStateFixed
	case "not-fixed":
		return security.FixStateNotFixed
	case "wont-fix":
		return security.FixStateWontFix
	default:
		return security.FixStateUnknown
	}
}

func referencesFrom(v Vulnerability) []findingspec.Reference {
	var refs []findingspec.Reference
	if v.DataSource != "" {
		refs = append(refs, findingspec.Reference{Title: v.Namespace, URL: v.DataSource})
	}
	for _, u := range v.URLs {
		refs = append(refs, findingspec.Reference{URL: u})
	}
	return refs
}
