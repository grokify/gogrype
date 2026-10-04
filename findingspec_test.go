package gogrype

import (
	"testing"

	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

func sampleOutput() *GrypeOutputJSON {
	return &GrypeOutputJSON{Matches: Matches{
		{
			Vulnerability: Vulnerability{
				ID:          "CVE-2024-1234",
				Severity:    "High",
				Description: "A flaw in openssl",
				Namespace:   "nvd:cpe",
				DataSource:  "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
				URLs:        []string{"https://example.com/advisory"},
				CVSS: []CVSS{
					{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L", Metrics: CVSSMetrics{BaseScore: 7.5}},
				},
				Fix: Fix{State: "fixed", Versions: []string{"1.1.1w"}},
			},
			Artifact: Artifact{Name: "openssl", Version: "1.1.1k", Type: "apk"},
		},
		{
			Vulnerability: Vulnerability{ID: "GHSA-xxxx", Severity: "Negligible"},
			Artifact:      Artifact{Name: "left-pad", Version: "1.0.0", Type: "npm"},
		},
	}}
}

func TestFindings(t *testing.T) {
	set := sampleOutput().Findings(FindingSpecOptions{Image: "alpine:3.19", ImageDigest: "sha256:abc", Repo: "acme/app"})
	if set.Len() != 2 {
		t.Fatalf("Len = %d; want 2", set.Len())
	}

	for _, f := range set.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.Domain != findingspec.DomainSecurity || f.Type != security.TypeContainer {
			t.Errorf("domain/type = %s/%s; want security/container", f.Domain, f.Type)
		}
		if f.Source.Tool != "grype" {
			t.Errorf("source = %q; want grype", f.Source.Tool)
		}
	}

	first := set.Findings[0]
	if first.RuleID != "CVE-2024-1234" {
		t.Errorf("ruleID = %q; want CVE-2024-1234", first.RuleID)
	}
	if first.Severity != findingspec.SeverityHigh {
		t.Errorf("severity = %q; want high", first.Severity)
	}
	// "Negligible" normalizes to informational.
	if got := set.Findings[1].Severity; got != findingspec.SeverityInformational {
		t.Errorf("negligible severity = %q; want informational", got)
	}

	d, err := findingspec.DetailAs[security.VulnerabilityDetail](first)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if d.Package == nil || d.Package.Name != "openssl" || d.Package.Ecosystem != "apk" {
		t.Errorf("package detail = %+v", d.Package)
	}
	if d.CVSS == nil || d.CVSS.Score != 7.5 {
		t.Errorf("cvss detail = %+v", d.CVSS)
	}
	if d.Fix == nil || d.Fix.State != security.FixStateFixed || len(d.Fix.Versions) != 1 {
		t.Errorf("fix detail = %+v", d.Fix)
	}
	if d.Artifact == nil || d.Artifact.Image != "alpine:3.19" {
		t.Errorf("artifact detail = %+v", d.Artifact)
	}
}
