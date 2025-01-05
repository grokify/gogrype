package gogrype

type CVSS struct {
	Version        string         `json:"version"`
	Vector         string         `json:"vector"`
	Metrics        CVSSMetrics    `json:"metrics"`
	VendorMetadata VendorMetadata `json:"vendorMetadata"`
}

type CVSSMetrics struct {
	BaseScore           float32 `json:"baseScore"`
	ExploitabilityScore float32 `json:"exploitabilityScore"`
	ImpactScore         float32 `json:"impactScore"`
}

type VendorMetadata struct {
	BaseSeverity string `json:"base_severity"`
	Status       string `json:"status"`
}
