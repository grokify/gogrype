package flatjson

import (
	"encoding/json"
	"os"
	"time"
)

type File struct {
	Metadata Metadata `json:"metadata"`
	Results  Results  `json:"results"`
}

func (f File) Stats() Stats {
	stats := f.Results.Stats()
	stats.ReferenceName = f.Metadata.Filters.ImageContext
	return stats
}

func ParseFile(filename string) (File, error) {
	res := File{}
	b, err := os.ReadFile(filename)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(b, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

type Metadata struct {
	ReportType   string          `json:"reportType"`
	ReportID     string          `json:"reportId"`
	ReportName   string          `json:"reportName"`
	Description  string          `json:"description"`
	CreatedAtUTC *time.Time      `json:"createdAtUTC"`
	Filters      MetadataFilters `json:"filters"`
}

type MetadataFilters struct {
	ImageContext          string     `json:"image.context"`
	IsGlobal              bool       `json:"isGlobal"`
	ResultsID             string     `json:"resultsId"`
	ResultsGeneratedAtUTC *time.Time `json:"resultsGeneratedAtUTC"`
}
