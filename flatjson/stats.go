package flatjson

import (
	"cmp"
	"slices"
)

type StatsSlice []Stats

type Stats struct {
	ReferenceName                 string
	TotalCount                    int
	UniqueCountVulnID             int
	UniqueCountLocVulnID          int
	SeverityCounts                map[string]int
	SeverityCountsUniqueVulnID    map[string]int
	SeverityCountsUniqueLocVulnID map[string]int
}

func (ss StatsSlice) Sort() {
	slices.SortFunc(ss, func(a, b Stats) int {
		return cmp.Compare(a.ReferenceName, b.ReferenceName)
	})
}
