package flatjson

import (
	"path/filepath"
	"regexp"
	"sort"

	"github.com/grokify/mogo/os/osutil"
	"github.com/grokify/mogo/type/slicesutil"
)

type Files []File

func ReadDir(dir string) (Files, error) {
	if dir == "" {
		dir = "."
	}
	files := Files{}
	entries, err := osutil.ReadDirMore(dir, regexp.MustCompile(`^.*\.json$`), false, true, false)
	if err != nil {
		return files, err
	}
	for _, e := range entries {
		if f, err := ParseFile(filepath.Join(dir, e.Name())); err != nil {
			return files, err
		} else {
			files = append(files, f)
		}
	}
	return files, nil
}

func (fs Files) SeverityNames() []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Results.SeverityNames()...)
	}
	out = slicesutil.Dedupe(out)
	sort.Strings(out)
	return out
}

func (fs Files) Stats() StatsSlice {
	ss := StatsSlice{}
	for _, f := range fs {
		ss = append(ss, f.Stats())
	}
	return ss
}

/*
func (ss StatsSlice) Table() *table.Table {
	t := table.NewTable("")

	return &t, nil
}
*/
