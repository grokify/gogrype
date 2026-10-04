package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/grokify/gogrype/flatjson"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/log/logutil"
)

// parse reads Grype/Anchore "flat JSON" vulnerability exports and prints
// per-file and aggregate statistics.
//
// Usage:
//
//	parse -file report.json   # parse a single export
//	parse -dir ./reports      # aggregate every *.json in a directory
func main() {
	file := flag.String("file", "", "path to a single flat-JSON export")
	dir := flag.String("dir", "", "directory of *.json flat-JSON exports to aggregate")
	flag.Parse()

	if *file == "" && *dir == "" {
		flag.Usage()
		os.Exit(2)
	}

	if *file != "" {
		res, err := flatjson.ParseFile(*file)
		logutil.FatalErr(err)
		fmtutil.MustPrintJSON(res)
		fmtutil.MustPrintJSON(res.Results.VulnerabilityIDCounts())
		fmtutil.MustPrintJSON(res.Results.SeverityCounts(true))
		fmt.Printf("Total Count: (%d)\n", len(res.Results))
		fmt.Printf("Unique Count: (%d)\n", len(res.Results.VulnerabilityIDCounts()))
		fmtutil.MustPrintJSON(res.Stats())
	}

	if *dir != "" {
		fs, err := flatjson.ReadDir(*dir)
		logutil.FatalErr(err)
		fmtutil.MustPrintJSON(fs.Stats())
	}

	log.Println("DONE")
}
