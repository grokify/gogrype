package main

import (
	"github.com/grokify/gogrype"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/log/logutil"
)

func main() {
	// uses Grype output file against:
	// https://github.com/tothi/log4shell-vulnerable-app
	f := "grype_log4shell-vulnerable-app.json"
	g, err := gogrype.ReadFileGrypeOutputJSON(f)
	logutil.FatalErr(err)
	fmtutil.MustPrintJSON(g)
	fmtutil.MustPrintJSON(g.GoVEXes())
}
