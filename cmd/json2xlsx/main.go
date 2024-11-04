package main

import (
	"fmt"
	"os"

	"github.com/grokify/gogrype"
	"github.com/grokify/mogo/log/logutil"
)

func main() {
	args := os.Args
	if len(args) < 3 {
		fmt.Println("usage: `json2xlsx {srcfile.json} {outfile.xlsx}")
		os.Exit(2)
	}
	srcfile := args[1]
	outfile := args[2]

	gout, err := gogrype.ReadFileGrypeOutputJSON(srcfile)
	logutil.FatalErr(err)

	err = gout.Matches.WriteFileXLSX(outfile, nil)
	logutil.FatalErr(err)

	fmt.Printf("WROTE (%s) with COUNT (%d)\n", outfile, gout.Len())

	fmt.Println("DONE")
}
