# Go Grype

[![Build Status][build-status-svg]][build-status-url]
[![Lint Status][lint-status-svg]][lint-status-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![LOC][loc-svg]][loc-url]
[![License][license-svg]][license-url]

 [build-status-svg]: https://github.com/grokify/gogrype/actions/workflows/ci.yaml/badge.svg?branch=main
 [build-status-url]: https://github.com/grokify/gogrype/actions/workflows/ci.yaml
 [lint-status-svg]: https://github.com/grokify/gogrype/actions/workflows/lint.yaml/badge.svg?branch=main
 [lint-status-url]: https://github.com/grokify/gogrype/actions/workflows/lint.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/gogrype
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/gogrype
 [codeclimate-status-svg]: https://codeclimate.com/github/grokify/gogrype/badges/gpa.svg
 [codeclimate-status-url]: https://codeclimate.com/github/grokify/gogrype
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/gogrype
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/gogrype
 [loc-svg]: https://tokei.rs/b1/github/grokify/gogrype
 [loc-url]: https://github.com/grokify/gogrype
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/gogrype/blob/master/LICENSE

`gogrype` is a package to interact with [`github.com/anchore/grype`](https://github.com/anchore/grype).

## Usage

### Generate Grype JSON output from SBOM

```
% grype sbom:./sbom.spdx.json --add-cpes-if-none > grypeout.json
```

### Generate Grype JSON output from JAR

```
% grype log4shell-vulnerable-app-all.jar -o json > grypeout.json
```

### Convert Grype JSON output to XLSX file

```
% go run cmd/json2xlsx/main.go grypeout.json grypeout.xlsx
```

### Integrate with GoVEX

```
import (
    "github.com/grokify/gogrype"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/log/logutil"
)

g, err := gogrype.ReadFileGrypeOutputJSON(f)
logutil.FatalErr(err)
fmtutil.PrintJSON(g)
fmtutil.PrintJSON(g.GoVEXes())
```
