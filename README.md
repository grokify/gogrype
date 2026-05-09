# Go Grype

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/grokify/gogrype/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/grokify/gogrype/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/grokify/gogrype/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/grokify/gogrype/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/grokify/gogrype/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/grokify/gogrype/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/gogrype
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/gogrype
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/gogrype
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/gogrype
 [viz-svg]: https://img.shields.io/badge/visualization-Go-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=grokify%2Fgogrype
 [loc-svg]: https://tokei.rs/b1/github/grokify/gogrype
 [repo-url]: https://github.com/grokify/gogrype
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/gogrype/blob/main/LICENSE

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
