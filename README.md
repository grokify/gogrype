# Go Grype

`gogrype` is a package to interact with [`github.com/anchore/grype`](https://github.com/anchore/grype).

## Usage

Generate Grype JSON output.

```
% grype sbom:./sbom.spdx.json --add-cpes-if-none > grypeout.json
```

Convert Grype JSON output to XLSX file:

```
% go run cmd/json2xlsx/main.go grypeout.json grypeout.xlsx
```