package mgmtapi

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/logstore"
)

// maxExportRows caps a single export so a huge date range can't buffer an
// unbounded result set in memory (matches the Python original's 500k limit).
const maxExportRows = 500_000

// registerLogsExportRoute wires GET /api/logs/export, streaming a CSV or XLSX
// of either log table over an optional [start,end] Unix-second range. Mirrors
// the Python management API's export_logs handler, including its kind/format
// whitelists and row-count ceiling.
func (s *Server) registerLogsExportRoute(r chi.Router) {
	r.Get("/api/logs/export", s.handleLogsExport)
}

func (s *Server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "requests"
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	if kind != "requests" && kind != "blocks" && kind != "policy_changes" {
		writeJSONError(w, http.StatusBadRequest, `kind must be one of ['requests', 'blocks', 'policy_changes']`)
		return
	}
	if format != "csv" && format != "xlsx" {
		writeJSONError(w, http.StatusBadRequest, `format must be one of ['csv', 'xlsx']`)
		return
	}

	startTs := parseTsParam(r, "start", 0)
	endTs := parseTsParam(r, "end", time.Now().Unix())

	rows := s.Logs.RowsInRange(kind, startTs, endTs)
	if len(rows) > maxExportRows {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf(
			"Export would return %d rows which exceeds the %d-row limit. Narrow the date range.",
			len(rows), maxExportRows))
		return
	}

	columns := logstore.RequestColumns
	switch kind {
	case "blocks":
		columns = logstore.BlockColumns
	case "policy_changes":
		columns = logstore.PolicyChangeColumns
	}
	filenameBase := kind + "-" + time.Now().UTC().Format("20060102-150405")

	if format == "csv" {
		writeCSVExport(w, filenameBase, columns, rows)
		return
	}
	writeXLSXExport(w, filenameBase, kind, columns, rows)
}

func parseTsParam(r *http.Request, name string, def int64) int64 {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// cellString renders a scanned SQLite value as text for export. modernc's
// driver yields int64/float64/string/[]byte/nil for our schema's columns.
func cellString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", t)
	}
}

func writeCSVExport(w http.ResponseWriter, filenameBase string, columns []string, rows []map[string]any) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filenameBase+`.csv"`)

	cw := csv.NewWriter(w)
	_ = cw.Write(columns)
	rec := make([]string, len(columns))
	for _, row := range rows {
		for i, c := range columns {
			rec[i] = cellString(row[c])
		}
		_ = cw.Write(rec)
	}
	cw.Flush()
}

// writeXLSXExport builds a minimal, valid single-sheet .xlsx (a zip of XML
// parts) using only the standard library - keeping the pure-Go, no-CGO,
// no-extra-dependency posture of the rest of the project. Cells are written
// as numbers when the value is numeric and inline strings otherwise.
func writeXLSXExport(w http.ResponseWriter, filenameBase, sheetName string, columns []string, rows []map[string]any) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name, content string) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write([]byte(content))
		return err
	}

	sheetXML := buildSheetXML(columns, rows)

	parts := []struct{ name, content string }{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", rootRelsXML},
		{"xl/workbook.xml", workbookXML(sheetName)},
		{"xl/_rels/workbook.xml.rels", workbookRelsXML},
		{"xl/worksheets/sheet1.xml", sheetXML},
	}
	for _, p := range parts {
		if err := add(p.name, p.content); err != nil {
			http.Error(w, "xlsx build failed", http.StatusInternalServerError)
			return
		}
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "xlsx build failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filenameBase+`.xlsx"`)
	_, _ = w.Write(buf.Bytes())
}

func buildSheetXML(columns []string, rows []map[string]any) string {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)

	// Header row.
	b.WriteString(`<row r="1">`)
	for i, c := range columns {
		writeInlineStrCell(&b, cellRef(i, 1), c)
	}
	b.WriteString(`</row>`)

	for ri, row := range rows {
		rowNum := ri + 2
		fmt.Fprintf(&b, `<row r="%d">`, rowNum)
		for ci, col := range columns {
			ref := cellRef(ci, rowNum)
			switch v := row[col].(type) {
			case int64:
				fmt.Fprintf(&b, `<c r="%s"><v>%d</v></c>`, ref, v)
			case int:
				fmt.Fprintf(&b, `<c r="%s"><v>%d</v></c>`, ref, v)
			case float64:
				fmt.Fprintf(&b, `<c r="%s"><v>%s</v></c>`, ref, strconv.FormatFloat(v, 'f', -1, 64))
			default:
				writeInlineStrCell(&b, ref, cellString(row[col]))
			}
		}
		b.WriteString(`</row>`)
	}

	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

func writeInlineStrCell(b *bytes.Buffer, ref, text string) {
	fmt.Fprintf(b, `<c r="%s" t="inlineStr"><is><t xml:space="preserve">`, ref)
	_ = xml.EscapeText(b, []byte(text))
	b.WriteString(`</t></is></c>`)
}

// cellRef builds an A1-style reference for a 0-based column and 1-based row.
func cellRef(col, row int) string {
	return colLetters(col) + strconv.Itoa(row)
}

func colLetters(col int) string {
	letters := ""
	col++ // 1-based
	for col > 0 {
		col--
		letters = string(rune('A'+col%26)) + letters
		col /= 26
	}
	return letters
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
	`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
	`</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
	`</Relationships>`

func workbookXML(sheetName string) string {
	var nb bytes.Buffer
	_ = xml.EscapeText(&nb, []byte(sheetName))
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
		`<sheets><sheet name="` + nb.String() + `" sheetId="1" r:id="rId1"/></sheets></workbook>`
}
