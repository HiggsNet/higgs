package text

import (
	"io"
	"strings"
	"unicode/utf8"
)

// rightAlignedCells pads semantic zone columns before they are passed to the
// tabwriter. Padding the cell (instead of enabling tabwriter.AlignRight) keeps
// non-zone columns left aligned.
func rightAlignedCells(rows [][]string, columns ...int) [][]string {
	widths := make(map[int]int, len(columns))
	for _, column := range columns {
		for _, row := range rows {
			if column < len(row) {
				widths[column] = max(widths[column], utf8.RuneCountInString(row[column]))
			}
		}
	}
	for i := range rows {
		for _, column := range columns {
			if column >= len(rows[i]) {
				continue
			}
			padding := widths[column] - utf8.RuneCountInString(rows[i][column])
			if padding > 0 {
				rows[i][column] = spaces(padding) + rows[i][column]
			}
		}
	}
	return rows
}

func writeAlignedRows(out *lineWriter, rows [][]string, columns ...int) {
	for _, row := range rightAlignedCells(rows, columns...) {
		out.Println(strings.Join(row, "\t"))
	}
}

// WriteAlignedRows writes tab-delimited rows while right-aligning only the
// requested semantic columns. The caller may wrap w in a tabwriter.Writer.
func WriteAlignedRows(w io.Writer, rows [][]string, columns ...int) error {
	out := newLineWriter(w)
	writeAlignedRows(out, rows, columns...)
	return out.Err()
}

func spaces(count int) string {
	if count <= 0 {
		return ""
	}
	buf := make([]byte, count)
	for i := range buf {
		buf[i] = ' '
	}
	return string(buf)
}
