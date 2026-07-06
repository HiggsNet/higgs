package text

import (
	"fmt"
	"io"
)

type lineWriter struct {
	w   io.Writer
	err error
}

func newLineWriter(w io.Writer) *lineWriter {
	return &lineWriter{w: w}
}

func (l *lineWriter) Printf(format string, args ...any) {
	if l == nil || l.err != nil {
		return
	}
	_, l.err = fmt.Fprintf(l.w, format, args...)
}

func (l *lineWriter) PrintIf(cond bool, format string, args ...any) {
	if cond {
		l.Printf(format, args...)
	}
}

func (l *lineWriter) Linef(format string, args ...any) {
	l.Printf(format+"\n", args...)
}

func (l *lineWriter) LineIf(cond bool, format string, args ...any) {
	if cond {
		l.Linef(format, args...)
	}
}

func (l *lineWriter) Println(args ...any) {
	if l == nil || l.err != nil {
		return
	}
	_, l.err = fmt.Fprintln(l.w, args...)
}

func (l *lineWriter) Blank() {
	l.Println()
}

func (l *lineWriter) Err() error {
	if l == nil {
		return nil
	}
	return l.err
}
