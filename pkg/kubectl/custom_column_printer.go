/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubectl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"

	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/jsonpath"
)

const (
	columnwidth       = 10
	tabwidth          = 4
	padding           = 3
	padding_character = ' '
	flags             = 0
)

// MassageJSONPath attempts to be flexible with JSONPath expressions, it accepts:
//   * metadata.name (no leading '.' or curly brances '{...}'
//   * {metadata.name} (no leading '.')
//   * .metadata.name (no curly braces '{...}')
//   * {.metadata.name} (complete expression)
// And transforms them all into a valid jsonpat expression:
//   {.metadata.name}
func massageJSONPath(pathExpression string) string {
	if len(pathExpression) == 0 {
		return pathExpression
	}
	if pathExpression[0] != '{' {
		if pathExpression[0] == '.' {
			return fmt.Sprintf("{%s}", pathExpression)
		} else {
			return fmt.Sprintf("{.%s}", pathExpression)
		}
	} else {
		if pathExpression[1] == '.' {
			return pathExpression
		} else {
			return fmt.Sprintf("{.%s}", pathExpression[1:len(pathExpression)-1])
		}
	}
}

// NewCustomColumnsPrinterFromSpec creates a custom columns printer from a comma separated list of <header>:<jsonpath-field-spec> pairs.
// e.g. NAME:metadata.name,API_VERSION:apiVersion creates a printer that prints:
//
//      NAME               API_VERSION
//      foo                bar
func NewCustomColumnsPrinterFromSpec(spec string) (*CustomColumnsPrinter, error) {
	parts := strings.Split(spec, ",")
	if len(parts) == 0 {
		return nil, fmt.Errorf("custom-columns format specified but no custom columns given")
	}
	columns := make([]Column, len(parts))
	for ix := range parts {
		colSpec := strings.Split(parts[ix], ":")
		if len(colSpec) != 2 {
			return nil, fmt.Errorf("unexpected custom-columns spec: %s, expected <header>:<json-path-expr>", parts[ix])
		}
		columns[ix] = Column{Header: colSpec[0], FieldSpec: massageJSONPath(colSpec[1])}
	}
	return &CustomColumnsPrinter{Columns: columns}, nil
}

func splitOnWhitespace(line string) []string {
	lineScanner := bufio.NewScanner(bytes.NewBufferString(line))
	lineScanner.Split(bufio.ScanWords)
	result := []string{}
	for lineScanner.Scan() {
		result = append(result, lineScanner.Text())
	}
	return result
}

// NewCustomColumnsPrinterFromTemplate creates a custom columns printer from a template stream.  The template is expected
// to consist of two lines, whitespace separated.  The first line is the header line, the second line is the jsonpath field spec
// For example the template below:
// NAME               API_VERSION
// {metadata.name}    {apiVersion}
func NewCustomColumnsPrinterFromTemplate(templateReader io.Reader) (*CustomColumnsPrinter, error) {
	scanner := bufio.NewScanner(templateReader)
	if !scanner.Scan() {
		return nil, fmt.Errorf("invalid template, missing header line")
	}
	headers := splitOnWhitespace(scanner.Text())

	if !scanner.Scan() {
		return nil, fmt.Errorf("invalid template, missing spec line")
	}
	specs := splitOnWhitespace(scanner.Text())
	fmt.Printf("SPECS: %v", specs)

	if len(headers) != len(specs) {
		return nil, fmt.Errorf("number of headers (%d) and field specifications (%d) don't match", len(headers), len(specs))
	}

	columns := make([]Column, len(headers))
	for ix := range headers {
		columns[ix] = Column{
			Header:    headers[ix],
			FieldSpec: massageJSONPath(specs[ix]),
		}
	}
	return &CustomColumnsPrinter{Columns: columns}, nil
}

// Column represents a user specified column
type Column struct {
	// The header to print above the column, general style is ALL_CAPS
	Header string
	// The pointer to the field in the object to print in JSONPath form
	// e.g. {.ObjectMeta.Name}, see pkg/util/jsonpath for more details.
	FieldSpec string
}

// CustomColumnPrinter is a printer that knows how to print arbitrary columns
// of data from templates specified in the `Columns` array
type CustomColumnsPrinter struct {
	Columns []Column
}

func (s *CustomColumnsPrinter) PrintObj(obj runtime.Object, out io.Writer) error {
	w := tabwriter.NewWriter(out, columnwidth, tabwidth, padding, padding_character, flags)
	headers := make([]string, len(s.Columns))
	for ix := range s.Columns {
		headers[ix] = s.Columns[ix].Header
	}
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	parsers := make([]*jsonpath.JSONPath, len(s.Columns))
	for ix := range s.Columns {
		parsers[ix] = jsonpath.New(fmt.Sprintf("column%d", ix))
		if err := parsers[ix].Parse(s.Columns[ix].FieldSpec); err != nil {
			return err
		}
	}

	if runtime.IsListType(obj) {
		objs, err := runtime.ExtractList(obj)
		if err != nil {
			return err
		}
		for ix := range objs {
			if err := s.printOneObject(objs[ix], parsers, w); err != nil {
				return err
			}
		}
	} else {
		if err := s.printOneObject(obj, parsers, w); err != nil {
			return err
		}
	}
	return w.Flush()
}

func (s *CustomColumnsPrinter) printOneObject(obj runtime.Object, parsers []*jsonpath.JSONPath, out io.Writer) error {
	columns := make([]string, len(parsers))
	for ix := range parsers {
		parser := parsers[ix]
		values, err := parser.FindResults(reflect.ValueOf(obj).Elem().Interface())
		if err != nil {
			return err
		}
		if len(values) == 0 || len(values[0]) == 0 {
			fmt.Fprintf(out, "<none>\t")
		}
		valueStrings := []string{}
		for arrIx := range values {
			for valIx := range values[arrIx] {
				valueStrings = append(valueStrings, fmt.Sprintf("%v", values[arrIx][valIx].Interface()))
			}
		}
		columns[ix] = strings.Join(valueStrings, ",")
	}
	fmt.Fprintln(out, strings.Join(columns, "\t"))
	return nil
}

func (s *CustomColumnsPrinter) HandledResources() []string {
	return []string{}
}
