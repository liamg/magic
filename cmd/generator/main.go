package main

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/liamg/magic"
)

type MimeInfo struct {
	XMLName   xml.Name   `xml:"mime-info"`
	MimeTypes []MimeType `xml:"mime-type"`
}

type MimeType struct {
	Type            string       `xml:"type,attr"`
	Comment         string       `xml:"comment"`
	Acronym         string       `xml:"acronym"`
	ExpandedAcronym string       `xml:"expanded-acronym"`
	Icon            Icon         `xml:"generic-icon"`
	Magic           []Magic      `xml:"magic"`
	Globs           []Glob       `xml:"glob"`
	SubClassOf      []SubClassOf `xml:"sub-class-of"`
}

type Icon struct {
	Name string `xml:"name,attr"`
}

type SubClassOf struct {
	Type string `xml:"type,attr"`
}

type Magic struct {
	Priority int     `xml:"priority,attr"`
	Matches  []Match `xml:"match"`
}

type Match struct {
	Type     string  `xml:"type,attr"`
	Value    string  `xml:"value,attr"`
	Offset   string  `xml:"offset,attr"`
	Mask     string  `xml:"mask,attr"`
	Children []Match `xml:"match"`
}

type Glob struct {
	Pattern string `xml:"pattern,attr"`
	Weight  int    `xml:"weight,attr"`
}

func applyMask(data []byte, mask []byte) []byte {
	copied := make([]byte, len(data))
	copy(copied, data)
	for i := range mask {
		if i >= len(copied) {
			break
		}
		copied[i] &= mask[i]
	}
	return copied
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input.xml> <output.go>\n", os.Args[0])
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	// Read and parse XML
	xmlFile, err := os.Open(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", inputFile, err)
		os.Exit(1)
	}
	defer func() { _ = xmlFile.Close() }()

	data, err := io.ReadAll(xmlFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", inputFile, err)
		os.Exit(1)
	}

	var mimeInfo MimeInfo
	if err := xml.Unmarshal(data, &mimeInfo); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing XML: %v\n", err)
		os.Exit(1)
	}

	var dataMatchers []*magic.DataMatcher

	for _, mt := range mimeInfo.MimeTypes {
		for _, magic := range mt.Magic {
			entry, err := buildDataMatchers(mt, magic)
			if err != nil {
				panic(fmt.Errorf("failed to build data matchers for %s: %v", mt.Type, err))
			}
			dataMatchers = append(dataMatchers, entry)
		}
	}

	sort.Slice(dataMatchers, func(i, j int) bool {
		return dataMatchers[i].Priority > dataMatchers[j].Priority
	})

	var filenameMatchers []*magic.FilenameMatcher
	for _, mt := range mimeInfo.MimeTypes {
		for _, g := range mt.Globs {
			res := buildResult(mt)
			if _, err := doublestar.Match(g.Pattern, ""); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing glob %s: %v\n", g.Pattern, err)
				os.Exit(1)
			}
			if g.Weight == 0 {
				g.Weight = 50
			}
			res.RecommendedExtension = filepath.Ext(g.Pattern)
			filenameMatchers = append(filenameMatchers, &magic.FilenameMatcher{
				Pattern:  g.Pattern,
				Result:   res,
				Priority: g.Weight,
			})
		}
	}

	sort.Slice(filenameMatchers, func(i, j int) bool {
		return filenameMatchers[i].Priority > filenameMatchers[j].Priority
	})

	// Generate Go code
	out, err := os.Create(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", outputFile, err)
		os.Exit(1)
	}
	defer func() { _ = out.Close() }()

	_, _ = fmt.Fprintln(out, "package magic")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "var filenameMatchers = []FilenameMatcher{")

	for _, fm := range filenameMatchers {
		writeFilenameMatcher(out, fm)
	}

	_, _ = fmt.Fprintln(out, "}")
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintln(out, "var dataMatchers = []DataMatcher{")

	for _, dm := range dataMatchers {
		writeDataMatcher(out, dm)
	}

	_, _ = fmt.Fprintln(out, "}")
}

func buildResult(mt MimeType) magic.FileType {
	return magic.FileType{
		Description:          mt.Comment,
		RecommendedExtension: filepath.Ext(mt.Type),
		MIME:                 mt.Type,
		Icon:                 mt.Icon.Name,
	}
}

func buildDataMatchers(mt MimeType, m Magic) (*magic.DataMatcher, error) {

	matcher := &magic.DataMatcher{
		Priority: m.Priority,
		Result:   buildResult(mt),
	}

	if matcher.Priority == 0 {
		matcher.Priority = 50
	}

	for _, match := range m.Matches {
		m, err := buildDataSubMatcher(match)
		if err != nil {
			return nil, err
		}
		matcher.Submatches = append(matcher.Submatches, m)
	}

	return matcher, nil
}

func buildDataSubMatcher(match Match) (magic.DataSubMatcher, error) {

	var children []magic.DataSubMatcher
	for _, child := range match.Children {
		c, err := buildDataSubMatcher(child)
		if err != nil {
			return magic.DataSubMatcher{}, err
		}
		children = append(children, c)
	}

	b, err := convertValue(match.Value, match.Type)
	if err != nil {
		return magic.DataSubMatcher{}, err
	}

	offsets, err := convertOffsets(match.Offset)
	if err != nil {
		return magic.DataSubMatcher{}, err
	}

	var mask []byte
	if match.Mask != "" {
		mask, err = convertMask(match.Mask)
		if err != nil {
			return magic.DataSubMatcher{}, err
		}
		b = applyMask(b, mask)
	}

	return magic.DataSubMatcher{
		Bytes:    b,
		Offsets:  offsets,
		Mask:     mask,
		Children: children,
	}, nil
}

func decodeOctalBytes(s string) ([]byte, error) {
	var result []byte
	// Process in groups of 3 digits (or remaining digits)
	for i := 0; i < len(s); i += 3 {
		end := i + 3
		if end > len(s) {
			end = len(s)
		}
		val, err := strconv.ParseUint(s[i:end], 8, 8)
		if err != nil {
			return nil, err
		}
		result = append(result, byte(val))
	}
	return result, nil
}

func convertMask(mask string) ([]byte, error) {
	switch {
	case strings.HasPrefix(mask, "0x"):
		return hex.DecodeString(mask[2:])
	case strings.HasPrefix(mask, "0o"):
		return decodeOctalBytes(mask[2:])
	case strings.HasPrefix(mask, "0") && len(mask) > 1:
		return decodeOctalBytes(mask)
	default:
		return nil, fmt.Errorf("invalid mask format: %s", mask)
	}
}

func convertOffsets(offset string) ([]int, error) {

	if offset == "" {
		return []int{0}, nil
	}

	start, end, ok := strings.Cut(offset, ":")
	startInt, err := strconv.Atoi(start)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []int{startInt}, nil
	}

	endInt, err := strconv.Atoi(end)
	if err != nil {
		return nil, err
	}

	var output []int
	for i := startInt; i <= endInt; i++ {
		output = append(output, i)
	}

	return output, nil
}

func convertValue(value string, valueType string) ([]byte, error) {
	switch valueType {
	case "string":
		// Handle escape sequences in string values
		return unescapeString(value), nil
	case "byte":
		// Byte values are typically in hex format or decimal
		if strings.HasPrefix(value, "0x") {
			// Hex format
			b, err := strconv.ParseUint(value[2:], 16, 8)
			if err != nil {
				return nil, err
			}
			return []byte{byte(b)}, nil
		}
		// Decimal format
		b, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, err
		}
		return []byte{byte(b)}, nil
	case "big16":
		val, err := parseInteger(value)
		if err != nil {
			return nil, err
		}
		return []byte{byte(val >> 8), byte(val)}, nil
	case "big32":
		val, err := parseInteger(value)
		if err != nil {
			return nil, err
		}
		return []byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}, nil
	case "little16":
		val, err := parseInteger(value)
		if err != nil {
			return nil, err
		}
		return []byte{byte(val), byte(val >> 8)}, nil
	case "little32":
		val, err := parseInteger(value)
		if err != nil {
			return nil, err
		}
		return []byte{byte(val), byte(val >> 8), byte(val >> 16), byte(val >> 24)}, nil
	case "host32":
		// Host byte order - we'll use big endian as it's more common for file magic
		val, err := parseInteger(value)
		if err != nil {
			return nil, err
		}
		return []byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}, nil
	case "host16":
		// Host byte order - we'll use big endian
		val, err := parseInteger(value)
		if err != nil {
			return nil, err
		}
		return []byte{byte(val >> 8), byte(val)}, nil
	default:
		return nil, fmt.Errorf("unsupported type: %s", valueType)
	}
}

func parseInteger(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") {
		return strconv.ParseUint(value[2:], 16, 64)
	}
	if strings.HasPrefix(value, "0o") {
		return strconv.ParseUint(value[2:], 8, 64)
	}
	if strings.HasPrefix(value, "0") && len(value) > 1 {
		return strconv.ParseUint(value[1:], 8, 64)
	}
	return strconv.ParseUint(value, 10, 64)
}

func unescapeString(s string) []byte {
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch {
			case s[i+1] == 'x':
				// Handle \xNN hex escape
				if i+3 < len(s) {
					hexStr := s[i+2 : i+4]
					if b, err := strconv.ParseUint(hexStr, 16, 8); err == nil {
						result = append(result, byte(b))
						i += 4
						continue
					}
				}
			case s[i+1] >= '0' && s[i+1] <= '7':
				// Handle octal escape \NNN (1-3 digits)
				octLen := 1
				for octLen < 3 && i+1+octLen < len(s) && s[i+1+octLen] >= '0' && s[i+1+octLen] <= '7' {
					octLen++
				}
				octStr := s[i+1 : i+1+octLen]
				if b, err := strconv.ParseUint(octStr, 8, 8); err == nil {
					result = append(result, byte(b))
					i += 1 + octLen
					continue
				}
			case s[i+1] == 'n':
				result = append(result, '\n')
				i += 2
				continue
			case s[i+1] == 't':
				result = append(result, '\t')
				i += 2
				continue
			case s[i+1] == 'r':
				result = append(result, '\r')
				i += 2
				continue
			case s[i+1] == '\\':
				result = append(result, '\\')
				i += 2
				continue
			case s[i+1] == '"':
				result = append(result, '"')
				i += 2
				continue
			}
		}
		result = append(result, s[i])
		i++
	}
	return result
}

const indentStep = "  "

func writeFilenameMatcher(out io.Writer, entry *magic.FilenameMatcher) {

	indent := indentStep

	_, _ = fmt.Fprintf(out, "%s{\n", indent)
	{
		indent := indent + indentStep
		_, _ = fmt.Fprintf(out, "%sPattern:  %q,\n", indent, entry.Pattern)
		_, _ = fmt.Fprintf(out, "%sPriority: %d,\n", indent, entry.Priority)
		_, _ = fmt.Fprintf(out, "%sResult:   ", indent)
		writeResult(out, entry.Result, indent)
	}
	_, _ = fmt.Fprintf(out, "%s},\n", indent)
}

func writeDataMatcher(out io.Writer, entry *magic.DataMatcher) {
	indent := indentStep

	_, _ = fmt.Fprintf(out, "%s{\n", indent)
	{
		indent := indent + indentStep
		_, _ = fmt.Fprintf(out, "%sSubmatches: []DataSubMatcher{\n", indent)
		for _, child := range entry.Submatches {
			writeDataSubMatcher(out, &child, indent+indentStep)
		}
		_, _ = fmt.Fprintf(out, "%s},\n", indent)
		_, _ = fmt.Fprintf(out, "%sPriority: %d,\n", indent, entry.Priority)
		_, _ = fmt.Fprintf(out, "%sResult: ", indent)
		writeResult(out, entry.Result, indent)
	}
	_, _ = fmt.Fprintf(out, "%s},\n", indent)
}

func writeDataSubMatcher(out io.Writer, entry *magic.DataSubMatcher, indent string) {

	_, _ = fmt.Fprintf(out, "%s{\n", indent)
	{
		indent := indent + indentStep
		_, _ = fmt.Fprintf(out, "%sBytes:    ", indent)
		writeBytes(out, entry.Bytes)
		_, _ = fmt.Fprint(out, ",\n")
		_, _ = fmt.Fprintf(out, "%sOffsets:  ", indent)
		writeInts(out, entry.Offsets)
		_, _ = fmt.Fprint(out, ",\n")
		if len(entry.Mask) > 0 {
			_, _ = fmt.Fprintf(out, "%sMask:     ", indent)
			writeBytes(out, entry.Mask)
			_, _ = fmt.Fprint(out, ",\n")
		}
		if len(entry.Children) > 0 {
			_, _ = fmt.Fprintf(out, "%sChildren: []DataSubMatcher{\n", indent)
			for _, child := range entry.Children {
				writeDataSubMatcher(out, &child, indent+indentStep)
			}
			_, _ = fmt.Fprintf(out, "%s},\n", indent)
		}
	}
	_, _ = fmt.Fprintf(out, "%s},\n", indent)
}

func writeResult(out io.Writer, result magic.FileType, indent string) {
	_, _ = fmt.Fprintf(out, "%sFileType{\n", indent)
	{

		icon := result.Icon
		if icon == "" {
			if strings.HasPrefix(result.MIME, "text/") {
				icon = "text-x-generic"
			} else {
				icon = "application-x-generic"
			}
		}

		indent := indent + indentStep
		_, _ = fmt.Fprintf(out, "%sDescription:          %q,\n", indent, result.Description)
		_, _ = fmt.Fprintf(out, "%sRecommendedExtension: %q,\n", indent, result.RecommendedExtension)
		_, _ = fmt.Fprintf(out, "%sIcon:                 %q,\n", indent, icon)
		_, _ = fmt.Fprintf(out, "%sMIME:                 %q,\n", indent, result.MIME)
	}
	_, _ = fmt.Fprintf(out, "%s},\n", indent)
}

func writeBytes(out io.Writer, b []byte) {
	_, _ = fmt.Fprint(out, "[]byte{")
	for i, v := range b {
		if i == len(b)-1 {
			_, _ = fmt.Fprintf(out, "%d", v)
		} else {
			_, _ = fmt.Fprintf(out, "%d, ", v)
		}
	}
	_, _ = fmt.Fprint(out, "}")
}

func writeInts(out io.Writer, b []int) {
	_, _ = fmt.Fprint(out, "[]int{")
	for i, v := range b {
		if i == len(b)-1 {
			_, _ = fmt.Fprintf(out, "%d", v)
		} else {
			_, _ = fmt.Fprintf(out, "%d, ", v)
		}
	}
	_, _ = fmt.Fprint(out, "}")
}
