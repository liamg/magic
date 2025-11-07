package magic

//go:generate go run cmd/generator/main.go freedesktop.org.xml generated.go

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
)

var unknownBinaryFileType = FileType{
	Description:          "Unknown",
	RecommendedExtension: ".bin",
	MIME:                 "application/octet-stream",
	Icon:                 "application-x-generic",
}

var unknownTextFileType = FileType{
	Description:          "Unknown",
	RecommendedExtension: ".txt",
	MIME:                 "text/plain",
	Icon:                 "text-x-generic",
}

type bufferedReader struct {
	reader io.Reader
	buffer []byte
}

func (b *bufferedReader) MaybeBuffer(length int) {
	_ = b.EnsureBuffered(length)
}

func (b *bufferedReader) EnsureBuffered(length int) error {
	if len(b.buffer) >= length {
		return nil
	}
	extra := length - len(b.buffer)
	existing := b.buffer

	b.buffer = make([]byte, length)
	if len(existing) > 0 {
		copy(b.buffer, existing)
	}

	if n, err := b.reader.Read(b.buffer[len(existing):]); err != nil {
		b.buffer = b.buffer[:len(existing)]
		return err
	} else if n < extra {
		b.buffer = b.buffer[:len(existing)+n]
		return fmt.Errorf("not enough data available to read")
	}

	return nil
}

func (b *bufferedReader) Data() []byte {
	return b.buffer
}

// Identify looks up the file type based on the provided bytes.
func Identify(r io.Reader) FileType {

	b := &bufferedReader{
		reader: r,
	}

	for _, t := range allDataMatchers {
		if t.MatchBytes(b) {
			return t.Result
		}
	}
	return identifyUnknownType(b)
}

func IdentifyPath(path string) (FileType, error) {
	f, err := os.Open(path)
	if err != nil {
		return unknownBinaryFileType, err
	}
	defer func() { _ = f.Close() }()
	return IdentifyWithFilename(f, filepath.Base(path)), nil
}

func identifyUnknownType(b *bufferedReader) FileType {
	// we just want to fill the buffer with anything up to 128 bytes
	b.MaybeBuffer(128)
	for i := range len(b.Data()) {
		if b.Data()[i] < 32 || b.Data()[i] > 126 {
			if utf8.Valid(b.Data()) {
				return unknownTextFileType
			}
			return unknownBinaryFileType
		}
	}
	return unknownTextFileType
}

// IdentifyWithFilename looks up the file type based on the provided filename, falling back to the bytes if needed.
// See https://specifications.freedesktop.org/shared-mime-info/latest/ar01s02.html#id-1.3.15 for checking order
func IdentifyWithFilename(r io.Reader, filename string) FileType {
	filename = filepath.Base(filename)
	candidates := make([]FilenameMatcher, 0)
	maxPriority := 0
	for _, t := range allFilenameMatchers {
		if t.Priority < maxPriority {
			continue
		}
		if ok, _ := doublestar.Match(t.Pattern, filename); ok {
			if t.Priority > maxPriority {
				maxPriority = t.Priority
			}
			candidates = append(candidates, t)
		}
	}
	if len(candidates) > 0 {
		filtered := make([]FilenameMatcher, 0, len(candidates))
		for _, c := range candidates {
			if c.Priority == maxPriority {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 1 {
			return filtered[0].Result
		}
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].Pattern > filtered[j].Pattern
		})
		maxPatternLength := len(filtered[0].Pattern)
		refiltered := make([]FilenameMatcher, 0, len(filtered))
		for _, f := range filtered {
			if len(f.Pattern) == maxPatternLength {
				refiltered = append(refiltered, f)
			}
		}
		mimes := make(map[string]struct{}, len(refiltered))
		for _, f := range refiltered {
			fmt.Println(f.Result.MIME)
			mimes[f.Result.MIME] = struct{}{}
		}
		if len(mimes) == 1 {
			return refiltered[0].Result
		}

		// we follow the fressdesktop advice here of using the file content if there are multiple filename matches.
		// however, if the file content doesn't yield a match either, we take the first filename match
		fallback := Identify(r)
		if fallback != unknownBinaryFileType && fallback != unknownTextFileType {
			return fallback
		}

		return refiltered[0].Result
	}
	return Identify(r)
}

type FilenameMatcher struct {
	Pattern  string
	Result   FileType
	Priority int
}

type DataMatcher struct {
	Submatches []DataSubMatcher
	Result     FileType
	Priority   int
}

type DataSubMatcher struct {
	Bytes    []byte
	Offsets  []int
	Mask     []byte
	Children []DataSubMatcher
}

// FileType provides information about the type of the file inferred from the provided magic bytes
type FileType struct {
	Description          string
	RecommendedExtension string
	Icon                 string
	MIME                 string
}

func (m *DataMatcher) MatchBytes(b *bufferedReader) bool {
	for _, match := range m.Submatches {
		lastOffset := match.Offsets[len(match.Offsets)-1]
		b.MaybeBuffer(lastOffset + len(match.Bytes))
		if match.Match(b.Data()) {
			return true
		}
	}
	return false
}

func (m *DataSubMatcher) Match(data []byte) bool {
	var peek []byte
	for _, offset := range m.Offsets {
		if len(data) <= offset {
			return false
		}
		peek = data[offset:]
		if len(peek) < len(m.Bytes) {
			return false
		}
		peek = peek[:len(m.Bytes)]
		if len(m.Mask) > 0 {
			peek = applyMask(peek, m.Mask)
		}
		if bytes.Equal(peek, m.Bytes) {

			if len(m.Children) == 0 {
				return true
			}

			for _, child := range m.Children {
				if child.Match(data) {
					return true
				}
			}

			continue
		}
	}
	return false
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
