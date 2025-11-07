package magic

import "sort"

var allDataMatchers = append(dataMatchers, extraDataMatchers...)
var allFilenameMatchers = append(filenameMatchers, extraFileMatchers...)

func init() {
	sort.Slice(allDataMatchers, func(i, j int) bool {
		return allDataMatchers[i].Priority > allDataMatchers[j].Priority
	})
	sort.Slice(allFilenameMatchers, func(i, j int) bool {
		return allFilenameMatchers[i].Priority > allFilenameMatchers[j].Priority
	})
}

var extraFileMatchers = []FilenameMatcher{
	{
		Pattern: "go.mod",
		Result: FileType{
			Description:          "Go modules configuration file",
			RecommendedExtension: ".mod",
			MIME:                 "text/x-go",
			Icon:                 "text-x-generic",
		},
		Priority: 50,
	},
	{
		Pattern: "go.sum",
		Result: FileType{
			Description:          "Go modules checksum file",
			RecommendedExtension: ".sum",
			MIME:                 "text/x-go",
			Icon:                 "text-x-generic",
		},
		Priority: 50,
	},
	{
		Pattern: "Makefile",
		Result: FileType{
			Description:          "Makefile",
			RecommendedExtension: "",
			MIME:                 "text/plain",
			Icon:                 "text-x-generic",
		},
		Priority: 50,
	},
}

var extraDataMatchers = []DataMatcher{
	{
		Submatches: []DataSubMatcher{
			{
				Bytes:   []byte("\xcf\xfa\xed\xfe"), // 64-bit little-endian
				Offsets: []int{0},
			},
		},
		Result: FileType{
			Description:          "Mach-O binary: 64-bit little-endian",
			RecommendedExtension: "",
			MIME:                 "application/x-mach-binary",
		},
		Priority: 50,
	},
	{
		Submatches: []DataSubMatcher{
			{
				Bytes:   []byte("\xfe\xed\xfa\xcf"),
				Offsets: []int{0},
			},
		},
		Result: FileType{
			Description:          "Mach-O binary: 64-bit big-endian",
			RecommendedExtension: "",
			MIME:                 "application/x-mach-binary",
		},
		Priority: 50,
	},
	{
		Submatches: []DataSubMatcher{
			{
				Bytes:   []byte("\xce\xfa\xed\xfe"), // 32-bit little-endian
				Offsets: []int{0},
			},
		},
		Result: FileType{
			Description:          "Mach-O binary: 32-bit little-endian",
			RecommendedExtension: "",
			MIME:                 "application/x-mach-binary",
		},
		Priority: 50,
	},
	{
		Submatches: []DataSubMatcher{
			{
				Bytes:   []byte("\xfe\xed\xfa\xce"), // 32-bit big-endian
				Offsets: []int{0},
			},
		},
		Result: FileType{
			Description:          "Mach-O binary: 32-bit big-endian",
			RecommendedExtension: "",
			MIME:                 "application/x-mach-binary",
		},
		Priority: 50,
	},
}
