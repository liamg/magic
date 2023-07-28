package magic

import "bytes"

// FileType provides information about the type of the file inferred from the provided magic bytes
type FileType struct {
	Description string
	MIME        string
	Extension   string
	Magic       []byte
	Offset      int
	children    []FileType
}

func (ft *FileType) check(data []byte, offset int) *FileType {
	if len(data) <= offset {
		return nil
	}
	trunc := data[offset:]
	if len(trunc) < len(ft.Magic) {
		return nil
	}
	if bytes.Equal(trunc[:len(ft.Magic)], ft.Magic) {
		if ft.children == nil {
			return ft
		}
		for _, child := range ft.children {
			f := child.check(trunc, child.Offset+len(ft.Magic))
			if f != nil {
				return &child
			}
		}
	}

	return nil
}

/*
Run on https://en.wikipedia.org/wiki/List_of_file_signatures

var code = "";
$('tr', $($('table')[0])).each(function(i, e){

	var offset = $($('td', $(e))[2]).text();
	var ext = $($('td', $(e))[3]).text().split("\n")[0];
	var desc = $($('td', $(e))[4]).text();

	$('pre', $($('td', $(e))[0])).each(function(i,e){
		var raw = $(e).text();
		var output = "{\n";
		output += "\tMagic: []byte{ 0x" + raw.trim().replace("\n", " ").split(/ /g).join(', 0x')  + "},\n";
		output += "\tOffset: " + offset.trim() + ",\n";
		output += "\tDescription: \"" + desc.trim() + "\",\n";
		output += "\tExtension: \"" + ext.trim() + "\",\n";
		output += "\tMIME: \"\",\n";
		output += "},\n";
		code += output + "\n\n";
	});
});
*/

var Types = []FileType{
	{
		Magic:       []byte{0xa1, 0xb2, 0xc3, 0xd4},
		Offset:      0,
		Description: "Libpcap File Format",
		Extension:   "pcap",
		MIME:        "",
	},

	{
		Magic:       []byte{0xd4, 0xc3, 0xb2, 0xa1},
		Offset:      0,
		Description: "Libpcap File Format",
		Extension:   "pcap",
		MIME:        "",
	},

	{
		Magic:       []byte{0x0a, 0x0d, 0x0d, 0x0a},
		Offset:      0,
		Description: "PCAP Next Generation Dump File Format",
		Extension:   "pcapng",
		MIME:        "",
	},

	{
		Magic:       []byte{0xed, 0xab, 0xee, 0xdb},
		Offset:      0,
		Description: "RedHat Package Manager (RPM) package ",
		Extension:   "rpm",
		MIME:        "",
	},

	{
		Magic:       []byte{0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00},
		Offset:      0,
		Description: "SQLite Database ",
		Extension:   "sqlite",
		MIME:        "",
	},

	{
		Magic:       []byte{0x53, 0x50, 0x30, 0x31},
		Offset:      0,
		Description: "Amazon Kindle Update Package ",
		Extension:   "bin",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Offset:      11,
		Description: "PalmPilot Database/Document File",
		Extension:   "pdb",
		MIME:        "",
	},

	{
		Magic:       []byte{0xBE, 0xBA, 0xFE, 0xCA},
		Offset:      0,
		Description: "Palm Desktop Calendar Archive",
		Extension:   "dba",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x01, 0x42, 0x44},
		Offset:      0,
		Description: "Palm Desktop To Do Archive",
		Extension:   "dba",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x01, 0x44, 0x54},
		Offset:      0,
		Description: "Palm Desktop Calendar Archive",
		Extension:   "tda",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x01, 0x00, 0x00},
		Offset:      0,
		Description: "Palm Desktop Data File (Access format)",
		Extension:   "pdd",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x00, 0x01, 0x00},
		Offset:      0,
		Description: "Icon encoded in ICO file format",
		Extension:   "ico",
		MIME:        "",
	},

	{
		Magic:       []byte{0x66, 0x74, 0x79, 0x70, 0x33, 0x67},
		Offset:      4,
		Description: "3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files",
		Extension:   "3gp",
		MIME:        "",
	},

	{
		Magic:       []byte{0x1F, 0x9D},
		Offset:      0,
		Description: "compressed file using Lempel-Ziv-Welch algorithm",
		Extension:   "tar.z",
		MIME:        "",
	},

	{
		Magic:       []byte{0x1F, 0xA0},
		Offset:      0,
		Description: "Compressed file using LZH algorithm",
		Extension:   "tar.z",
		MIME:        "",
	},

	{
		Magic:       []byte{0x42, 0x41, 0x43, 0x4B, 0x4D, 0x49, 0x4B, 0x45, 0x44, 0x49, 0x53, 0x4B},
		Offset:      0,
		Description: "File or tape containing a backup done with AmiBack on an Amiga",
		Extension:   "bac",
		MIME:        "",
	},

	{
		Magic:       []byte{0x42, 0x5A, 0x68},
		Offset:      0,
		Description: "Compressed file using Bzip2 algorithm",
		Extension:   "bz2",
		MIME:        "",
	},

	{
		Magic:       []byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61},
		Offset:      0,
		Description: "Image file encoded in the Graphics Interchange Format (GIF)",
		Extension:   "gif",
		MIME:        "",
	},

	{
		Magic:       []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61},
		Offset:      0,
		Description: "Image file encoded in the Graphics Interchange Format (GIF)",
		Extension:   "gif",
		MIME:        "",
	},

	{
		Magic:       []byte{0x49, 0x49, 0x2A, 0x00},
		Offset:      0,
		Description: "Tagged Image File Format",
		Extension:   "tiff",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4D, 0x4D, 0x00, 0x2A},
		Offset:      0,
		Description: "Tagged Image File Format",
		Extension:   "tiff",
		MIME:        "",
	},

	{
		Magic:       []byte{0x49, 0x49, 0x2A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x43, 0x52},
		Offset:      0,
		Description: "Canon RAW Format Version 2[8]Canon's RAW format is based on the TIFF file format",
		Extension:   "cr2",
		MIME:        "",
	},

	{
		Magic:       []byte{0x80, 0x2A, 0x5F, 0xD7},
		Offset:      0,
		Description: "Kodak Cineon image",
		Extension:   "cin",
		MIME:        "",
	},

	{
		Magic:       []byte{0x52, 0x4E, 0x43, 0x01},
		Offset:      0,
		Description: "Compressed file using Rob Northen Compression algorithm",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x52, 0x4E, 0x43, 0x02},
		Offset:      0,
		Description: "Compressed file using Rob Northen Compression algorithm",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x53, 0x44, 0x50, 0x58},
		Offset:      0,
		Description: "SMPTE DPX image",
		Extension:   "dpx",
		MIME:        "",
	},

	{
		Magic:       []byte{0x58, 0x50, 0x44, 0x53},
		Offset:      0,
		Description: "SMPTE DPX image",
		Extension:   "dpx",
		MIME:        "",
	},

	{
		Magic:       []byte{0x76, 0x2F, 0x31, 0x01},
		Offset:      0,
		Description: "OpenEXR image",
		Extension:   "exr",
		MIME:        "",
	},

	{
		Magic:       []byte{0x42, 0x50, 0x47, 0xFB},
		Offset:      0,
		Description: "Better Portable Graphics format",
		Extension:   "bpg",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFF, 0xD8, 0xFF, 0xDB},
		Offset:      0,
		Description: "JPEG raw or in the JFIF or Exif file format",
		Extension:   "jpg",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01},
		Offset:      0,
		Description: "JPEG raw or in the JFIF or Exif file format",
		Extension:   "jpg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x49, 0x4E, 0x44, 0x58},
		Offset:      0,
		Description: "Index file to a file or tape containing a backup done with AmiBack on an Amiga.",
		Extension:   "idx",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4C, 0x5A, 0x49, 0x50},
		Offset:      0,
		Description: "lzip compressed file",
		Extension:   "lz",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4D, 0x5A},
		Offset:      0,
		Description: "DOS MZ executable file format and its descendants (including NE and PE)",
		Extension:   "exe",
		MIME:        "",
	},

	{
		Magic:       []byte{0x50, 0x4B, 0x03, 0x04},
		Offset:      0,
		Description: "zip file format and formats based on it, such as JAR, ODF, OOXML",
		Extension:   "zip",
		MIME:        "",
	},

	{
		Magic:       []byte{0x50, 0x4B, 0x05, 0x06},
		Offset:      0,
		Description: "zip file format and formats based on it, such as JAR, ODF, OOXML",
		Extension:   "zip",
		MIME:        "",
	},

	{
		Magic:       []byte{0x50, 0x4B, 0x07, 0x08},
		Offset:      0,
		Description: "zip file format and formats based on it, such as JAR, ODF, OOXML",
		Extension:   "zip",
		MIME:        "",
	},

	{
		Magic:       []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00},
		Offset:      0,
		Description: "RAR archive version 1.50 onwards",
		Extension:   "rar",
		MIME:        "",
	},

	{
		Magic:       []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00},
		Offset:      0,
		Description: "RAR archive version 5.0 onwards",
		Extension:   "rar",
		MIME:        "",
	},

	{
		Magic:       []byte{0x7F, 0x45, 0x4C, 0x46},
		Offset:      0,
		Description: "Executable and Linkable Format",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		Offset:      0,
		Description: "Image encoded in the Portable Network Graphics format",
		Extension:   "png",
		MIME:        "",
	},

	{
		Magic:       []byte{0xCA, 0xFE, 0xBA, 0xBE},
		Offset:      0,
		Description: "Java class file, Mach-O Fat Binary",
		Extension:   "class",
		MIME:        "",
	},

	{
		Magic:       []byte{0xEF, 0xBB, 0xBF},
		Offset:      0,
		Description: "UTF-8 encoded Unicode byte order mark, commonly seen in text files.",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFE, 0xED, 0xFA, 0xCE},
		Offset:      0,
		Description: "Mach-O binary (32-bit)",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFE, 0xED, 0xFA, 0xCF},
		Offset:      0,
		Description: "Mach-O binary (64-bit)",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFE, 0xED, 0xFE, 0xED},
		Offset:      0,
		Description: "JKS JavakeyStore",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xCE, 0xFA, 0xED, 0xFE},
		Offset:      0,
		Description: "Mach-O binary (reverse byte ordering scheme, 32-bit)",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xCF, 0xFA, 0xED, 0xFE},
		Offset:      0,
		Description: "Mach-O binary (reverse byte ordering scheme, 64-bit)",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFF, 0xFE},
		Offset:      0,
		Description: "Byte-order mark for text file encoded in little-endian 16-bit Unicode Transfer Format",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFF, 0xFE, 0x00, 0x00},
		Offset:      0,
		Description: "Byte-order mark for text file encoded in little-endian 32-bit Unicode Transfer Format",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x25, 0x21, 0x50, 0x53},
		Offset:      0,
		Description: "PostScript document",
		Extension:   "ps",
		MIME:        "",
	},

	{
		Magic:       []byte{0x25, 0x50, 0x44, 0x46, 0x2d},
		Offset:      0,
		Description: "PDF document",
		Extension:   "pdf",
		MIME:        "",
	},

	{
		Magic:       []byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C},
		Offset:      0,
		Description: "Advanced Systems Format",
		Extension:   "asf",
		MIME:        "",
	},

	{
		Magic:       []byte{0x24, 0x53, 0x44, 0x49, 0x30, 0x30, 0x30, 0x31},
		Offset:      0,
		Description: "System Deployment Image, a disk image format used by Microsoft",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4F, 0x67, 0x67, 0x53},
		Offset:      0,
		Description: "Ogg, an open source media container format",
		Extension:   "ogg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x38, 0x42, 0x50, 0x53},
		Offset:      0,
		Description: "Photoshop Document file, Adobe Photoshop's native file format",
		Extension:   "psd",
		MIME:        "",
	},

	{
		Magic:  []byte{0x52, 0x49, 0x46, 0x46},
		Offset: 0,
		children: []FileType{
			{
				Magic:       []byte{0x57, 0x41, 0x56, 0x45},
				Offset:      4,
				Description: "Waveform Audio File Format",
				Extension:   "wav",
				MIME:        "",
			},
			{
				Magic:       []byte{0x41, 0x56, 0x49, 0x20},
				Offset:      4,
				Description: "Audio Video Interleave video format",
				Extension:   "avi",
				MIME:        "",
			},
		},
	},

	{
		Magic:       []byte{0xFF, 0xFB},
		Offset:      0,
		Description: "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)",
		Extension:   "mp3",
		MIME:        "",
	},

	{
		Magic:       []byte{0x49, 0x44, 0x33},
		Offset:      0,
		Description: "MP3 file with an ID3v2 container",
		Extension:   "mp3",
		MIME:        "",
	},

	{
		Magic:       []byte{0x42, 0x4D},
		Offset:      0,
		Description: "BMP file, a bitmap format used mostly in the Windows world",
		Extension:   "bmp",
		MIME:        "",
	},

	{
		Magic:       []byte{0x43, 0x44, 0x30, 0x30, 0x31},
		Offset:      0x8001,
		Description: "ISO9660 CD/DVD image file",
		Extension:   "iso",
		MIME:        "",
	},

	{
		Magic:       []byte{0x53, 0x49, 0x4D, 0x50, 0x4C, 0x45, 0x20, 0x20},
		Offset:      0,
		Description: "Flexible Image Transport System (FITS)",
		Extension:   "fits",
		MIME:        "",
	},

	{
		Magic:       []byte{0x3D, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x54},
		Offset:      0,
		Description: "Flexible Image Transport System (FITS)",
		Extension:   "fits",
		MIME:        "",
	},

	{
		Magic:       []byte{0x66, 0x4C, 0x61, 0x43},
		Offset:      0,
		Description: "Free Lossless Audio Codec",
		Extension:   "flac",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4D, 0x54, 0x68, 0x64},
		Offset:      0,
		Description: "MIDI sound file",
		Extension:   "mid",
		MIME:        "",
	},

	{
		Magic:       []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
		Offset:      0,
		Description: "Compound File Binary Format, a container format used for document by older versions of Microsoft Office.[21] It is however an open format used by other programs as well.",
		Extension:   "doc",
		MIME:        "",
	},

	{
		Magic:       []byte{0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00},
		Offset:      0,
		Description: "Dalvik Executable",
		Extension:   "dex",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4B, 0x44, 0x4D},
		Offset:      0,
		Description: "VMDK files[22]",
		Extension:   "vmdk",
		MIME:        "",
	},

	{
		Magic:       []byte{0x43, 0x72, 0x32, 0x34},
		Offset:      0,
		Description: "Google Chrome extension[24] or packaged app",
		Extension:   "crx",
		MIME:        "",
	},

	{
		Magic:       []byte{0x41, 0x47, 0x44, 0x33},
		Offset:      0,
		Description: "FreeHand 8 document[26][27]",
		Extension:   "fh8",
		MIME:        "",
	},

	{
		Magic:       []byte{0x05, 0x07, 0x00, 0x00, 0x42, 0x4F, 0x42, 0x4F, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		Offset:      0,
		Description: "AppleWorks 5 document",
		Extension:   "cwk",
		MIME:        "",
	},

	{
		Magic:       []byte{0x06, 0x07, 0xE1, 0x00, 0x42, 0x4F, 0x42, 0x4F, 0x06, 0x07, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		Offset:      0,
		Description: "AppleWorks 6 document",
		Extension:   "cwk",
		MIME:        "",
	},

	{
		Magic:       []byte{0x45, 0x52, 0x02, 0x00, 0x00, 0x00},
		Offset:      0,
		Description: "Roxio Toast disc image file, also some .dmg-files begin with same bytes",
		Extension:   "toast",
		MIME:        "",
	},

	{
		Magic:       []byte{0x8B, 0x45, 0x52, 0x02, 0x00, 0x00, 0x00},
		Offset:      0,
		Description: "Roxio Toast disc image file, also some .dmg-files begin with same bytes",
		Extension:   "toast",
		MIME:        "",
	},

	{
		Magic:       []byte{0x78, 0x01, 0x73, 0x0D, 0x62, 0x62, 0x60},
		Offset:      0,
		Description: "Apple Disk Image file",
		Extension:   "dmg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x78, 0x61, 0x72, 0x21},
		Offset:      0,
		Description: "eXtensible ARchive format",
		Extension:   "xar",
		MIME:        "",
	},

	{
		Magic:       []byte{0x50, 0x4D, 0x4F, 0x43, 0x43, 0x4D, 0x4F, 0x43},
		Offset:      0,
		Description: "Windows Files And Settings Transfer Repository",
		Extension:   "dat",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4E, 0x45, 0x53, 0x1A},
		Offset:      0,
		Description: "Nintendo Entertainment System ROM file",
		Extension:   "nes",
		MIME:        "",
	},

	{
		Magic:       []byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30},
		Offset:      0x101,
		Description: "tar archive",
		Extension:   "tar",
		MIME:        "",
	},

	{
		Magic:       []byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00},
		Offset:      0x101,
		Description: "tar archive",
		Extension:   "tar",
		MIME:        "",
	},

	{
		Magic:       []byte{0x74, 0x6F, 0x78, 0x33},
		Offset:      0,
		Description: "Open source portable voxel file",
		Extension:   "tox",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4D, 0x4C, 0x56, 0x49},
		Offset:      0,
		Description: "Magic Lantern Video file",
		Extension:   "mlv",
		MIME:        "",
	},

	{
		Magic:       []byte{0x44, 0x43, 0x4D, 0x01, 0x50, 0x41, 0x33, 0x30},
		Offset:      0,
		Description: "Windows Update Binary Delta Compression",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
		Offset:      0,
		Description: "7-Zip File Format",
		Extension:   "7z",
		MIME:        "",
	},

	{
		Magic:       []byte{0x1F, 0x8B},
		Offset:      0,
		Description: "GZIP compressed file",
		Extension:   "gz",
		MIME:        "",
	},

	{
		Magic:       []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00},
		Offset:      0,
		Description: "XZ compression utility using LZMA2 compression",
		Extension:   "xz",
		MIME:        "",
	},

	{
		Magic:       []byte{0x04, 0x22, 0x4D, 0x18},
		Offset:      0,
		Description: "LZ4 Frame Format",
		Extension:   "lz4",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4D, 0x53, 0x43, 0x46},
		Offset:      0,
		Description: "Microsoft Cabinet file",
		Extension:   "cab",
		MIME:        "",
	},

	{
		Magic:       []byte{0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33},
		Offset:      0,
		Description: "Microsoft compressed file in Quantum format",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x46, 0x4C, 0x49, 0x46},
		Offset:      0,
		Description: "Free Lossless Image Format",
		Extension:   "flif",
		MIME:        "",
	},

	{
		Magic:       []byte{0x1A, 0x45, 0xDF, 0xA3},
		Offset:      0,
		Description: "Matroska media container, including WebM",
		Extension:   "webm",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4D, 0x49, 0x4C, 0x20},
		Offset:      0,
		Description: "SEAN: Session Analysis Training file",
		Extension:   "stg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x30, 0x82},
		Offset:      0,
		Description: "DER encoded X.509 certificate",
		Extension:   "der",
		MIME:        "",
	},

	{
		Magic:       []byte{0x44, 0x49, 0x43, 0x4D},
		Offset:      0x80,
		Description: "DICOM Medical File Format",
		Extension:   "dcm",
		MIME:        "",
	},

	{
		Magic:       []byte{0x77, 0x4F, 0x46, 0x46},
		Offset:      0,
		Description: "WOFF File Format 1.0",
		Extension:   "woff",
		MIME:        "",
	},

	{
		Magic:       []byte{0x77, 0x4F, 0x46, 0x32},
		Offset:      0,
		Description: "WOFF File Format 2.0",
		Extension:   "woff2",
		MIME:        "",
	},

	{
		Magic:       []byte{0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20},
		Offset:      0,
		Description: "eXtensible Markup Language when using the ASCII character encoding",
		Extension:   "XML",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x61, 0x73, 0x6d},
		Offset:      0,
		Description: "WebAssembly binary format",
		Extension:   "wasm",
		MIME:        "",
	},

	{
		Magic:       []byte{0xcf, 0x84, 0x01},
		Offset:      0,
		Description: "Lepton compressed JPEG image",
		Extension:   "lep",
		MIME:        "",
	},

	{
		Magic:       []byte{0x43, 0x57, 0x53},
		Offset:      0,
		Description: "flash .swf",
		Extension:   "swf",
		MIME:        "",
	},

	{
		Magic:       []byte{0x46, 0x57, 0x53},
		Offset:      0,
		Description: "flash .swf",
		Extension:   "swf",
		MIME:        "",
	},

	{
		Magic:       []byte{0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E},
		Offset:      0,
		Description: "linux deb file",
		Extension:   "deb",
		MIME:        "",
	},

	{
		Magic:  []byte{0x52, 0x49, 0x46, 0x46},
		Offset: 0,
		children: []FileType{
			{
				Magic:       []byte{0x57, 0x45, 0x42, 0x50},
				Offset:      4,
				Description: "Google WebP image file",
				Extension:   "webp",
				MIME:        "",
			},
		},
	},

	{
		Magic:       []byte{0x27, 0x05, 0x19, 0x56},
		Offset:      0,
		Description: "U-Boot/uImage/Das U-Boot/Universal Boot Loader.",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31},
		Offset:      0,
		Description: "Rich Text Format",
		Extension:   "rtf",
		MIME:        "",
	},

	{
		Magic:       []byte{0x54, 0x41, 0x50, 0x45},
		Offset:      0,
		Description: "Microsoft Tape Format",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x47},
		Offset:      0,
		Description: "MPEG Transport Stream (MPEG-2 Part 1)",
		Extension:   "ts",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x00, 0x01, 0xBA},
		Offset:      0,
		Description: "MPEG Program Stream  (MPEG-1 Part 1 (essentially identical) and MPEG-2 Part 1)",
		Extension:   "m2p",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x00, 0x01, 0xBA},
		Offset:      0,
		Description: "MPEG Program Stream",
		Extension:   "mpg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x47},
		Offset:      0,
		Description: "MPEG Program Stream",
		Extension:   "mpg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x00, 0x00, 0x01, 0xB3},
		Offset:      0,
		Description: "MPEG Program Stream",
		Extension:   "mpg",
		MIME:        "",
	},

	{
		Magic:       []byte{0x78, 0x01},
		Offset:      0,
		Description: "zlib: No/Low Compression",
		Extension:   "zlib",
		MIME:        "",
	},

	{
		Magic:       []byte{0x78, 0x9C},
		Offset:      0,
		Description: "zlib: Default Compression",
		Extension:   "zlib",
		MIME:        "",
	},

	{
		Magic:       []byte{0x78, 0xDA},
		Offset:      0,
		Description: "zlib: Best Compression",
		Extension:   "zlib",
		MIME:        "",
	},

	{
		Magic:       []byte{0x62, 0x76, 0x78, 0x32},
		Offset:      0,
		Description: "LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding. OSS by Apple.",
		Extension:   "lzfse",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4F, 0x52, 0x43},
		Offset:      0,
		Description: "Apache ORC (Optimized Row Columnar) file format",
		Extension:   "orc",
		MIME:        "",
	},

	{
		Magic:       []byte{0x4F, 0x62, 0x6A, 0x01},
		Offset:      0,
		Description: "Apache Avro binary file format",
		Extension:   "avro",
		MIME:        "",
	},

	{
		Magic:       []byte{0x53, 0x45, 0x51, 0x36},
		Offset:      0,
		Description: "RCFile columnar file format",
		Extension:   "rc",
		MIME:        "",
	},

	{
		Magic:       []byte{0x65, 0x87, 0x78, 0x56},
		Offset:      0,
		Description: "PhotoCap Object Templates",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x55, 0x55, 0xaa, 0xaa},
		Offset:      0,
		Description: "PhotoCap Vector",
		Extension:   "pcv",
		MIME:        "",
	},

	{
		Magic:       []byte{0x78, 0x56, 0x34},
		Offset:      0,
		Description: "PhotoCap Template",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x50, 0x41, 0x52, 0x31},
		Offset:      0,
		Description: "Apache Parquet columnar file format",
		Extension:   "",
		MIME:        "",
	},

	{
		Magic:       []byte{0x45, 0x4D, 0x58, 0x32},
		Offset:      0,
		Description: "Emulator Emaxsynth samples",
		Extension:   "ez2",
		MIME:        "",
	},

	{
		Magic:       []byte{0x45, 0x4D, 0x55, 0x33},
		Offset:      0,
		Description: "Emulator III synth samples",
		Extension:   "ez3",
		MIME:        "",
	},

	{
		Magic:       []byte{0x1B, 0x4C, 0x75, 0x61},
		Offset:      0,
		Description: "Lua bytecode",
		Extension:   "luac",
		MIME:        "",
	},

	{
		Magic:       []byte{0x62, 0x6F, 0x6F, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x6D, 0x61, 0x72, 0x6B, 0x00, 0x00, 0x00, 0x00},
		Offset:      0,
		Description: "macOS file Alias[46]  (Symbolic link)",
		Extension:   "alias",
		MIME:        "",
	},

	{
		Magic:       []byte{0x5B, 0x5A, 0x6F, 0x6E, 0x65, 0x54, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65, 0x72, 0x5D},
		Offset:      0,
		Description: "Microsoft Zone Identifier for URL Security Zones",
		Extension:   "Identifier",
		MIME:        "",
	},

	{
		Magic:       []byte{0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64},
		Offset:      0,
		Description: "Email Message var5",
		Extension:   "eml",
		MIME:        "",
	},

	{
		Magic:       []byte{0x20, 0x02, 0x01, 0x62, 0xA0, 0x1E, 0xAB, 0x07, 0x02, 0x00, 0x00, 0x00},
		Offset:      0,
		Description: "Tableau Datasource",
		Extension:   "tde",
		MIME:        "",
	},

	{
		Magic:       []byte{0x28, 0xB5, 0x2F, 0xFD},
		Offset:      0,
		Description: "Zstandard compressed file[49]",
		Extension:   "zst",
		MIME:        "",
	},
}
