package magic

import (
	"bytes"
	"testing"

	"gotest.tools/assert"
)

func TestIdentifyWithFilename(t *testing.T) {

	tests := []struct {
		filename     string
		expectedMIME string
	}{
		{
			filename:     "test.txt",
			expectedMIME: "text/plain",
		},
		{
			filename:     "test.jpg",
			expectedMIME: "image/jpeg",
		},
		{
			filename:     "test.png",
			expectedMIME: "image/png",
		},
		{
			filename:     "test.gif",
			expectedMIME: "image/gif",
		},
		{
			filename:     "test.pdf",
			expectedMIME: "application/pdf",
		},
		{
			filename:     "test.zip",
			expectedMIME: "application/zip",
		},
		{
			filename:     "test.tar",
			expectedMIME: "application/x-tar",
		},
		{
			filename:     "test.gz",
			expectedMIME: "application/gzip",
		},
		{
			filename:     "test.bz2",
			expectedMIME: "application/x-bzip2",
		},
		{
			filename:     "test.mp3",
			expectedMIME: "audio/mpeg",
		},
		{
			filename:     "test.mp4",
			expectedMIME: "video/mp4",
		},
		{
			filename:     "test.avi",
			expectedMIME: "video/vnd.avi",
		},
		{
			filename:     "test.mkv",
			expectedMIME: "video/x-matroska",
		},
		{
			filename:     "test.wav",
			expectedMIME: "audio/vnd.wave",
		},
		{
			filename:     "test.flac",
			expectedMIME: "audio/flac",
		},
		{
			filename:     "test.ogg",
			expectedMIME: "audio/ogg",
		},
		{
			filename:     "test.webm",
			expectedMIME: "video/webm",
		},
		{
			filename:     "test.html",
			expectedMIME: "text/html",
		},
		{
			filename:     "test.css",
			expectedMIME: "text/css",
		},
		{
			filename:     "test.js",
			expectedMIME: "text/javascript",
		},
		{
			filename:     "test.json",
			expectedMIME: "application/json",
		},
		{
			filename:     "test.xml",
			expectedMIME: "application/xml",
		},
		{
			filename:     "test.svg",
			expectedMIME: "image/svg+xml",
		},
		{
			filename:     "test.webp",
			expectedMIME: "image/webp",
		},
		{
			filename:     "test.ico",
			expectedMIME: "image/vnd.microsoft.icon",
		},
		{
			filename:     "test.bmp",
			expectedMIME: "image/bmp",
		},
		{
			filename:     "test.tiff",
			expectedMIME: "image/tiff",
		},
		{
			filename:     "test.psd",
			expectedMIME: "image/vnd.adobe.photoshop",
		},
		{
			filename:     "test.doc",
			expectedMIME: "application/msword",
		},
		{
			filename:     "test.docx",
			expectedMIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		},
		{
			filename:     "test.xls",
			expectedMIME: "application/vnd.ms-excel",
		},
		{
			filename:     "test.xlsx",
			expectedMIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		},
		{
			filename:     "test.ppt",
			expectedMIME: "application/vnd.ms-powerpoint",
		},
		{
			filename:     "test.pptx",
			expectedMIME: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		},
		{
			filename:     "test.7z",
			expectedMIME: "application/x-7z-compressed",
		},
		{
			filename:     "test.rar",
			expectedMIME: "application/vnd.rar",
		},
		{
			filename:     "test.exe",
			expectedMIME: "application/x-msdownload",
		},
		{
			filename:     "test.dmg",
			expectedMIME: "application/x-apple-diskimage",
		},
		{
			filename:     "test.deb",
			expectedMIME: "application/vnd.debian.binary-package",
		},
		{
			filename:     "test.rpm",
			expectedMIME: "application/x-rpm",
		},
		{
			filename:     "test.iso",
			expectedMIME: "application/vnd.efi.iso",
		},
		{
			filename:     "test.ttf",
			expectedMIME: "font/ttf",
		},
		{
			filename:     "test.otf",
			expectedMIME: "application/vnd.oasis.opendocument.formula-template",
		},
		{
			filename:     "test.woff",
			expectedMIME: "font/woff",
		},
		{
			filename:     "test.woff2",
			expectedMIME: "font/woff2",
		},
		{
			filename:     "test.csv",
			expectedMIME: "text/csv",
		},
		{
			filename:     "test.md",
			expectedMIME: "text/markdown",
		},
		{
			filename:     "test.yaml",
			expectedMIME: "application/yaml",
		},
		{
			filename:     "test.yml",
			expectedMIME: "application/yaml",
		},
		{
			filename:     "test.sh",
			expectedMIME: "application/x-shellscript",
		},
	}

	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			fileType := IdentifyWithFilename(bytes.NewBuffer(nil), test.filename)
			assert.Equal(t, fileType.MIME, test.expectedMIME)
		})
	}

}

func TestIdentifyBytes(t *testing.T) {

	tests := []struct {
		data         []byte
		expectedMIME string
		detail       string // optional
	}{
		{
			data:         []byte("this is a non-specific file type"),
			expectedMIME: "text/plain",
			detail:       "non-specific text file type",
		},
		{
			data:         []byte("\x99\x99\x99\x99"),
			expectedMIME: "application/octet-stream",
			detail:       "non-specific binary file type",
		},
		{
			data:         []byte("ID3"),
			expectedMIME: "audio/mpeg",
			detail:       "MP3",
		},
		{
			data:         []byte("\x89PNG\r\n\x1a\n"),
			expectedMIME: "image/png",
			detail:       "PNG",
		},
		{
			data:         []byte("\xff\xd8\xff"),
			expectedMIME: "image/jpeg",
			detail:       "JPEG",
		},
		{
			data:         []byte("GIF87a"),
			expectedMIME: "image/gif",
			detail:       "GIF87a",
		},
		{
			data:         []byte("GIF89a"),
			expectedMIME: "image/gif",
			detail:       "GIF89a",
		},
		{
			data:         []byte("%PDF-1."),
			expectedMIME: "application/pdf",
			detail:       "PDF",
		},
		{
			data:         []byte("PK\x03\x04"),
			expectedMIME: "application/zip",
			detail:       "ZIP",
		},
		{
			data:         []byte("\x1f\x8b\x08"),
			expectedMIME: "application/gzip",
			detail:       "GZIP",
		},
		{
			data:         []byte("BZh"),
			expectedMIME: "application/x-bzip2",
			detail:       "BZIP2",
		},
		{
			data:         []byte("Rar!\x1a\x07"),
			expectedMIME: "application/vnd.rar",
			detail:       "RAR",
		},
		{
			data:         []byte("7z\xbc\xaf\x27\x1c"),
			expectedMIME: "application/x-7z-compressed",
			detail:       "7-Zip",
		},
		{
			data:         []byte("MZ"),
			expectedMIME: "application/x-msdownload",
			detail:       "Windows executable",
		},
		{
			data:         []byte("\x7fELF\x02\x01"),
			expectedMIME: "application/x-executable",
			detail:       "ELF executable",
		},
		{
			data:         []byte("\xcf\xfa\xed\xfe"),
			expectedMIME: "application/x-mach-binary",
			detail:       "Mach-O binary (64-bit little-endian)",
		},
		{
			data:         []byte("<!DOCTYPE html>"),
			expectedMIME: "text/html",
			detail:       "HTML with DOCTYPE",
		},
		{
			data:         []byte("<html>"),
			expectedMIME: "text/html",
			detail:       "HTML",
		},
		{
			data:         []byte("<?xml"),
			expectedMIME: "application/xml",
			detail:       "XML",
		},
		{
			data:         []byte("RIFF....WAVE"),
			expectedMIME: "audio/vnd.wave",
			detail:       "WAV",
		},
		{
			data:         []byte("fLaC"),
			expectedMIME: "audio/flac",
			detail:       "FLAC",
		},
		{
			data:         []byte("OggS"),
			expectedMIME: "application/ogg",
			detail:       "Ogg",
		},
		{
			data:         []byte("\x00\x00\x00\x18ftypmp42"),
			expectedMIME: "video/mp4",
			detail:       "MP4",
		},
		{
			data:         []byte("\x00\x00\x00\x20ftypisom"),
			expectedMIME: "video/mp4",
			detail:       "MP4 ISOM",
		},
		{
			data:         []byte("\x1aE\xdf\xa3.\x42\x82.webm"),
			expectedMIME: "video/webm",
			detail:       "WebM",
		},
		{
			data:         []byte("BM............\x0c"),
			expectedMIME: "image/bmp",
			detail:       "BMP",
		},
		{
			data:         []byte("II*\x00"),
			expectedMIME: "image/tiff",
			detail:       "TIFF little-endian",
		},
		{
			data:         []byte("MM\x00*"),
			expectedMIME: "image/tiff",
			detail:       "TIFF big-endian",
		},
		{
			data:         []byte("\x00\x00\x01\x00\x00\x00"),
			expectedMIME: "image/vnd.microsoft.icon",
			detail:       "ICO",
		},
		{
			data:         []byte("8BPS..\x00\x00\x00\x00"),
			expectedMIME: "image/vnd.adobe.photoshop",
			detail:       "PSD",
		},
		{
			data: append(
				append(
					[]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
					bytes.Repeat([]byte{0}, 504)...,
				),
				[]byte("\xec\xa5\x00\x00")...,
			),
			expectedMIME: "application/msword",
			detail:       "MS Office document",
		},
		{
			data:         append(bytes.Repeat([]byte{0}, 257), []byte("ustar\x00")...),
			expectedMIME: "application/x-tar",
			detail:       "TAR",
		},
		{
			data:         append(bytes.Repeat([]byte{0}, 257), []byte("ustar\x20\x20\x00")...),
			expectedMIME: "application/x-tar",
			detail:       "TAR (old format)",
		},
		{
			data:         []byte("\xfd7zXZ\x00"),
			expectedMIME: "application/x-xz",
			detail:       "XZ",
		},
		{
			data:         []byte("!<arch>\n"),
			expectedMIME: "application/x-archive",
			detail:       "AR archive",
		},
		{
			data:         []byte("\x1f\x9d"),
			expectedMIME: "application/x-compress",
			detail:       "Unix compress",
		},
		{
			data:         []byte("#!/bin/sh"),
			expectedMIME: "application/x-shellscript",
			detail:       "Shell script (sh)",
		},
		{
			data:         []byte("#!/bin/bash"),
			expectedMIME: "application/x-shellscript",
			detail:       "Shell script (bash)",
		},
		{
			data:         []byte("#!/usr/bin/env python"),
			expectedMIME: "text/x-python",
			detail:       "Python script",
		},
		{
			data:         []byte("\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a........jp2\x20"),
			expectedMIME: "image/jp2",
			detail:       "JPEG 2000",
		},
		{
			data:         []byte("-----BEGIN CERTIFICATE-----"),
			expectedMIME: "application/pkix-cert",
			detail:       "PKIX certificate",
		},
		{
			data:         []byte("SQLite format 3\x00"),
			expectedMIME: "application/vnd.sqlite3",
			detail:       "SQLite database",
		},
		{
			data:         []byte("FFIL"),
			expectedMIME: "font/ttf",
			detail:       "TrueType font",
		},
		{
			data:         []byte("OTTO\x00"),
			expectedMIME: "font/otf",
			detail:       "OpenType font",
		},
		{
			data:         []byte("wOFF"),
			expectedMIME: "font/woff",
			detail:       "WOFF font",
		},
		{
			data:         []byte("wOF2"),
			expectedMIME: "font/woff2",
			detail:       "WOFF2 font",
		},
	}

	for _, test := range tests {
		name := test.expectedMIME
		if test.detail != "" {
			name = test.detail
		}
		t.Run(name, func(t *testing.T) {
			fileType := Identify(bytes.NewBuffer(test.data))
			assert.Equal(t, fileType.MIME, test.expectedMIME)
		})
	}
}
