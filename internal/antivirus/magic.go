package antivirus

import (
	"bytes"
	"encoding/binary"
	"path"
	"strings"
)

// sniffLen is how many leading bytes are kept for type detection. Every
// signature below fits well inside it, and ZIP central-directory inspection
// works from the local header at offset 0.
const sniffLen = 1024

// DetectType reports what the bytes actually are, and a non-empty explanation
// when that disagrees with the filename in a way that matters.
//
// The two checks are deliberately asymmetric. An *unknown* type is not a
// finding: a marketplace sells Blender scenes, Procreate brushes and Logic
// projects, and a system that rejected everything it did not recognise would
// reject most of the catalogue. A *dangerous* type, or a dangerous type wearing
// a harmless extension, is always a finding.
func DetectType(head []byte, filename string) (detected string, mismatch string) {
	detected = sniff(head)
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(filename), "."))

	if isDangerous(detected) {
		return detected, "the file is an executable or system binary (" + detected +
			"), which is never a deliverable digital product"
	}

	// A dangerous extension with unrecognised content is still a finding: an
	// uploader who names something .exe is telling us what they intend it to be.
	if dangerousExtensions[ext] {
		return detected, "the filename claims a directly executable type (." + ext +
			"), which is never a deliverable digital product"
	}

	if detected == "" || ext == "" {
		return detected, ""
	}

	// An extension that has a known signature, whose content is something else
	// entirely, is worth a human look. This catches a script or a document
	// dressed as a font or an image — the common shape of a delivery attack.
	if want, known := extensionSignatures[ext]; known && !matchesFamily(detected, want) {
		return detected, "the file is " + detected + " but is named ." + ext +
			", and those are not the same kind of file"
	}
	return detected, ""
}

// matchesFamily allows the legitimate aliasing that real formats have: every
// OOXML document and EPUB is a ZIP, and a JPEG is a JPEG whichever extension
// spelling it carries.
func matchesFamily(detected string, want []string) bool {
	for _, w := range want {
		if detected == w {
			return true
		}
	}
	return false
}

// sniff identifies a type from leading bytes. It returns "" for anything it
// does not recognise, which is a normal and common answer.
func sniff(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	for _, s := range signatures {
		if s.offset+len(s.magic) <= len(b) && bytes.Equal(b[s.offset:s.offset+len(s.magic)], s.magic) {
			if s.refine != nil {
				if t := s.refine(b); t != "" {
					return t
				}
			}
			return s.name
		}
	}
	// Text formats have no magic number, so they are recognised by shape. SVG
	// matters because it is an image that can carry script, which is exactly
	// why deliverable assets are served as attachments from a separate origin.
	if looksLikeXML(b) {
		lower := bytes.ToLower(b)
		switch {
		case bytes.Contains(lower, []byte("<svg")):
			return "image/svg+xml"
		case bytes.Contains(lower, []byte("<!doctype html")), bytes.Contains(lower, []byte("<html")):
			return "text/html"
		}
		return "application/xml"
	}
	if bytes.HasPrefix(b, []byte("#!")) {
		return "text/x-shellscript"
	}
	return ""
}

type signature struct {
	name   string
	offset int
	magic  []byte
	// refine distinguishes formats that share a prefix — every OOXML file and
	// every EPUB starts with the same four ZIP bytes.
	refine func([]byte) string
}

var signatures = []signature{
	// Archives and container formats.
	{name: "application/zip", magic: []byte("PK\x03\x04"), refine: refineZIP},
	{name: "application/zip", magic: []byte("PK\x05\x06")},
	{name: "application/x-7z-compressed", magic: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}},
	{name: "application/vnd.rar", magic: []byte("Rar!\x1A\x07")},
	{name: "application/gzip", magic: []byte{0x1F, 0x8B}},
	{name: "application/x-xz", magic: []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}},
	{name: "application/x-bzip2", magic: []byte("BZh")},
	{name: "application/x-tar", offset: 257, magic: []byte("ustar")},

	// Documents.
	{name: "application/pdf", magic: []byte("%PDF-")},
	{name: "application/rtf", magic: []byte(`{\rtf`)},
	{name: "application/vnd.ms-office", magic: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}},

	// Raster images.
	{name: "image/png", magic: []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}},
	{name: "image/jpeg", magic: []byte{0xFF, 0xD8, 0xFF}},
	{name: "image/gif", magic: []byte("GIF8")},
	{name: "image/bmp", magic: []byte("BM")},
	{name: "image/tiff", magic: []byte{0x49, 0x49, 0x2A, 0x00}},
	{name: "image/tiff", magic: []byte{0x4D, 0x4D, 0x00, 0x2A}},
	{name: "image/vnd.adobe.photoshop", magic: []byte("8BPS")},
	{name: "image/x-icon", magic: []byte{0x00, 0x00, 0x01, 0x00}},
	{name: "image/webp", magic: []byte("RIFF"), refine: refineRIFF},

	// Audio and video.
	{name: "audio/mpeg", magic: []byte("ID3")},
	{name: "audio/mpeg", magic: []byte{0xFF, 0xFB}},
	{name: "audio/flac", magic: []byte("fLaC")},
	{name: "audio/ogg", magic: []byte("OggS")},
	{name: "audio/midi", magic: []byte("MThd")},
	{name: "video/x-matroska", magic: []byte{0x1A, 0x45, 0xDF, 0xA3}},
	{name: "video/mp4", offset: 4, magic: []byte("ftyp"), refine: refineFTYP},

	// Fonts.
	{name: "font/ttf", magic: []byte{0x00, 0x01, 0x00, 0x00}},
	{name: "font/otf", magic: []byte("OTTO")},
	{name: "font/woff", magic: []byte("wOFF")},
	{name: "font/woff2", magic: []byte("wOF2")},

	// Executables — every one of these is a finding, not a format.
	{name: "application/x-dosexec", magic: []byte("MZ")},
	{name: "application/x-elf", magic: []byte{0x7F, 'E', 'L', 'F'}},
	{name: "application/x-mach-binary", magic: []byte{0xFE, 0xED, 0xFA, 0xCE}},
	{name: "application/x-mach-binary", magic: []byte{0xFE, 0xED, 0xFA, 0xCF}},
	{name: "application/x-mach-binary", magic: []byte{0xCF, 0xFA, 0xED, 0xFE}},
	{name: "application/x-mach-binary", magic: []byte{0xCE, 0xFA, 0xED, 0xFE}},
	{name: "application/java-vm", magic: []byte{0xCA, 0xFE, 0xBA, 0xBE}},
	{name: "application/wasm", magic: []byte{0x00, 'a', 's', 'm'}},
}

// refineZIP reads the first local file header's name, which is how OOXML,
// OpenDocument and EPUB identify themselves.
func refineZIP(b []byte) string {
	// Local file header: 30 fixed bytes, then the name, whose length is at
	// offset 26 as a little-endian uint16.
	const nameLenOffset, headerLen = 26, 30
	if len(b) < headerLen {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(b[nameLenOffset : nameLenOffset+2]))
	if n <= 0 || headerLen+n > len(b) {
		return ""
	}
	name := string(b[headerLen : headerLen+n])

	switch {
	case name == "mimetype":
		// OpenDocument and EPUB store an uncompressed mimetype member first,
		// precisely so a sniffer can read it without inflating anything.
		rest := b[headerLen+n:]
		for _, t := range []string{
			"application/epub+zip",
			"application/vnd.oasis.opendocument.text",
			"application/vnd.oasis.opendocument.spreadsheet",
			"application/vnd.oasis.opendocument.presentation",
			"application/vnd.oasis.opendocument.graphics",
		} {
			if bytes.HasPrefix(rest, []byte(t)) {
				return t
			}
		}
	case strings.HasPrefix(name, "word/"):
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case strings.HasPrefix(name, "xl/"):
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case strings.HasPrefix(name, "ppt/"):
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case name == "[Content_Types].xml":
		// An OOXML package whose first member is the content-type map. The
		// specific flavour is inside, which needs inflation; ZIP is enough.
		return "application/zip"
	}
	return ""
}

// refineRIFF separates WebP and WAV, which share the RIFF container.
func refineRIFF(b []byte) string {
	if len(b) < 12 {
		return ""
	}
	switch string(b[8:12]) {
	case "WEBP":
		return "image/webp"
	case "WAVE":
		return "audio/wav"
	case "AVI ":
		return "video/x-msvideo"
	}
	return ""
}

// refineFTYP separates the ISO base media family.
func refineFTYP(b []byte) string {
	if len(b) < 12 {
		return ""
	}
	switch string(b[8:12]) {
	case "qt  ":
		return "video/quicktime"
	case "M4A ":
		return "audio/mp4"
	case "avif", "avis":
		return "image/avif"
	case "heic", "heix", "hevc":
		return "image/heic"
	}
	return "video/mp4"
}

// dangerousTypes never appear in a legitimate deliverable.
//
// A seller shipping software ships source, or an archive — not a bare binary
// the buyer's operating system will execute on a double-click. Refusing these
// costs a genuine use case almost nothing and removes the single most direct
// path from this marketplace to an infected buyer.
var dangerousTypes = map[string]bool{
	"application/x-dosexec":     true,
	"application/x-elf":         true,
	"application/x-mach-binary": true,
	"application/java-vm":       true,
	"text/x-shellscript":        true,
	"text/html":                 true,
}

func isDangerous(t string) bool { return dangerousTypes[t] }

// dangerousExtensions are refused on the name alone, whatever the bytes say.
var dangerousExtensions = map[string]bool{
	"exe": true, "dll": true, "scr": true, "com": true, "pif": true,
	"bat": true, "cmd": true, "ps1": true, "vbs": true, "vbe": true,
	"js": true, "jse": true, "wsf": true, "wsh": true, "hta": true,
	"msi": true, "msp": true, "cpl": true, "jar": true, "app": true,
	"deb": true, "rpm": true, "dmg": true, "pkg": true, "sh": true,
	"lnk": true, "reg": true, "scf": true, "inf": true,
}

// extensionSignatures maps an extension to the content types that legitimately
// carry it. An extension absent from this table is never a mismatch — the map
// is an allow-list of *checks*, not of formats.
var extensionSignatures = map[string][]string{
	"pdf":  {"application/pdf"},
	"png":  {"image/png"},
	"jpg":  {"image/jpeg"},
	"jpeg": {"image/jpeg"},
	"gif":  {"image/gif"},
	"webp": {"image/webp"},
	"bmp":  {"image/bmp"},
	"tif":  {"image/tiff"},
	"tiff": {"image/tiff"},
	"svg":  {"image/svg+xml", "application/xml"},
	"ico":  {"image/x-icon"},
	"psd":  {"image/vnd.adobe.photoshop"},
	"avif": {"image/avif"},
	"heic": {"image/heic"},

	"zip":  {"application/zip"},
	"7z":   {"application/x-7z-compressed"},
	"rar":  {"application/vnd.rar"},
	"gz":   {"application/gzip"},
	"tgz":  {"application/gzip"},
	"xz":   {"application/x-xz"},
	"bz2":  {"application/x-bzip2"},
	"tar":  {"application/x-tar"},
	"epub": {"application/epub+zip", "application/zip"},

	"docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
	"xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
	"pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip"},
	"odt":  {"application/vnd.oasis.opendocument.text", "application/zip"},
	"ods":  {"application/vnd.oasis.opendocument.spreadsheet", "application/zip"},
	"odp":  {"application/vnd.oasis.opendocument.presentation", "application/zip"},
	"doc":  {"application/vnd.ms-office"},
	"xls":  {"application/vnd.ms-office"},
	"ppt":  {"application/vnd.ms-office"},
	"rtf":  {"application/rtf"},

	"mp3":  {"audio/mpeg"},
	"flac": {"audio/flac"},
	"ogg":  {"audio/ogg"},
	"oga":  {"audio/ogg"},
	"wav":  {"audio/wav"},
	"mid":  {"audio/midi"},
	"midi": {"audio/midi"},
	"m4a":  {"audio/mp4", "video/mp4"},
	"mp4":  {"video/mp4"},
	"mov":  {"video/quicktime", "video/mp4"},
	"mkv":  {"video/x-matroska"},
	"avi":  {"video/x-msvideo"},

	"ttf":   {"font/ttf"},
	"otf":   {"font/otf", "font/ttf"},
	"woff":  {"font/woff"},
	"woff2": {"font/woff2"},

	"wasm": {"application/wasm"},
}

func looksLikeXML(b []byte) bool {
	trimmed := bytes.TrimLeft(b, " \t\r\n\ufeff")
	return bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<"))
}
