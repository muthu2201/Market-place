package antivirus

import (
	"strings"
	"testing"
)

func TestDetectTypeIdentifiesRealFormats(t *testing.T) {
	cases := []struct {
		name     string
		head     []byte
		filename string
		want     string
	}{
		{"PNG", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13}, "art.png", "image/png"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 16, 'J', 'F', 'I', 'F'}, "photo.jpg", "image/jpeg"},
		{"PDF", []byte("%PDF-1.7\n%\xE2\xE3\xCF\xD3"), "guide.pdf", "application/pdf"},
		{"GIF", []byte("GIF89a\x01\x00\x01\x00"), "loop.gif", "image/gif"},
		{"FLAC", []byte("fLaC\x00\x00\x00\x22"), "master.flac", "audio/flac"},
		{"OGG", []byte("OggS\x00\x02\x00\x00"), "loop.ogg", "audio/ogg"},
		{"MIDI", []byte("MThd\x00\x00\x00\x06"), "score.mid", "audio/midi"},
		{"WOFF2", []byte("wOF2\x00\x01\x00\x00"), "face.woff2", "font/woff2"},
		{"OTF", []byte("OTTO\x00\x0A\x00\x80"), "face.otf", "font/otf"},
		{"TTF", []byte{0x00, 0x01, 0x00, 0x00, 0, 12, 0, 128}, "face.ttf", "font/ttf"},
		{"PSD", []byte("8BPS\x00\x01\x00\x00"), "layered.psd", "image/vnd.adobe.photoshop"},
		{"7z", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4}, "bundle.7z", "application/x-7z-compressed"},
		{"gzip", []byte{0x1F, 0x8B, 0x08, 0x00}, "bundle.gz", "application/gzip"},
		{"SVG", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">`), "icon.svg", "image/svg+xml"},
		{"unknown is not an error", []byte("BLENDER-v303RENDH"), "scene.blend", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, mismatch := DetectType(tc.head, tc.filename)
			if got != tc.want {
				t.Errorf("detected %q, want %q", got, tc.want)
			}
			if mismatch != "" {
				t.Errorf("unexpected mismatch: %s", mismatch)
			}
		})
	}
}

// TestDetectTypeSeparatesSharedContainers covers the formats that would
// otherwise all read as "application/zip" or "RIFF".
func TestDetectTypeSeparatesSharedContainers(t *testing.T) {
	cases := []struct {
		name     string
		head     []byte
		filename string
		want     string
	}{
		{"docx", zipWithFirstMember("word/document.xml", nil), "brief.docx",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		{"xlsx", zipWithFirstMember("xl/workbook.xml", nil), "model.xlsx",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		{"pptx", zipWithFirstMember("ppt/presentation.xml", nil), "deck.pptx",
			"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
		{"epub", zipWithFirstMember("mimetype", []byte("application/epub+zip")), "novel.epub",
			"application/epub+zip"},
		{"odt", zipWithFirstMember("mimetype", []byte("application/vnd.oasis.opendocument.text")), "notes.odt",
			"application/vnd.oasis.opendocument.text"},
		{"plain zip", zipWithFirstMember("assets/readme.txt", nil), "bundle.zip", "application/zip"},
		{"webp", riff("WEBP"), "hero.webp", "image/webp"},
		{"wav", riff("WAVE"), "stem.wav", "audio/wav"},
		{"avi", riff("AVI "), "clip.avi", "video/x-msvideo"},
		{"mp4", ftyp("isom"), "trailer.mp4", "video/mp4"},
		{"quicktime", ftyp("qt  "), "trailer.mov", "video/quicktime"},
		{"avif", ftyp("avif"), "hero.avif", "image/avif"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, mismatch := DetectType(tc.head, tc.filename)
			if got != tc.want {
				t.Errorf("detected %q, want %q", got, tc.want)
			}
			if mismatch != "" {
				t.Errorf("unexpected mismatch: %s", mismatch)
			}
		})
	}
}

// TestDetectTypeRefusesExecutables is the control that matters most: a buyer
// must never be able to purchase something their operating system will run.
func TestDetectTypeRefusesExecutables(t *testing.T) {
	cases := []struct {
		name     string
		head     []byte
		filename string
	}{
		{"Windows PE named as a font", []byte("MZ\x90\x00\x03\x00\x00\x00"), "helvetica.otf"},
		{"Linux ELF named as a texture", []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}, "texture.png"},
		{"Mach-O named as an archive", []byte{0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1}, "bundle.zip"},
		{"Java class named as audio", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61}, "loop.mp3"},
		{"shell script named as a preset", []byte("#!/bin/sh\nrm -rf /\n"), "preset.xmp"},
		{"HTML named as an image", []byte("<!DOCTYPE html><html><script>alert(1)</script>"), "logo.png"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, mismatch := DetectType(tc.head, tc.filename)
			if mismatch == "" {
				t.Fatalf("executable content was accepted as %q", tc.filename)
			}
			t.Logf("refused: %s", mismatch)
		})
	}
}

// TestDetectTypeRefusesDangerousExtensions covers the other direction: content
// we do not recognise, named as something that executes on a double-click.
func TestDetectTypeRefusesDangerousExtensions(t *testing.T) {
	for _, name := range []string{
		"installer.exe", "setup.msi", "run.bat", "go.cmd", "macro.vbs",
		"helper.ps1", "tool.jar", "app.dmg", "hook.sh", "shortcut.lnk",
	} {
		if _, mismatch := DetectType([]byte("this content is unremarkable"), name); mismatch == "" {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestDetectTypeAllowsUnknownFormats guards against the opposite failure. A
// marketplace that rejected every format it did not have a signature for would
// reject most of a real catalogue.
func TestDetectTypeAllowsUnknownFormats(t *testing.T) {
	for _, f := range []struct {
		name string
		head []byte
	}{
		{"project.blend", []byte("BLENDER-v303RENDH\x00\x00")},
		{"brushes.abr", []byte("\x00\x06\x00\x02\x00\x00")},
		{"session.logicx", []byte("logic-arbitrary-bytes-here")},
		{"preset.ffx", []byte("arbitrary after effects preset")},
		{"model.c4d", []byte("\x00\x00\x00\x00C4D-payload")},
	} {
		if _, mismatch := DetectType(f.head, f.name); mismatch != "" {
			t.Errorf("%s was refused: %s", f.name, mismatch)
		}
	}
}

// TestDetectTypeMismatchExplainsItself: a moderator acts on the text, so the
// text has to say which two things disagreed.
func TestDetectTypeMismatchExplainsItself(t *testing.T) {
	_, mismatch := DetectType([]byte("%PDF-1.4\n"), "cover.png")
	if mismatch == "" {
		t.Fatal("a PDF named .png should be a mismatch")
	}
	for _, want := range []string{"application/pdf", ".png"} {
		if !strings.Contains(mismatch, want) {
			t.Errorf("explanation %q does not mention %q", mismatch, want)
		}
	}
}

func TestDetectTypeHandlesShortAndEmptyInput(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0x89}, {0x89, 'P', 'N'}} {
		if got, _ := DetectType(b, "x.bin"); got != "" {
			t.Errorf("%d bytes detected as %q; too little input must detect nothing", len(b), got)
		}
	}
}

// ---- builders ---------------------------------------------------------------

// zipWithFirstMember builds a ZIP local file header naming one member, which is
// all the sniffer reads.
func zipWithFirstMember(name string, extra []byte) []byte {
	b := make([]byte, 30)
	copy(b, "PK\x03\x04")
	b[26] = byte(len(name))
	b[27] = byte(len(name) >> 8)
	b = append(b, name...)
	return append(b, extra...)
}

func riff(form string) []byte {
	b := append([]byte("RIFF"), 0x24, 0, 0, 0)
	return append(b, form...)
}

func ftyp(brand string) []byte {
	b := append([]byte{0, 0, 0, 0x20}, "ftyp"...)
	return append(b, brand...)
}
