package provenance

import (
	"bytes"
	"encoding/binary"
	"path"
	"strings"
)

// GeneratorHint reads the authoring tool out of an asset's metadata.
//
// This is the weakest signal in the package and is documented as such wherever
// it surfaces. It is a plain-text field that any uploader can strip in one
// command, so its absence proves nothing at all. Its presence is still worth
// recording: it corroborates an honest declaration, and in aggregate it is how
// a moderation queue notices that a seller's "no AI" catalogue all came out of
// the same generator.
//
// It is never, on its own, grounds for action against a seller.
func GeneratorHint(asset []byte) (tool string, indicatesAI bool) {
	for _, extract := range []func([]byte) string{
		xmpCreatorTool, exifSoftware, pngTextSoftware,
	} {
		if tool = extract(asset); tool != "" {
			break
		}
	}
	if tool == "" {
		return "", false
	}
	return tool, namesGenerator(tool)
}

// knownGenerators are tool names that indicate generative authorship.
//
// The list is a corroboration aid, not a blocklist, and it is deliberately
// conservative: a false entry here turns an honest seller's metadata into an
// accusation. Matching is on a lowercased substring, so version suffixes and
// vendor prefixes still match.
var knownGenerators = []string{
	"stable diffusion", "stablediffusion", "midjourney", "dall-e", "dalle",
	"firefly", "imagen", "flux.1", "comfyui", "automatic1111", "invokeai",
	"leonardo.ai", "nightcafe", "novelai", "playground ai", "ideogram",
	"runway", "sora", "kling", "pika labs", "luma dream machine",
	"suno", "udio", "elevenlabs", "musicgen", "audiocraft",
	"gpt-4", "gpt-5", "claude", "gemini", "llama", "copilot",
}

func namesGenerator(tool string) bool {
	lower := strings.ToLower(tool)
	for _, g := range knownGenerators {
		if strings.Contains(lower, g) {
			return true
		}
	}
	return false
}

// xmpCreatorTool reads xmp:CreatorTool from an embedded XMP packet.
//
// XMP is XML, and it is read here with a bounded scan rather than an XML parser
// on purpose: the input is attacker-controlled, an XML parser is a large attack
// surface (entity expansion, external entities, quadratic blowup), and one
// string out of one well-known element does not justify any of that risk.
func xmpCreatorTool(asset []byte) string {
	start := bytes.Index(asset, []byte("<x:xmpmeta"))
	if start < 0 {
		if start = bytes.Index(asset, []byte("<?xpacket")); start < 0 {
			return ""
		}
	}
	// Bound the region examined: an XMP packet is kilobytes, and a file that
	// claims otherwise is not one we need to read further into.
	end := min(start+maxXMPScan, len(asset))
	packet := asset[start:end]

	for _, tag := range []string{"xmp:CreatorTool", "tiff:Software", "photoshop:History"} {
		if v := xmlElementOrAttribute(packet, tag); v != "" {
			return v
		}
	}
	return ""
}

const maxXMPScan = 128 << 10

// xmlElementOrAttribute finds <tag>value</tag> or tag="value".
func xmlElementOrAttribute(b []byte, tag string) string {
	if open := bytes.Index(b, []byte("<"+tag+">")); open >= 0 {
		rest := b[open+len(tag)+2:]
		if close := bytes.Index(rest, []byte("</"+tag+">")); close >= 0 && close < maxHintLen {
			return sanitiseHint(string(rest[:close]))
		}
	}
	if attr := bytes.Index(b, []byte(tag+"=\"")); attr >= 0 {
		rest := b[attr+len(tag)+2:]
		if close := bytes.IndexByte(rest, '"'); close >= 0 && close < maxHintLen {
			return sanitiseHint(string(rest[:close]))
		}
	}
	return ""
}

// exifSoftware reads EXIF tag 0x0131 (Software) from a JPEG APP1 segment.
func exifSoftware(asset []byte) string {
	app1 := bytes.Index(asset, []byte("Exif\x00\x00"))
	if app1 < 0 {
		return ""
	}
	tiff := asset[app1+6:]
	if len(tiff) < 8 {
		return ""
	}

	var order binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return ""
	}

	ifdOffset := int(order.Uint32(tiff[4:8]))
	if ifdOffset < 8 || ifdOffset+2 > len(tiff) {
		return ""
	}
	count := int(order.Uint16(tiff[ifdOffset : ifdOffset+2]))
	// Each entry is 12 bytes. Bound the count by what the buffer can hold
	// before iterating, rather than trusting the header.
	if count <= 0 || ifdOffset+2+count*12 > len(tiff) {
		return ""
	}

	for i := 0; i < count; i++ {
		e := tiff[ifdOffset+2+i*12:]
		if order.Uint16(e[:2]) != 0x0131 { // Software
			continue
		}
		length := int(order.Uint32(e[4:8]))
		if length <= 1 || length > maxHintLen {
			return ""
		}
		var value []byte
		if length <= 4 {
			value = e[8 : 8+length]
		} else {
			off := int(order.Uint32(e[8:12]))
			if off < 0 || off+length > len(tiff) {
				return ""
			}
			value = tiff[off : off+length]
		}
		return sanitiseHint(string(bytes.TrimRight(value, "\x00")))
	}
	return ""
}

// pngTextSoftware reads tEXt and iTXt chunks with a Software or parameters key.
//
// The "parameters" key is what several image generators write their whole
// prompt into, which is both the strongest hint of the three and the easiest to
// remove.
func pngTextSoftware(asset []byte) string {
	if !bytes.HasPrefix(asset, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}) {
		return ""
	}
	i := 8
	for i+12 <= len(asset) {
		length := int(binary.BigEndian.Uint32(asset[i : i+4]))
		if length < 0 || i+12+length > len(asset) {
			return ""
		}
		chunkType := string(asset[i+4 : i+8])
		if chunkType == "IEND" {
			return ""
		}
		if chunkType == "tEXt" || chunkType == "iTXt" {
			data := asset[i+8 : i+8+length]
			if sep := bytes.IndexByte(data, 0); sep > 0 {
				key := string(data[:sep])
				value := data[sep+1:]
				if chunkType == "iTXt" && len(value) > 4 {
					// iTXt: compression flag, method, language, translated key,
					// then the text. Only uncompressed entries are read.
					if value[0] != 0 {
						i += 12 + length
						continue
					}
					if idx := bytes.LastIndexByte(value, 0); idx >= 0 && idx+1 < len(value) {
						value = value[idx+1:]
					}
				}
				switch strings.ToLower(key) {
				case "software", "parameters", "creator", "comment", "description":
					if v := sanitiseHint(string(value)); v != "" {
						return v
					}
				}
			}
		}
		i += 12 + length
	}
	return ""
}

const maxHintLen = 512

// sanitiseHint bounds the value and strips control characters.
//
// This string reaches a moderator's screen and a database column, and it came
// out of a file a stranger uploaded. Control characters, bidirectional
// overrides and unbounded length are all the sort of thing that turns a
// metadata field into a display exploit.
func sanitiseHint(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxHintLen {
		s = s[:maxHintLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x20 && r != '\t', r == 0x7f:
			b.WriteByte(' ')
		case r == '\ufeff', r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069':
			// Byte-order marks and bidirectional overrides: dropped, because
			// their only use in a tool name is to make it render as something
			// other than what it is.
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// sourceProjectExtensions are editable project formats. Shipping one alongside
// a deliverable is the hardest provenance signal to fabricate: it takes the
// actual work to produce a layered file whose layers are coherent.
var sourceProjectExtensions = map[string]string{
	"psd": "Photoshop document", "psb": "Photoshop large document",
	"ai": "Illustrator document", "indd": "InDesign document",
	"xd": "Adobe XD document", "fig": "Figma document",
	"sketch": "Sketch document", "afdesign": "Affinity Designer document",
	"afphoto": "Affinity Photo document", "afpub": "Affinity Publisher document",
	"blend": "Blender scene", "c4d": "Cinema 4D scene", "ma": "Maya scene",
	"mb": "Maya binary scene", "max": "3ds Max scene", "spp": "Substance Painter project",
	"aep": "After Effects project", "prproj": "Premiere Pro project",
	"drp": "DaVinci Resolve project", "veg": "Vegas project",
	"logicx": "Logic Pro project", "als": "Ableton Live set",
	"flp": "FL Studio project", "ptx": "Pro Tools session",
	"rpp": "Reaper project", "cpr": "Cubase project",
	"svg": "editable vector source", "xcf": "GIMP document",
	"kra": "Krita document", "procreate": "Procreate document",
	"sla": "Scribus document", "graffle": "OmniGraffle document",
}

// DetectSourceProjects reports which editable project files are present among a
// set of uploaded filenames.
func DetectSourceProjects(filenames []string) (present bool, kinds []string) {
	seen := map[string]bool{}
	for _, f := range filenames {
		ext := strings.ToLower(strings.TrimPrefix(path.Ext(f), "."))
		if kind, ok := sourceProjectExtensions[ext]; ok && !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
	}
	return len(kinds) > 0, kinds
}
