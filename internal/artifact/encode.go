package artifact

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"
)

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// sanitizeText renders a bounded text preview, replacing invalid UTF-8 and
// control characters so untrusted emulator data stays structurally safe.
func sanitizeText(data []byte) string {
	var builder strings.Builder
	for index := 0; index < len(data); {
		character, width := utf8.DecodeRune(data[index:])
		if character == utf8.RuneError && width <= 1 {
			builder.WriteRune('\uFFFD')
			index++
			continue
		}
		if character < 0x20 && character != '\n' && character != '\t' && character != '\r' {
			builder.WriteRune('.')
			index += width
			continue
		}
		builder.WriteRune(character)
		index += width
	}
	return builder.String()
}

// HexDump renders classic offset rows, mirroring the requested start address.
func HexDump(data []byte, offset int64) string {
	if len(data) == 0 {
		return ""
	}
	var rows []string
	for index := 0; index < len(data); index += 16 {
		end := index + 16
		if end > len(data) {
			end = len(data)
		}
		var hexBytes strings.Builder
		var ascii strings.Builder
		for position := index; position < end; position++ {
			if position > index {
				hexBytes.WriteByte(' ')
			}
			fmt.Fprintf(&hexBytes, "%02x", data[position])
			if data[position] >= 0x20 && data[position] < 0x7f {
				ascii.WriteByte(data[position])
			} else {
				ascii.WriteByte('.')
			}
		}
		rows = append(rows, fmt.Sprintf("%08x  %-47s  |%s|", uint64(offset)+uint64(index), hexBytes.String(), ascii.String()))
	}
	return strings.Join(rows, "\n")
}
