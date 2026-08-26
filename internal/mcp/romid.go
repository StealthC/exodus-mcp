package mcp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"time"
)

// ROM identity (roadmap P2): one shared object identifying the loaded
// cartridge by file SHA-256, file and padded mapping sizes, header serial and
// title, Sega checksum status, mapped image base, and target generation. It is
// computed from the ROM file on the server host (the server runs on Windows
// next to Exodus, so the cartridge path from emulator_status is readable) and
// cached per file version. Every ROM-derived artifact, state, symbol, and
// export records the identity's essential fields in its provenance.
//
// The checksum status is computed over the file bytes, never over a partial
// bus read: a comparison is only reported complete when the covered byte
// range equals the header-declared ROM body.

const mappedImageBase = "0x000000"

// romChecksumStatus reports the Sega header checksum over the ROM file body
// with explicit completeness facts, so a partial comparison is never mistaken
// for full validation.
type romChecksumStatus struct {
	Stored         uint16 `json:"stored"`
	Computed       uint16 `json:"computed"`
	Matches        bool   `json:"matches"`
	Complete       bool   `json:"complete"`
	BytesCovered   uint64 `json:"bytes_covered"`
	ExpectedEnd    uint64 `json:"expected_end_address"`
	ExpectedLength uint64 `json:"expected_byte_length"`
	CapReason      string `json:"cap_reason"` // "none" when complete
}

// romFileFacts are the immutable file-derived identity facts, cached per file
// version (path + size + mtime).
type romFileFacts struct {
	SHA256           string             `json:"rom_sha256"`
	SHA256Available  bool               `json:"rom_sha256_available"`
	SizeBytes        uint64             `json:"size_bytes"`
	Title            string             `json:"title,omitempty"`
	Serial           string             `json:"serial,omitempty"`
	HeaderIdentified bool               `json:"header_identified"`
	Checksum         *romChecksumStatus `json:"checksum,omitempty"`
	FileUnreadable   bool               `json:"-"`
}

type romIdentityKey struct {
	path  string
	size  int64
	mtime time.Time
}

// romIdentityProvider caches the file-derived identity per file version so
// hashing a multi-megabyte cartridge does not repeat on every artifact.
type romIdentityProvider struct {
	mu    sync.Mutex
	key   romIdentityKey
	facts romFileFacts
}

func newROMIdentityProvider() *romIdentityProvider {
	return &romIdentityProvider{}
}

// romFileFacts returns the cached file-derived identity for path, recomputing
// only when the path, file size, or modification time changes. An unreadable
// file is reported honestly (no SHA-256, no header, no checksum) and is not
// cached, so a later readable file replaces it.
func (provider *romIdentityProvider) romFileFacts(path string) romFileFacts {
	if path == "" {
		return romFileFacts{}
	}
	info, err := os.Stat(path)
	if err != nil {
		return romFileFacts{FileUnreadable: true}
	}
	key := romIdentityKey{path: path, size: info.Size(), mtime: info.ModTime()}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.key == key {
		return provider.facts
	}
	provider.key = key
	provider.facts = computeROMFileFacts(path, uint64(info.Size()))
	return provider.facts
}

// computeROMFileFacts hashes the file, parses the Sega header from its first
// 0x200 bytes, and computes the Sega checksum over the header-declared body.
func computeROMFileFacts(path string, sizeBytes uint64) romFileFacts {
	facts := romFileFacts{SizeBytes: sizeBytes}
	file, err := os.Open(path)
	if err != nil {
		facts.FileUnreadable = true
		return facts
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		facts.FileUnreadable = true
		return facts
	}
	facts.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	facts.SHA256Available = true

	header := make([]byte, 0x200)
	count, err := file.ReadAt(header, 0x100)
	if err != nil && count < 0x100 {
		// The file is shorter than the header; identity stays file-only.
		facts.HeaderIdentified = false
		return facts
	}
	header = header[:count]
	parsed, failure := decodeMDHeader(header)
	if failure != nil {
		facts.HeaderIdentified = false
		return facts
	}
	facts.HeaderIdentified = true
	facts.Title = parsed.Overseas
	if facts.Title == "" {
		facts.Title = parsed.Domestic
	}
	facts.Serial = parsed.Serial

	// Checksum over the declared ROM body: [0x200, declared end + 1), clamped
	// to the file size. A declared end beyond the file means the comparison
	// cannot cover the full declared range and is reported incomplete.
	expectedEnd := uint64(parsed.ROMEnd) + 1
	if expectedEnd < 0x200 || uint64(parsed.ROMEnd) < uint64(parsed.ROMStart) {
		// Degenerate or unset declared end: the expected body is the file.
		expectedEnd = sizeBytes
	}
	if expectedEnd < 0x200 {
		expectedEnd = 0x200
	}
	status := &romChecksumStatus{
		Stored:         parsed.Checksum,
		ExpectedEnd:    expectedEnd,
		ExpectedLength: expectedEnd - 0x200,
		CapReason:      "none",
	}
	if expectedEnd <= 0x200 {
		status.BytesCovered = 0
		status.Complete = false
		status.CapReason = "declared_end_beyond_file"
		status.Matches = false
		facts.Checksum = status
		return facts
	}
	covered := expectedEnd
	if covered > sizeBytes {
		covered = sizeBytes
		status.CapReason = "declared_end_beyond_file"
	}
	if covered <= 0x200 {
		status.BytesCovered = 0
		status.Complete = false
		status.Matches = false
		facts.Checksum = status
		return facts
	}
	computed, err := computeFileChecksum(file, 0x200, covered)
	if err != nil {
		facts.Checksum = status
		return facts
	}
	status.Computed = computed
	status.BytesCovered = covered - 0x200
	status.Complete = status.BytesCovered == status.ExpectedLength && covered == expectedEnd
	if !status.Complete {
		// The header declares a body the file does not contain.
		status.CapReason = "declared_end_beyond_file"
	}
	status.Matches = status.Computed == status.Stored
	facts.Checksum = status
	return facts
}

// computeFileChecksum sums big-endian words over [start, end) of file using
// the same Sega algorithm as computeSegaChecksum, streaming to keep memory
// bounded. A trailing odd byte is treated as the high byte of the final word.
func computeFileChecksum(file *os.File, start, end uint64) (uint16, error) {
	if _, err := file.Seek(int64(start), io.SeekStart); err != nil {
		return 0, err
	}
	reader := io.LimitReader(file, int64(end-start))
	var sum uint16
	var pending byte
	havePending := false
	buffer := make([]byte, 64*1024)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			data := buffer[:count]
			if havePending {
				sum += uint16(pending)<<8 | uint16(data[0])
				data = data[1:]
				havePending = false
			}
			for index := 0; index+1 < len(data); index += 2 {
				sum += binary.BigEndian.Uint16(data[index:])
			}
			if len(data)%2 == 1 {
				pending = data[len(data)-1]
				havePending = true
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if havePending {
		sum += uint16(pending) << 8
	}
	return sum, nil
}

// romIdentityView stamps the target generation onto the file facts and renders
// the shared rom_identity object attached to rom_info, target_info, and
// artifact provenance.
func (server *Server) romIdentityView(paddedSizeBytes uint64) map[string]any {
	facts := server.romIdentity.romFileFacts(server.currentROMPath())
	view := map[string]any{
		"mapped_image_base":    mappedImageBase,
		"target_generation":    server.target.Generation(),
		"rom_sha256":           facts.SHA256,
		"rom_sha256_available": facts.SHA256Available,
		"size_bytes":           facts.SizeBytes,
		"header_identified":    facts.HeaderIdentified,
	}
	if paddedSizeBytes > 0 {
		view["padded_size_bytes"] = paddedSizeBytes
	}
	if facts.Title != "" {
		view["title"] = facts.Title
	}
	if facts.Serial != "" {
		view["serial"] = facts.Serial
	}
	if facts.Checksum != nil {
		view["checksum"] = facts.Checksum
	}
	if facts.FileUnreadable {
		view["note"] = "The ROM file is not readable from the server host; file-derived identity (SHA-256, header, checksum) is unavailable. Header and checksum facts that need the bus remain available through rom_info."
	}
	return view
}
