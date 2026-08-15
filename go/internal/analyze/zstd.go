package analyze

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// zstdMagic is the Zstandard frame magic number, little-endian.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// isZstd reports whether the bytes begin with a Zstandard frame. Extension
// alone is not enough: dsh writes session.jsonl.zstd by default but plain
// session.jsonl when compression is disabled, and an operator may rename either.
func isZstd(data []byte) bool {
	return len(data) >= 4 && bytes.Equal(data[:4], zstdMagic)
}

// hasCompressedExt reports whether a path carries a Zstandard extension.
func hasCompressedExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zstd", ".zst":
		return true
	}
	return false
}

// maxDecompressed caps the output of a single decode. A compressed transcript
// can expand enormously, and TRACE must not let one artifact exhaust memory on
// an examiner's machine.
const maxDecompressed = 256 << 20 // 256 MiB

// readMaybeCompressed reads a file, transparently decoding Zstandard frames.
// It returns "" when the file is unreadable, oversized, or not decodable —
// callers treat that the same as an empty artifact.
func readMaybeCompressed(path string) string {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return ""
	}
	// A compressed transcript is small on disk relative to its content, so the
	// plain-file cap is applied to the decompressed side instead.
	if !hasCompressedExt(path) && st.Size() > maxScanBytes {
		return ""
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if !isZstd(data) {
		if len(data) > maxScanBytes {
			return ""
		}
		return string(data)
	}

	out, err := decodeZstd(data)
	if err != nil {
		return ""
	}
	return out
}

// decodeZstd decompresses a Zstandard stream, bounded by maxDecompressed.
//
// dsh appends one frame per write batch, so a session log is a concatenation of
// frames rather than a single one; the streaming decoder handles that, where a
// one-shot DecodeAll would stop after the first frame.
func decodeZstd(data []byte) (string, error) {
	reader, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer reader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(reader, maxDecompressed)); err != nil {
		// Return whatever decoded cleanly: a truncated or partially corrupt
		// transcript is still evidence, and refusing it loses the whole session.
		if buf.Len() == 0 {
			return "", err
		}
	}
	return buf.String(), nil
}
