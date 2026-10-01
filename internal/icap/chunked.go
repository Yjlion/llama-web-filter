package icap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxChunkLineBytes bounds a chunk-size line ("1f4; ext\r\n"). Anything
// longer is a malformed or hostile peer, not a real chunked body.
const maxChunkLineBytes = 1024

// errChunkTooLong is returned when a chunk-size line exceeds maxChunkLineBytes.
var errChunkTooLong = errors.New("icap: chunk-size line too long")

// readChunkedBody decodes an RFC 7230 chunked body from br, stopping after
// the terminating zero-sized chunk and its (ignored) trailer.
//
// It reports two things the stdlib's chunked reader cannot. The first is
// whether the zero chunk carried the "ieof" extension, which is how an ICAP
// preview says "that was the entire body, do not ask me for more" (RFC 3507
// §4.5) - without it there is no way to tell a complete short body from the
// first 4 KiB of a long one. The second is whether the body ran past limit:
// the remaining bytes are still drained off the wire, because the ICAP
// connection carries the next transaction and must stay in sync, but they are
// discarded rather than buffered so a multi-gigabyte download cannot become
// multiple gigabytes of proxy heap.
func readChunkedBody(br *bufio.Reader, limit int) (body []byte, ieof, truncated bool, err error) {
	var buf []byte
	for {
		size, ext, err := readChunkHeader(br)
		if err != nil {
			return buf, false, truncated, err
		}
		if size == 0 {
			// The zero chunk ends the body; a trailer (header lines followed
			// by a blank one) may follow and is not meaningful to ICAP.
			if err := discardTrailer(br); err != nil {
				return buf, false, truncated, err
			}
			return buf, hasIEOF(ext), truncated, nil
		}
		room := limit - len(buf)
		if room < 0 {
			room = 0
		}
		if size <= room {
			chunk := make([]byte, size)
			if _, err := io.ReadFull(br, chunk); err != nil {
				return buf, false, truncated, err
			}
			buf = append(buf, chunk...)
		} else {
			truncated = true
			if room > 0 {
				chunk := make([]byte, room)
				if _, err := io.ReadFull(br, chunk); err != nil {
					return buf, false, truncated, err
				}
				buf = append(buf, chunk...)
			}
			if _, err := io.CopyN(io.Discard, br, int64(size-room)); err != nil {
				return buf, false, truncated, err
			}
		}
		if err := expectCRLF(br); err != nil {
			return buf, false, truncated, err
		}
	}
}

// readChunkHeader reads one "size[; extension]" line and returns the decoded
// size along with the raw extension text.
func readChunkHeader(br *bufio.Reader) (size int, ext string, err error) {
	line, err := readLine(br, maxChunkLineBytes)
	if err != nil {
		return 0, "", err
	}
	sizePart := line
	if i := strings.IndexByte(line, ';'); i >= 0 {
		sizePart, ext = line[:i], line[i+1:]
	}
	sizePart = strings.TrimSpace(sizePart)
	if sizePart == "" {
		return 0, "", fmt.Errorf("icap: empty chunk size")
	}
	n, err := strconv.ParseUint(sizePart, 16, 31)
	if err != nil {
		return 0, "", fmt.Errorf("icap: bad chunk size %q", sizePart)
	}
	return int(n), ext, nil
}

// hasIEOF reports whether a chunk extension list contains the ICAP "ieof"
// token. Matching is case-insensitive and tolerates surrounding whitespace
// and additional extensions.
func hasIEOF(ext string) bool {
	for _, part := range strings.Split(ext, ";") {
		if strings.EqualFold(strings.TrimSpace(part), "ieof") {
			return true
		}
	}
	return false
}

// discardTrailer consumes the optional trailer section after the zero chunk,
// up to and including the blank line that terminates it.
func discardTrailer(br *bufio.Reader) error {
	for {
		line, err := readLine(br, maxChunkLineBytes)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

// expectCRLF consumes the CRLF that follows every chunk's data.
func expectCRLF(br *bufio.Reader) error {
	line, err := readLine(br, 2)
	if err != nil {
		return err
	}
	if line != "" {
		return fmt.Errorf("icap: expected CRLF after chunk, got %q", line)
	}
	return nil
}

// readLine reads a single CRLF- (or LF-) terminated line, returning it
// without the terminator. Lines longer than limit are an error rather than an
// unbounded allocation.
func readLine(br *bufio.Reader, limit int) (string, error) {
	var sb strings.Builder
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			s := sb.String()
			return strings.TrimSuffix(s, "\r"), nil
		}
		if sb.Len() >= limit {
			return "", errChunkTooLong
		}
		sb.WriteByte(b)
	}
}

// writeChunkedBody writes body as a single chunk followed by the terminating
// zero chunk. ICAP bodies are always fully buffered by the time they are
// written back (every addon needs the whole thing anyway), so there is no
// reason to fragment them.
func writeChunkedBody(w io.Writer, body []byte) error {
	if len(body) > 0 {
		if _, err := fmt.Fprintf(w, "%x\r\n", len(body)); err != nil {
			return err
		}
		if _, err := w.Write(body); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\r\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "0\r\n\r\n")
	return err
}
