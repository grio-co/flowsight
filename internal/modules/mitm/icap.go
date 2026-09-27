package mitm

// The transport: ICAP, the protocol squid speaks to a content adaptation
// service (RFC 3507).
//
// Two other routes were tried and rejected. A parent proxy cannot take a
// decrypted https:// request from squid without tunnelling it back through
// CONNECT, which puts the payload out of reach again. Taking the packets
// directly, as mitmproxy's transparent mode does, means a second interception
// path beside the one that already works, with its own certificate minting
// and its own failure modes in front of the whole network.
//
// ICAP is the supported path: squid hands over each request and response as
// it passes, FlowSight reads it and answers "no modification". With a
// preview the exchange costs almost nothing: squid sends the headers and the
// first few kilobytes, which is everything an inspector needs (a
// DNS-over-HTTPS question is a few hundred bytes), FlowSight answers 204,
// and the body streams on untouched. Nothing is modified, nothing is stored.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// icapServe handles one connection for as long as squid keeps it open.
func (m *Module) icapServe(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 64<<10)
	bw := bufio.NewWriter(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := readICAP(br)
		if err != nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		switch req.Method {
		case "OPTIONS":
			m.icapOptions(bw, req)
		case "REQMOD", "RESPMOD":
			m.icapMod(bw, req)
		default:
			fmt.Fprintf(bw, "ICAP/1.0 405 Method Not Allowed\r\nISTag: \"%s\"\r\nEncapsulated: null-body=0\r\n\r\n", istag)
		}
		if bw.Flush() != nil {
			return
		}
	}
}

const istag = "flowsight-1"

func (m *Module) icapOptions(w io.Writer, req *icapRequest) {
	service := "reqmod respmod"
	preview := core.Int(m.ctx.Settings(), "preview_bytes", 4096)
	if preview < 0 {
		preview = 0
	}
	fmt.Fprintf(w, "ICAP/1.0 200 OK\r\n"+
		"Methods: %s\r\n"+
		"Service: FlowSight stateful packet inspection\r\n"+
		"ISTag: \"%s\"\r\n"+
		"Allow: 204\r\n"+
		"Preview: %d\r\n"+
		"Transfer-Preview: *\r\n"+
		"Max-Connections: 64\r\n"+
		"Options-TTL: 3600\r\n"+
		"Encapsulated: null-body=0\r\n\r\n",
		strings.ToUpper(strings.ReplaceAll(service, " ", ", ")), istag, preview)
}

// icapMod reads one encapsulated exchange, records it, and tells squid to
// carry on unchanged.
func (m *Module) icapMod(w io.Writer, req *icapRequest) {
	rec := Request{TS: time.Now().Unix(), Client: req.ClientIP()}
	if req.HTTPRequest != nil {
		rec.Method = req.HTTPRequest.Method
		rec.URL = redactURL(req.HTTPRequest.URL)
		rec.Host = req.HTTPRequest.Host
		if rec.Host == "" {
			rec.Host = req.HTTPRequest.URL.Host
		}
		if core.Bool(m.ctx.Settings(), "record_headers", true) {
			rec.Headers = safeHeaders(req.HTTPRequest.Header)
		}
	}
	if req.HTTPResponse != nil {
		rec.Status = req.HTTPResponse.StatusCode
		rec.Type = req.HTTPResponse.Header.Get("Content-Type")
		if n, err := strconv.ParseInt(req.HTTPResponse.Header.Get("Content-Length"), 10, 64); err == nil {
			rec.BytesIn = n
		}
	}
	// A CONNECT is the tunnel being opened, not something inside it: the
	// proxy log already has it, and recording it here would list every
	// inspected session twice and say nothing about its contents.
	if rec.Method != "CONNECT" && (rec.URL != "" || rec.Host != "") {
		m.record(rec, req.Body, req.Method == "RESPMOD")
	}
	// 204 is "I have nothing to change": squid keeps the original message and
	// streams it on. This is the whole point of a preview.
	fmt.Fprintf(w, "ICAP/1.0 204 No Content\r\nISTag: \"%s\"\r\nEncapsulated: null-body=0\r\n\r\n", istag)
}

// ---------------------------------------------------------------- parsing

type icapRequest struct {
	Method       string
	URI          string
	Header       http.Header
	HTTPRequest  *http.Request
	HTTPResponse *http.Response
	Body         []byte // the preview, at most preview_bytes
}

// ClientIP is the address squid says the request came from.
func (r *icapRequest) ClientIP() string {
	for _, h := range []string{"X-Client-IP", "X-Client-Ip", "X-Forwarded-For"} {
		if v := r.Header.Get(h); v != "" {
			if i := strings.IndexByte(v, ','); i > 0 {
				v = v[:i]
			}
			return strings.TrimSpace(v)
		}
	}
	if r.HTTPRequest != nil {
		if v := r.HTTPRequest.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	return ""
}

func readICAP(br *bufio.Reader) (*icapRequest, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return nil, fmt.Errorf("bad ICAP request line %q", line)
	}
	req := &icapRequest{Method: strings.ToUpper(parts[0]), URI: parts[1], Header: http.Header{}}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	if req.Method == "OPTIONS" {
		return req, nil
	}
	// Encapsulated: req-hdr=0, req-body=412   (offsets into what follows)
	sections := parseEncapsulated(req.Header.Get("Encapsulated"))
	var reqHdr, respHdr []byte
	for i, sec := range sections {
		size := 0
		if i+1 < len(sections) {
			size = sections[i+1].off - sec.off
		}
		switch sec.name {
		case "req-hdr", "res-hdr":
			buf := make([]byte, size)
			if _, err := io.ReadFull(br, buf); err != nil {
				return nil, err
			}
			if sec.name == "req-hdr" {
				reqHdr = buf
			} else {
				respHdr = buf
			}
		case "req-body", "res-body", "opt-body":
			body, err := readChunkedPreview(br)
			if err != nil {
				return nil, err
			}
			req.Body = body
		case "null-body":
			// nothing follows
		}
	}
	if len(reqHdr) > 0 {
		if r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqHdr))); err == nil {
			// An adapted request carries an absolute URI; make Host usable.
			if r.URL != nil && r.URL.Host == "" {
				r.URL.Host = r.Host
			}
			req.HTTPRequest = r
		}
	}
	if len(respHdr) > 0 {
		if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respHdr)), req.HTTPRequest); err == nil {
			req.HTTPResponse = resp
		}
	}
	return req, nil
}

type encSection struct {
	name string
	off  int
}

func parseEncapsulated(v string) []encSection {
	var out []encSection
	for _, part := range strings.Split(v, ",") {
		k, n, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		off, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			continue
		}
		out = append(out, encSection{name: strings.TrimSpace(k), off: off})
	}
	return out
}

// readChunkedPreview reads the preview body: chunked, ended either by a zero
// chunk or by the "0; ieof" marker that says this was the whole message.
func readChunkedPreview(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return out, err
		}
		line = strings.TrimRight(line, "\r\n")
		sizeStr := line
		if i := strings.IndexByte(line, ';'); i >= 0 {
			sizeStr = line[:i]
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil {
			return out, fmt.Errorf("bad chunk size %q", line)
		}
		if n == 0 {
			// Trailing CRLF after the last chunk.
			_, _ = br.ReadString('\n')
			return out, nil
		}
		if n > 1<<20 {
			n = 1 << 20
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return out, err
		}
		out = append(out, buf...)
		_, _ = br.ReadString('\n') // CRLF after the chunk
	}
}

// safeHeaders records what a header was without recording a secret: a cookie
// or an authorization header becomes its length.
func safeHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, vs := range h {
		v := strings.Join(vs, ", ")
		switch strings.ToLower(k) {
		case "cookie", "authorization", "proxy-authorization", "x-api-key", "set-cookie":
			out[k] = fmt.Sprintf("(%d bytes, not recorded)", len(v))
		default:
			if len(v) > 300 {
				v = v[:300] + "…"
			}
			out[k] = v
		}
	}
	return out
}

// redactURL keeps what a request was for and drops what it carried: the
// scheme, host and path stay, the names of query parameters stay (so
// "?token=…&page=…" still says which endpoint was called), and every value,
// any user:password and the fragment go. Query strings routinely carry API
// keys, session ids and one-time codes, and inspection must not become a
// store of them.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	c.Fragment, c.RawFragment = "", ""
	if c.RawQuery != "" {
		q, err := url.ParseQuery(c.RawQuery)
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"=…")
		}
		if err != nil || len(parts) == 0 {
			parts = []string{"…"}
		}
		c.RawQuery = strings.Join(parts, "&")
	}
	return c.String()
}
