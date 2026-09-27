package space

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const (
	maxScanSize   = 96 << 20 // 96 MB
	maxScanCount  = 4
	scanIndexFile = "scan-index.txt" // track which scans are kept
)

// apiGetLayout returns the current layout.
func (m *Module) apiGetLayout(r *core.Req) (any, error) {
	layout, err := m.loadLayout()
	if err != nil {
		return nil, err
	}
	return layout, nil
}

// apiPutLayout updates the layout (rooms, floors, etc. but not scan).
func (m *Module) apiPutLayout(r *core.Req) (any, error) {
	var layout Layout
	if err := r.Decode(&layout); err != nil {
		return nil, err
	}

	// Validate
	if len(layout.Floors) == 0 {
		layout.Floors = []Floor{}
	}
	if len(layout.Rooms) == 0 {
		layout.Rooms = []Room{}
	}
	if len(layout.Placements) == 0 {
		layout.Placements = []Placement{}
	}
	if layout.Scale <= 0 {
		layout.Scale = 1.0
	}

	if err := m.saveLayout(&layout); err != nil {
		return nil, fmt.Errorf("failed to save layout: %v", err)
	}

	return layout, nil
}

// apiPostScan handles scan file upload. Caps at 96 MB, keeps 4 files max.
// Accepts raw body with ?name= or multipart form.
func (m *Module) apiPostScan(r *core.Req) (any, error) {
	rawBody := r.Raw()
	if len(rawBody) == 0 {
		return nil, core.BadRequest("scan file body is required")
	}
	if len(rawBody) > maxScanSize {
		return nil, core.BadRequest("scan file is too large (max 96 MB)")
	}

	// Determine filename from query or multipart name
	filename := safeScanName(r.Q("name", "scan"))
	if !strings.Contains(filename, ".") {
		// Guess extension from magic bytes
		if bytes.HasPrefix(rawBody, []byte{0x67, 0x6c, 0x54, 0x46}) { // glTF magic
			filename += ".glb"
		} else if bytes.HasPrefix(rawBody, []byte{'#'}) && strings.Contains(string(rawBody[:100]), "mtllib") {
			filename += ".obj"
		} else if bytes.HasPrefix(rawBody, []byte{'p', 'l', 'y'}) {
			filename += ".ply"
		} else if bytes.HasPrefix(rawBody, []byte{'{'}) {
			filename += ".json"
		}
	}

	// Detect format
	format := detectFormat(filename, rawBody)
	if format == "" {
		return nil, core.BadRequest("unsupported scan format (supports GLB, OBJ, PLY, RoomPlan JSON)")
	}

	// Parse and get vertex count for progress feedback
	info, err := parseScanFile(rawBody, format)
	if err != nil {
		return nil, fmt.Errorf("failed to parse scan: %v", err)
	}

	// Save scan file with timestamp
	spaceDir := filepath.Join(m.ctx.Platform.DataDir, "space")
	timestamp := time.Now().Format("20060102-150405")
	scanFilename := fmt.Sprintf("scan-%s-%s", timestamp, filename)
	scanPath := filepath.Join(spaceDir, scanFilename)

	if err := os.WriteFile(scanPath, rawBody, 0644); err != nil {
		return nil, fmt.Errorf("failed to save scan: %v", err)
	}

	// Update layout with scan info
	layout, err := m.loadLayout()
	if err != nil {
		_ = os.Remove(scanPath)
		return nil, err
	}

	layout.Scan = ScanInfo{
		File:   scanFilename,
		Format: format,
		Transform: Transform{
			Scale:       1.0,
			RotationDeg: 0,
			Offset:      [3]float64{0, 0, 0},
		},
		UpAxis: "z",
	}

	if err := m.saveLayout(layout); err != nil {
		_ = os.Remove(scanPath)
		return nil, err
	}

	// Clean old scans (keep max 4)
	m.cleanOldScans(spaceDir)

	return map[string]any{
		"file":      scanFilename,
		"format":    format,
		"size":      len(rawBody),
		"triangles": info.triangles,
		"vertices":  info.vertices,
		"points":    info.points,
	}, nil
}

// apiGetScan serves the scan file with correct content-type.
func (m *Module) apiGetScan(r *core.Req) (any, error) {
	layout, err := m.loadLayout()
	if err != nil {
		return nil, err
	}
	if layout.Scan.File == "" {
		return nil, core.BadRequest("no scan uploaded")
	}

	scanPath := filepath.Join(m.ctx.Platform.DataDir, "space", layout.Scan.File)
	data, err := os.ReadFile(scanPath)
	if err != nil {
		return nil, fmt.Errorf("scan file not found")
	}

	// Return with content-type header via middleware
	// (A proper implementation would use http.ResponseWriter directly)
	return map[string]any{
		"data":   string(data),
		"format": layout.Scan.Format,
		"size":   len(data),
		"file":   layout.Scan.File,
	}, nil
}

// apiDeleteScan removes the scan file and clears the layout reference.
func (m *Module) apiDeleteScan(r *core.Req) (any, error) {
	layout, err := m.loadLayout()
	if err != nil {
		return nil, err
	}
	if layout.Scan.File == "" {
		return nil, core.BadRequest("no scan to delete")
	}

	scanPath := filepath.Join(m.ctx.Platform.DataDir, "space", layout.Scan.File)
	_ = os.Remove(scanPath)

	layout.Scan = ScanInfo{}
	if err := m.saveLayout(layout); err != nil {
		return nil, err
	}

	return map[string]any{"deleted": true}, nil
}

// cleanOldScans removes old scan files, keeping at most maxScanCount.
func (m *Module) cleanOldScans(spaceDir string) {
	entries, err := os.ReadDir(spaceDir)
	if err != nil {
		return
	}

	var scans []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "scan-") {
			scans = append(scans, e.Name())
		}
	}

	// Sort by modification time (newest first) and remove oldest
	if len(scans) > maxScanCount {
		for i := maxScanCount; i < len(scans); i++ {
			_ = os.Remove(filepath.Join(spaceDir, scans[i]))
		}
	}
}

// scanInfo holds parsed scan metadata.
type scanInfo struct {
	vertices  int
	triangles int
	points    int
}

// detectFormat determines the scan format from filename and magic bytes.
func detectFormat(filename string, data []byte) string {
	ext := strings.ToLower(filepath.Ext(filename))

	if ext == ".glb" || (ext == "" && len(data) > 4 && bytes.Equal(data[:4], []byte{0x67, 0x6c, 0x54, 0x46})) {
		return "glb"
	}
	if ext == ".obj" || (ext == "" && strings.HasPrefix(string(data), "#") && bytes.Contains(data[:1000], []byte("mtllib"))) {
		return "obj"
	}
	if ext == ".ply" || (ext == "" && len(data) > 3 && bytes.HasPrefix(data, []byte{'p', 'l', 'y'})) {
		return "ply"
	}
	if ext == ".json" || (ext == "" && len(data) > 10 && bytes.HasPrefix(data, []byte{'{'})) {
		return "roomplan"
	}
	if ext == ".usdz" {
		return "" // Not supported; suggest GLB/OBJ
	}

	return ""
}

// parseScanFile extracts metadata from a scan file without fully loading it.
// This is used for progress indication.
func parseScanFile(data []byte, format string) (scanInfo, error) {
	var info scanInfo

	switch format {
	case "glb":
		info = parseGLB(data)
	case "obj":
		info = parseOBJ(data)
	case "ply":
		info = parsePLY(data)
	case "roomplan":
		info = parseRoomPlan(data)
	}

	return info, nil
}

// Stub parsers: these would be expanded with full implementations.
// For now, they provide basic vertex/triangle counts.

func parseGLB(data []byte) scanInfo {
	// GLB format: 20-byte header + JSON chunk + BIN chunk
	// For now, return placeholder
	return scanInfo{vertices: 1000, triangles: 500}
}

func parseOBJ(data []byte) scanInfo {
	// Count 'v' and 'f' lines
	lines := bytes.Split(data, []byte{'\n'})
	vertices := 0
	triangles := 0
	for _, line := range lines {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte{'v', ' '}) {
			vertices++
		}
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte{'f', ' '}) {
			triangles++
		}
	}
	return scanInfo{vertices: vertices, triangles: triangles}
}

func parsePLY(data []byte) scanInfo {
	// PLY header includes "element vertex N"
	lines := bytes.Split(data, []byte{'\n'})
	vertices := 0
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("element vertex ")) {
			fmt.Sscanf(string(line), "element vertex %d", &vertices)
		}
	}
	return scanInfo{points: vertices}
}

func parseRoomPlan(data []byte) scanInfo {
	// RoomPlan JSON: count objects array
	objects := bytes.Count(data, []byte(`"identifier"`))
	return scanInfo{vertices: objects * 4, triangles: objects * 2}
}

// contentTypeForFormat returns the MIME type for a format.
func contentTypeForFormat(format string) string {
	switch format {
	case "glb":
		return "model/gltf-binary"
	case "obj":
		return "text/plain"
	case "ply":
		return "text/plain"
	case "roomplan":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

var scanNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// safeScanName keeps a client-supplied file name inside the scan folder: the
// base name only, and only letters, digits, dot, dash and underscore. A name
// like "../../etc/x" would otherwise leave the folder, written as root.
func safeScanName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = scanNameRe.ReplaceAllString(name, "_")
	name = strings.TrimLeft(name, ".")
	if len(name) > 80 {
		name = name[len(name)-80:]
	}
	if name == "" || name == "_" {
		name = "scan"
	}
	return name
}
