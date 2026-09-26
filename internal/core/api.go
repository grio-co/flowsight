package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// API is the HTTP layer. Rules, learned the hard way from the previous UI:
//
//   - request state is per request, never global;
//   - every write passes one gate, whatever the verb;
//   - handlers read the store and return; collection happens in jobs;
//   - bodies are bounded, sockets have timeouts, errors are JSON with `error`;
//   - no CDN, no inline script, so the CSP can forbid inline script entirely.
type API struct {
	core   *Core
	mu     sync.RWMutex
	routes map[string]*Route // method + " " + path
	static fs.FS
	log    *slog.Logger

	sessMu   sync.Mutex
	sessions map[string]session
}

type session struct {
	user    string
	expires time.Time
}

// Field describes a single field in a request/response schema.
type Field struct {
	Name        string
	Type        string // "string", "integer", "boolean", "object", "array", "number"
	Required    bool
	Description string
	Example     any
	Items       *Field // for array items
	Properties  map[string]*Field
}

// Fld is a shorthand constructor for Field.
func Fld(name, typ string, required bool, desc string, example any) *Field {
	return &Field{
		Name:        name,
		Type:        typ,
		Required:    required,
		Description: desc,
		Example:     example,
	}
}

// FldObj creates an object Field with the given properties.
func FldObj(name string, required bool, desc string, props ...*Field) *Field {
	f := &Field{
		Name:        name,
		Type:        "object",
		Required:    required,
		Description: desc,
		Properties:  make(map[string]*Field),
	}
	for _, p := range props {
		f.Properties[p.Name] = p
	}
	return f
}

// FldArr creates an array Field with the given item type.
func FldArr(name string, required bool, desc string, items *Field) *Field {
	return &Field{
		Name:        name,
		Type:        "array",
		Required:    required,
		Description: desc,
		Items:       items,
	}
}

// ParameterInfo describes a query or path parameter.
type ParameterInfo struct {
	Name        string
	In          string // "query" or "path"
	Type        string // OpenAPI type: string, integer, boolean, etc.
	Required    bool
	Description string
	Example     any
}

// ResponseInfo describes the response body.
type ResponseInfo struct {
	Description string
	Schema      any // Can be Field, or a struct value for auto-generation
	Example     any
}

type Route struct {
	Method, Path, Module string
	Handler              Handler
	Description          string
	Write                bool
	Feature              string            // tier feature this route belongs to ("" = free)
	Params               map[string]string // Legacy: query param descriptions
	Tags                 []string          // OpenAPI tags for grouping
	OperationId          string            // unique operation identifier
	RequestBodyType      string            // describes the request body for docs

	// New rich documentation fields
	Parameters     []*ParameterInfo
	RequestBody    *Field            // Request body schema
	RequestExample any               // Request body example
	Response       *ResponseInfo     // Response documentation
	Examples       map[string]string // Named curl examples
}

type RouteOption func(*Route)

func Doc(desc string) RouteOption { return func(r *Route) { r.Description = desc } }
func Write() RouteOption          { return func(r *Route) { r.Write = true } }
func Params(kv ...string) RouteOption {
	return func(r *Route) {
		for i := 0; i+1 < len(kv); i += 2 {
			r.Params[kv[i]] = kv[i+1]
		}
	}
}
func Tags(tags ...string) RouteOption {
	return func(r *Route) {
		r.Tags = append(r.Tags, tags...)
	}
}
func OperationId(id string) RouteOption {
	return func(r *Route) {
		r.OperationId = id
	}
}

// PathParam documents a {path} parameter.
func PathParam(name, typ, desc string, example any) RouteOption {
	return func(r *Route) {
		if r.Parameters == nil {
			r.Parameters = []*ParameterInfo{}
		}
		r.Parameters = append(r.Parameters, &ParameterInfo{
			Name: name, In: "path", Type: typ, Required: true,
			Description: desc, Example: example,
		})
	}
}

// Query documents a query parameter.
func Query(name, typ, desc string, required bool, example any) RouteOption {
	return func(r *Route) {
		if r.Parameters == nil {
			r.Parameters = []*ParameterInfo{}
		}
		r.Parameters = append(r.Parameters, &ParameterInfo{
			Name: name, In: "query", Type: typ, Required: required,
			Description: desc, Example: example,
		})
	}
}

// Body documents the request body as individual fields.
func Body(fields ...*Field) RouteOption {
	return func(r *Route) {
		r.RequestBody = &Field{
			Type:       "object",
			Properties: make(map[string]*Field),
		}
		for _, f := range fields {
			r.RequestBody.Properties[f.Name] = f
		}
	}
}

// BodySchema documents the request body as a single complex schema.
func BodySchema(schema *Field) RouteOption {
	return func(r *Route) {
		r.RequestBody = schema
	}
}

// BodyExample sets the example for the request body.
func BodyExample(example any) RouteOption {
	return func(r *Route) {
		r.RequestExample = example
	}
}

// Returns documents the response with description and example.
func Returns(desc string, example any) RouteOption {
	return func(r *Route) {
		r.Response = &ResponseInfo{
			Description: desc,
			Example:     example,
		}
	}
}

// ReturnsType documents the response by extracting schema from a struct type.
// Pass a zero value or pointer: ReturnsType("description", &MyType{})
func ReturnsType(desc string, example any) RouteOption {
	return func(r *Route) {
		r.Response = &ResponseInfo{
			Description: desc,
			Schema:      example, // Will be converted to OpenAPI schema during generation
			Example:     example,
		}
	}
}

// Example adds a named curl example.
func Example(name, curlish string) RouteOption {
	return func(r *Route) {
		if r.Examples == nil {
			r.Examples = make(map[string]string)
		}
		r.Examples[name] = curlish
	}
}

// Handler returns a JSON-able value, or an *Error.
type Handler func(r *Req) (any, error)

// Req is the request as handlers see it.
type Req struct {
	*http.Request
	User   string
	Client string
	body   []byte
	Params map[string]string // path parameters from {param} matches
}

// Error carries an HTTP status.
type Error struct {
	Status  int
	Message string
	Extra   map[string]any
}

func (e *Error) Error() string { return e.Message }

func Errorf(status int, format string, a ...any) *Error {
	return &Error{Status: status, Message: fmt.Sprintf(format, a...)}
}

func BadRequest(format string, a ...any) *Error { return Errorf(400, format, a...) }
func NotFound(format string, a ...any) *Error   { return Errorf(404, format, a...) }
func Forbidden(format string, a ...any) *Error  { return Errorf(403, format, a...) }

// Query helpers ------------------------------------------------------------

func (r *Req) Q(name, def string) string {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	return v
}

var safeRe = regexp.MustCompile(`^[A-Za-z0-9_.:@/ -]*$`)

// QSafe returns a query value limited to a safe character set and length.
func (r *Req) QSafe(name, def string, maxLen int) (string, error) {
	v := r.Q(name, def)
	if len(v) > maxLen {
		v = v[:maxLen]
	}
	if !safeRe.MatchString(v) {
		return "", BadRequest("%s contains invalid characters", name)
	}
	return v, nil
}

func (r *Req) QInt(name string, def, lo, hi int) int {
	v, err := strconv.Atoi(r.Q(name, ""))
	if err != nil {
		v = def
	}
	if v < lo {
		v = lo
	}
	if hi > 0 && v > hi {
		v = hi
	}
	return v
}

// Hours returns the requested window, bounded.
func (r *Req) Hours(def int) int { return r.QInt("hours", def, 1, 24*400) }

// Since returns now - hours as a unix timestamp.
func (r *Req) Since(defHours int) int64 {
	return time.Now().Unix() - int64(r.Hours(defHours))*3600
}

// Decode parses the JSON body into v.
func (r *Req) Decode(v any) error {
	if len(r.body) == 0 {
		return BadRequest("request body is required")
	}
	if err := json.Unmarshal(r.body, v); err != nil {
		return BadRequest("body is not valid JSON: %v", err)
	}
	return nil
}

// Body returns the parsed body as a generic map (empty map when none).
func (r *Req) Body() map[string]any {
	m := map[string]any{}
	if len(r.body) > 0 {
		_ = json.Unmarshal(r.body, &m)
	}
	return m
}

// Raw returns the raw body bytes.
func (r *Req) Raw() []byte { return r.body }

// NewReq builds a request carrying body, for calling handlers directly (tests,
// or a listener outside the API server) the way the server itself would.
func NewReq(r *http.Request, user, client string, body []byte) *Req {
	return &Req{Request: r, User: user, Client: client, body: body, Params: map[string]string{}}
}

// Setup ---------------------------------------------------------------------

func NewAPI(core *Core, static fs.FS, log *slog.Logger) *API {
	return &API{core: core, routes: map[string]*Route{}, static: static, log: log,
		sessions: map[string]session{}}
}

func (a *API) Add(method, p string, h Handler, module string, opts ...RouteOption) {
	method = strings.ToUpper(method)
	r := &Route{
		Method:     method,
		Path:       p,
		Handler:    h,
		Module:     module,
		Params:     map[string]string{},
		Parameters: []*ParameterInfo{},
		Examples:   make(map[string]string),
	}
	for _, o := range opts {
		o(r)
	}
	if r.Write && method == "GET" {
		panic("write route cannot be GET: " + p)
	}
	a.mu.Lock()
	a.routes[method+" "+p] = r
	a.mu.Unlock()
}

// fieldToOpenAPISchema converts a Field to an OpenAPI schema object.
func fieldToOpenAPISchema(f *Field) map[string]any {
	if f == nil {
		return map[string]any{"type": "object"}
	}

	schema := map[string]any{}
	if f.Type != "" {
		schema["type"] = f.Type
	}
	if f.Description != "" {
		schema["description"] = f.Description
	}
	if f.Example != nil {
		schema["example"] = f.Example
	}
	if f.Items != nil && f.Type == "array" {
		schema["items"] = fieldToOpenAPISchema(f.Items)
	}
	if len(f.Properties) > 0 {
		props := make(map[string]any)
		required := []string{}
		for name, prop := range f.Properties {
			props[name] = fieldToOpenAPISchema(prop)
			if prop.Required {
				required = append(required, name)
			}
		}
		sort.Strings(required)
		schema["properties"] = props
		if len(required) > 0 {
			schema["required"] = required
		}
	}
	return schema
}

// OpenAPI generates the reference from the route table, so it can never
// describe an endpoint that does not exist.
func (a *API) OpenAPI() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	keys := make([]string, 0, len(a.routes))
	for k := range a.routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	paths := map[string]map[string]any{}
	areaTagMap := map[string][]string{} // area -> list of area/page tags

	for _, k := range keys {
		r := a.routes[k]

		// Derive tags from TagMap if not explicitly set
		tags := r.Tags
		if len(tags) == 0 {
			if mapped, ok := TagMap[r.Module]; ok {
				tags = mapped // area/page pair like ["Monitor", "Hosts"]
			} else {
				tags = []string{"Other", r.Module}
			}
		}

		// Track area/page tags for x-tagGroups
		if len(tags) > 0 {
			area := tags[0]
			tagStr := area
			if len(tags) > 1 {
				tagStr = area + "/" + strings.Join(tags[1:], "/")
			}
			found := false
			for _, existing := range areaTagMap[area] {
				if existing == tagStr {
					found = true
					break
				}
			}
			if !found {
				areaTagMap[area] = append(areaTagMap[area], tagStr)
			}
		}

		// Generate operationId if not set
		opId := r.OperationId
		if opId == "" {
			opId = deriveOperationId(r.Module, r.Method, r.Path)
		}

		op := map[string]any{
			"summary":     r.Description,
			"tags":        tags,
			"operationId": opId,
		}

		if r.Description == "" {
			op["summary"] = "(undocumented)"
		}

		// Build parameters from both legacy Params and new Parameters
		var ps []map[string]any

		// Add rich parameters first
		for _, p := range r.Parameters {
			param := map[string]any{
				"name":     p.Name,
				"in":       p.In,
				"required": p.Required,
			}
			if p.Description != "" {
				param["description"] = p.Description
			}
			schema := map[string]any{"type": p.Type}
			if p.Example != nil {
				schema["example"] = p.Example
			}
			param["schema"] = schema
			ps = append(ps, param)
		}

		// Add legacy Params (query parameters) if no Parameters defined
		if len(r.Parameters) == 0 && len(r.Params) > 0 {
			pk := make([]string, 0, len(r.Params))
			for n := range r.Params {
				pk = append(pk, n)
			}
			sort.Strings(pk)
			for _, n := range pk {
				ps = append(ps, map[string]any{
					"name":        n,
					"in":          "query",
					"description": r.Params[n],
					"schema":      map[string]any{"type": "string"},
				})
			}
		}

		if len(ps) > 0 {
			op["parameters"] = ps
		}

		// Build request body
		if r.Write || r.RequestBody != nil {
			rb := map[string]any{
				"content": map[string]any{
					"application/json": map[string]any{},
				},
			}
			ajson := rb["content"].(map[string]any)["application/json"].(map[string]any)

			if r.RequestBody != nil {
				ajson["schema"] = fieldToOpenAPISchema(r.RequestBody)
			} else {
				ajson["schema"] = map[string]any{"type": "object"}
			}

			if r.RequestExample != nil {
				ajson["example"] = r.RequestExample
			}

			op["requestBody"] = rb
			op["x-write"] = true
		}

		// Build response
		resp := map[string]any{"description": "Success"}
		if r.Response != nil {
			if r.Response.Description != "" {
				resp["description"] = r.Response.Description
			}
			if r.Response.Example != nil || r.Response.Schema != nil {
				content := map[string]any{}
				ajson := map[string]any{}

				if r.Response.Schema != nil {
					if f, ok := r.Response.Schema.(*Field); ok {
						ajson["schema"] = fieldToOpenAPISchema(f)
					} else {
						// For other types, use example as schema hint
						ajson["schema"] = map[string]any{"type": "object"}
					}
				} else {
					ajson["schema"] = map[string]any{"type": "object"}
				}

				if r.Response.Example != nil {
					ajson["example"] = r.Response.Example
				}
				content["application/json"] = ajson
				resp["content"] = content
			}
		} else {
			resp["content"] = map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"type": "object"},
				},
			}
		}

		op["responses"] = map[string]any{"200": resp}

		// Store examples if any
		if len(r.Examples) > 0 {
			op["x-examples"] = r.Examples
		}

		if paths[r.Path] == nil {
			paths[r.Path] = map[string]any{}
		}
		paths[r.Path][strings.ToLower(r.Method)] = op
	}

	// Build x-tagGroups from collected areas and tags
	areas := []string{"Monitor", "Inventory", "Protect", "Administration"}
	var tagGroups []map[string]any
	for _, area := range areas {
		if tags, ok := areaTagMap[area]; ok && len(tags) > 0 {
			sort.Strings(tags)
			tagGroups = append(tagGroups, map[string]any{
				"name": area,
				"tags": tags,
			})
		}
	}

	info := map[string]any{
		"title":   "FlowSight API",
		"version": a.core.Version,
		"description": `Complete REST API for FlowSight network monitoring and policy.

**Authentication:**
- Token-based: Send X-Flowsight-Token header with your API token, or use Bearer scheme in Authorization header
- Session-based: POST to /api/login with token, receive fs_session cookie
- Loopback (127.0.0.1, ::1) with no token: trusted for local integration

**Query Windows:**
Use 'hours' and 'minutes' parameters to specify time windows for historical data (default varies by endpoint).

**Error Format:**
All errors return JSON: {"error": "description"}

**Write Operations:**
Use X-Requested-With: Flowsight header for security when calling from browsers, or provide X-Flowsight-Token / Bearer token.
`,
	}

	return map[string]any{
		"openapi":     "3.0.3",
		"info":        info,
		"servers":     []map[string]any{{"url": "/"}},
		"paths":       paths,
		"x-tagGroups": tagGroups,
	}
}

// IterateRoutes calls fn for each registered route.
func (a *API) IterateRoutes(fn func(method, path string, route *Route)) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	keys := make([]string, 0, len(a.routes))
	for k := range a.routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts := strings.Fields(k)
		if len(parts) != 2 {
			continue
		}
		method, path := parts[0], parts[1]
		fn(method, path, a.routes[k])
	}
}

// Auth ----------------------------------------------------------------------

func (a *API) token() string { return a.core.Config.Core().APIToken }

// tokenName says which configured token was presented: "token" for the
// unnamed api_token, "token:<name>" for a named one, "" for none.
func (a *API) tokenName(presented string) string {
	if presented == "" {
		return ""
	}
	cs := a.core.Config.Core()
	if cs.APIToken != "" && hmac.Equal([]byte(presented), []byte(cs.APIToken)) {
		return "token"
	}
	for _, t := range cs.APITokens {
		if t.Token != "" && hmac.Equal([]byte(presented), []byte(t.Token)) {
			return "token:" + t.Name
		}
	}
	return ""
}

func (a *API) anyToken() bool {
	cs := a.core.Config.Core()
	return cs.APIToken != "" || len(cs.APITokens) > 0
}

// authenticate returns (ok, user). Loopback with no token configured is
// trusted: that is the OPNsense case, where the GUI has already authenticated
// and proxies over 127.0.0.1. Anywhere else a token or session is required.
func (a *API) authenticate(r *http.Request, client string) (bool, string) {
	tok := a.token()
	presented := r.Header.Get("X-Flowsight-Token")
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		presented = strings.TrimSpace(h[7:])
	}
	loopback := client == "127.0.0.1" || client == "::1"
	if c, err := r.Cookie("fs_session"); err == nil {
		a.sessMu.Lock()
		s, ok := a.sessions[c.Value]
		a.sessMu.Unlock()
		if ok && s.expires.After(time.Now()) {
			return true, s.user
		}
	}
	if name := a.tokenName(presented); name != "" {
		// The OPNsense plugin proxies over loopback with the token and
		// says which GUI user is acting; the audit log names the person and
		// keeps the token beside them.
		if u := r.Header.Get("X-Flowsight-User"); u != "" && loopback {
			return true, u + " (gui, " + name + ")"
		}
		return true, name
	}
	if !a.anyToken() && loopback {
		if u := r.Header.Get("X-Flowsight-User"); u != "" {
			return true, u + " (gui)"
		}
		return true, "local"
	}
	_ = tok
	return false, ""
}

func (a *API) login(token string) (string, bool) {
	name := a.tokenName(token)
	if name == "" {
		return "", false
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	sid := base64.RawURLEncoding.EncodeToString(b)
	a.sessMu.Lock()
	// Expired sessions go every time one is made, and the table has a
	// ceiling: past it the soonest-to-expire are dropped, so a flood of
	// logins cannot grow memory without bound.
	now := time.Now()
	for k, s := range a.sessions {
		if s.expires.Before(now) {
			delete(a.sessions, k)
		}
	}
	for len(a.sessions) >= 1000 {
		var oldest string
		var oldestAt time.Time
		for k, s := range a.sessions {
			if oldest == "" || s.expires.Before(oldestAt) {
				oldest, oldestAt = k, s.expires
			}
		}
		delete(a.sessions, oldest)
	}
	a.sessions[sid] = session{user: "session (" + name + ")", expires: now.Add(12 * time.Hour)}
	a.sessMu.Unlock()
	return sid, true
}

// Serving -------------------------------------------------------------------

const maxBody = 4 << 20

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"encoding failed"}`)
		status = 500
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	a.securityHeaders(h)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (a *API) securityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' "+
		"'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; "+
		"frame-ancestors 'self'")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	client := clientIP(r)
	p := path.Clean(r.URL.Path)
	defer func() {
		if d := time.Since(t0); d > 5*time.Second {
			a.log.Warn("slow request", "method", r.Method, "path", p, "seconds", d.Seconds())
		}
	}()

	// Static UI, no auth: it is public HTML that reveals nothing.
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if p == "/" || p == "/index.html" {
			// The shell references its assets under a version directory so a
			// browser never keeps an old app.js after an update.
			a.serveIndex(w, r)
			return
		}
		if p == "/favicon.ico" {
			p = "/static/favicon.svg"
		}
		if strings.HasPrefix(p, "/static/") {
			a.serveStatic(w, r, strings.TrimPrefix(p, "/static/"))
			return
		}
	}

	ok, user := a.authenticate(r, client)

	if p == "/api/login" && r.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var in struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(body, &in)
		sid, good := a.login(in.Token)
		if !good {
			time.Sleep(500 * time.Millisecond)
			a.writeJSON(w, 401, map[string]any{"error": "invalid token"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "fs_session", Value: sid, HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Path: "/", MaxAge: 12 * 3600})
		a.writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if !ok {
		a.writeJSON(w, 401, map[string]any{"error": "authentication required"})
		return
	}

	a.mu.RLock()
	route := a.routes[r.Method+" "+p]
	if route == nil && (r.Method == http.MethodPut || r.Method == http.MethodDelete ||
		r.Method == http.MethodPatch) {
		route = a.routes["POST "+p]
	}
	// Try pattern matching for parameterized paths
	var params map[string]string
	if route == nil {
		route, params = a.matchPattern(r.Method, p)
	}
	a.mu.RUnlock()
	if route == nil {
		a.writeJSON(w, 404, map[string]any{"error": "not found: " + p})
		return
	}

	req := &Req{Request: r, User: user, Client: client, Params: params}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.ContentLength > maxBody {
			a.writeJSON(w, 413, map[string]any{"error": "payload too large"})
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(b) > maxBody {
			a.writeJSON(w, 413, map[string]any{"error": "payload too large"})
			return
		}
		req.body = b
	}

	if route.Write {
		// The single write gate. A cross-site request from a browser cannot
		// carry a custom header without a CORS preflight, and preflights are
		// never answered here, so this header is proof the call came from the
		// UI itself or from an API client holding the token.
		if r.Header.Get("X-Requested-With") != "Flowsight" && r.Header.Get("X-Flowsight-Token") == "" &&
			!strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "bearer ") {
			a.writeJSON(w, 403, map[string]any{"error": "missing X-Requested-With: Flowsight header"})
			return
		}
		if a.core.ReadOnly() {
			a.writeJSON(w, 403, map[string]any{"error": "this instance is read-only"})
			return
		}
	}

	if route.Feature != "" {
		lic := a.core.License()
		if err := lic.Allowed(route.Feature); err != nil {
			e := err.(*Error)
			doc := map[string]any{"error": e.Message}
			for k, v := range e.Extra {
				doc[k] = v
			}
			a.writeJSON(w, e.Status, doc)
			return
		}
		if route.Write && lic.Expired() {
			e := ExpiredError(route.Feature).(*Error)
			doc := map[string]any{"error": e.Message}
			for k, v := range e.Extra {
				doc[k] = v
			}
			a.writeJSON(w, e.Status, doc)
			return
		}
	}
	result, err := a.call(route, req)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			doc := map[string]any{"error": e.Message}
			for k, v := range e.Extra {
				doc[k] = v
			}
			a.writeJSON(w, e.Status, doc)
			return
		}
		a.log.Error("handler failed", "method", r.Method, "path", p, "error", err.Error())
		a.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if route.Write {
		a.core.audit(user, r.Method, p, req.Body(), client)
	}
	switch v := result.(type) {
	case nil:
		a.writeJSON(w, 200, map[string]any{"ok": true})
	case Stream:
		// The handler writes the response itself: server-sent events, a
		// long download. Headers and flushing are its business.
		a.securityHeaders(w.Header())
		v(w)
	case Raw:
		h := w.Header()
		h.Set("Content-Type", v.ContentType)
		h.Set("Cache-Control", "no-store")
		a.securityHeaders(h)
		if v.Filename != "" {
			h.Set("Content-Disposition", "attachment; filename=\""+v.Filename+"\"")
		}
		w.WriteHeader(200)
		_, _ = w.Write(v.Body)
	default:
		a.writeJSON(w, 200, v)
	}
}

// Stream lets a handler take over the response writer, for server-sent
// events and other responses that are written as they happen.
type Stream func(w http.ResponseWriter)

// Raw lets a handler return non-JSON (CSV export, a PEM file, a report).
type Raw struct {
	ContentType string
	Filename    string
	Body        []byte
}

func (a *API) call(route *Route, req *Req) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in %s: %v", route.Path, r)
		}
	}()
	return route.Handler(req)
}

// serveIndex serves the shell with every /static/ reference rewritten to
// /static/v<version>/ so assets are cached hard yet refreshed on update.
func (a *API) serveIndex(w http.ResponseWriter, r *http.Request) {
	if a.static == nil {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(a.static, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	v := "v" + strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' {
			return c
		}
		return '-'
	}, a.core.Version)
	html := strings.ReplaceAll(string(data), `"/static/`, `"/static/`+v+`/`)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	a.securityHeaders(h)
	_, _ = w.Write([]byte(html))
}

func (a *API) serveStatic(w http.ResponseWriter, r *http.Request, rel string) {
	if rel == "" || strings.Contains(rel, "..") || a.static == nil {
		http.NotFound(w, r)
		return
	}
	// A leading version directory (see serveIndex) is only a cache key.
	versioned := false
	if strings.HasPrefix(rel, "v") {
		if i := strings.IndexByte(rel, '/'); i > 0 {
			rel, versioned = rel[i+1:], true
		}
	}
	data, err := fs.ReadFile(a.static, rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctype := mime.TypeByExtension(path.Ext(rel))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	sum := sha1.Sum(data)
	etag := `"` + hex.EncodeToString(sum[:10]) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	if versioned {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	h.Set("Content-Type", ctype)
	a.securityHeaders(h)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// Listen serves until the context ends.
func (a *API) Listen(bind string, port int) (*http.Server, error) {
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	srv := &http.Server{Addr: addr, Handler: a, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 64 << 10}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if bind != "127.0.0.1" && bind != "::1" && bind != "localhost" && a.token() == "" {
		a.log.Warn("listening beyond loopback with no api_token: anyone on that network can read and "+
			"change everything; set api_token in the config", "bind", bind)
	}
	a.log.Info("listening", "addr", "http://"+addr)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("http server stopped", "error", err.Error())
		}
	}()
	return srv, nil
}

// matchPattern attempts to match a request path against parameterized route patterns.
// It returns the matching route and extracted parameters if found.
func (a *API) matchPattern(method, path string) (*Route, map[string]string) {
	// Try to match against registered patterns
	for key, route := range a.routes {
		parts := strings.Fields(key) // "METHOD /path"
		if len(parts) != 2 || parts[0] != method {
			continue
		}
		pattern := parts[1]
		if params := matchPath(pattern, path); params != nil {
			return route, params
		}
	}
	return nil, nil
}

// matchPath checks if a path matches a pattern like /api/policy/groups/{name}.
// Returns extracted parameters if it matches, nil otherwise.
func matchPath(pattern, path string) map[string]string {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return nil
	}

	params := make(map[string]string)
	for i, pp := range patternParts {
		if strings.HasPrefix(pp, "{") && strings.HasSuffix(pp, "}") {
			// This is a parameter
			paramName := pp[1 : len(pp)-1]
			params[paramName] = pathParts[i]
		} else if pp != pathParts[i] {
			// Literal mismatch
			return nil
		}
	}
	return params
}

// OpenAPI helper functions -------------------------------------------------

// deriveOperationId creates a stable operation ID from module, method, and path.
// Format: module.methodNoun (e.g., policy.listPolicies, policy.createPolicy)
func deriveOperationId(module, method, path string) string {
	noun := derivNoun(path)
	verb := verbFromMethod(method)
	return module + "." + verb + noun
}

// derivNoun extracts the main resource name from a path.
// /api/policy -> "Policy", /api/policy/policies -> "Policies"
// /api/enroll/devices/{mac} -> "Device"
func derivNoun(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
	if len(parts) < 2 {
		return "Item"
	}
	noun := parts[1]
	if noun == "" {
		return "Item"
	}
	// Singularize common plurals in operationId
	if strings.HasSuffix(noun, "ies") {
		noun = noun[:len(noun)-3] + "y"
	} else if strings.HasSuffix(noun, "es") {
		noun = noun[:len(noun)-2]
	} else if strings.HasSuffix(noun, "s") && noun != "status" && noun != "rules" {
		noun = noun[:len(noun)-1]
	}
	return capitalize(noun)
}

// verbFromMethod maps HTTP method to operation verb.
func verbFromMethod(method string) string {
	switch method {
	case "GET":
		return "get"
	case "POST", "PUT":
		return "create"
	case "DELETE":
		return "delete"
	case "PATCH":
		return "update"
	default:
		return "handle"
	}
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
