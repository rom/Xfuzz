package schemaio

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rom/Xfuzz/pkg/schema"
)

// OpenAPI imports an OpenAPI description as a grammar for HTTP requests.
//
// Requests rather than JSON documents, because that is what the API tier sends
// (ADR-0014): a request line, headers, a blank line and a body, as bytes. The
// body's shape comes from the operation's JSON Schema, so this importer is the
// JSON Schema one with an HTTP envelope around it and a path template filled in.
//
// The root is a choice over every operation, which makes one grammar cover a
// whole API: a mutation that switches the alternative sends a different endpoint
// with the corpus's accumulated body shapes behind it, which is a class of input
// nobody writes by hand.
//
// ADR-0014 is explicit that a specification is the secondary source and captured
// traffic the primary one, and the reason shows up here. A description says what
// the API accepts; it does not say which values the service will still recognise
// an hour later, and it carries no identity, so the authorization oracle has
// nothing to work with. An imported grammar is a good way to reach endpoints a
// capture never exercised, and a poor substitute for the capture.
type OpenAPI struct{}

// Name implements Importer.
func (OpenAPI) Name() string { return "openapi" }

// Extensions implements Importer.
func (OpenAPI) Extensions() []string { return []string{".yaml", ".yml", ".json"} }

// sniff implements sniffer.
func (OpenAPI) sniff(head string) bool {
	return strings.Contains(head, "openapi:") || strings.Contains(head, `"openapi"`) ||
		strings.Contains(head, "swagger:") || strings.Contains(head, `"swagger"`)
}

// Import implements Importer.
func (OpenAPI) Import(src []byte, filename string) (*schema.Schema, *Report, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, nil, fmt.Errorf("openapi: %s: %w", filename, err)
	}
	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("openapi: %s: no paths, so there are no requests to describe", filename)
	}

	o := &openAPIImport{
		b:    newBuilder("openapi", filename),
		doc:  doc,
		host: hostOf(doc),
	}
	o.json = newJSONImport(o.b, doc)

	var ops []schema.Field
	for _, path := range sortedKeys(paths) {
		item, _ := paths[path].(map[string]any)
		for _, method := range sortedKeys(item) {
			if !isHTTPMethod(method) {
				continue
			}
			op, _ := item[method].(map[string]any)
			name := o.operation(method, path, op, item)
			ops = append(ops, field(name, refTo(name)))
		}
	}
	if len(ops) == 0 {
		return nil, nil, fmt.Errorf("openapi: %s: the paths declare no operations", filename)
	}

	root := o.b.nameFor("request")
	if len(ops) == 1 {
		o.b.s.Types[root] = structOf(field("op", ops[0].Type))
	} else {
		o.b.s.Types[root] = structOf(field("op", choiceOf(uniqueFields(ops)...)))
	}
	return o.b.finish(root)
}

type openAPIImport struct {
	b    *builder
	doc  map[string]any
	json *jsonImport
	host string
}

var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

func isHTTPMethod(s string) bool { return httpMethods[strings.ToLower(s)] }

// hostOf reads the first server's host, which is what the Host header needs.
//
// The header has to be there and has to be something: HTTP/1.1 requires it, and
// a request without one is rejected by every server before it reaches the code
// worth fuzzing. The campaign's own address is what the request is actually sent
// to; this is only what it claims.
func hostOf(doc map[string]any) string {
	servers, _ := doc["servers"].([]any)
	for _, s := range servers {
		m, _ := s.(map[string]any)
		raw, _ := m["url"].(string)
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if h, ok := doc["host"].(string); ok && h != "" {
		return h // OpenAPI 2
	}
	return "localhost"
}

// operation declares one request type and returns its name.
func (o *openAPIImport) operation(method, path string, op, item map[string]any) string {
	name := o.b.nameFor(operationName(method, path, op))
	where := strings.ToUpper(method) + " " + path

	fields := []schema.Field{
		field("method", magic(strings.ToUpper(method)+" ")),
	}
	fields = append(fields, o.target(name, path, op, item, where)...)
	fields = append(fields, field("version", magic(" HTTP/1.1\r\n")))
	fields = append(fields, field("host", magic("Host: "+o.host+"\r\n")))

	for _, h := range o.headerParams(name, op, item, where) {
		fields = append(fields, h)
	}

	body, ok := o.body(name, op, where)
	if ok {
		fields = append(fields,
			field("content_type", magic("Content-Type: application/json\r\n")),
			// A decimal length is not a fixed-width integer, so it cannot be a
			// derived field: this language computes lengths as binary. The API
			// tier recomputes it immediately before the write, which is what its
			// fix-length option is for; without that the request is sent with a
			// length that does not describe the body.
			field("content_length", magic("Content-Length: 0\r\n")),
			field("blank", magic("\r\n")),
			field("body", body),
		)
		o.b.rep.Add(where, "Content-Length",
			"a decimal length is not a fixed-width integer, so the grammar cannot "+
				"derive it; run the api tier with fix-length, which recomputes it "+
				"before the request is written")
	} else {
		fields = append(fields, field("blank", magic("\r\n")))
	}

	o.b.s.Types[name] = structOf(uniqueFields(fields)...)
	return name
}

// operationName is what the type is called: the operationId when the document
// gives one, because that is the name the API's own users know it by.
func operationName(method, path string, op map[string]any) string {
	if id, ok := op["operationId"].(string); ok && id != "" {
		return id
	}
	return strings.ToLower(method) + "_" + strings.Trim(path, "/")
}

// target builds the request target, filling in the path template.
//
// A path parameter is a value the service will look up, so it is a field a
// mutator may edit rather than a literal: /items/{id} is where the
// identifier-shaped bugs are, and a grammar that froze the template's example
// would never send a different one.
func (o *openAPIImport) target(owner, path string, op, item map[string]any, where string) []schema.Field {
	params := mergeParams(item, op)
	var fields []schema.Field
	rest := path
	i := 0
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			break
		}
		close := strings.IndexByte(rest[open:], '}')
		if close < 0 {
			break
		}
		if open > 0 {
			fields = append(fields, field(fmt.Sprintf("p%d", i), magic(rest[:open])))
		}
		pname := rest[open+1 : open+close]
		fields = append(fields, field(ident(pname), o.paramValue(owner, pname, params, "path", where)))
		rest = rest[open+close+1:]
		i++
	}
	if rest != "" {
		fields = append(fields, field(fmt.Sprintf("p%d", i), magic(rest)))
	}
	if q := o.query(owner, params, where); q != nil {
		fields = append(fields, field("query", q))
	}
	if len(fields) == 0 {
		fields = append(fields, field("path", magic(path)))
	}
	return fields
}

// query builds the query string from the parameters declared in it.
func (o *openAPIImport) query(owner string, params []map[string]any, where string) *schema.Type {
	var fields []schema.Field
	first := true
	for _, p := range params {
		if in, _ := p["in"].(string); in != "query" {
			continue
		}
		name, _ := p["name"].(string)
		if name == "" {
			continue
		}
		sep := "&"
		if first {
			sep, first = "?", false
		}
		member := structOf(
			field("sep", magic(sep+name+"=")),
			field("value", o.paramText(owner, name, p, where)),
		)
		if req, _ := p["required"].(bool); req {
			fields = append(fields, field(ident(name), member))
			continue
		}
		// The separator travels inside the parameter, so an absent one leaves a
		// query string rather than a dangling ampersand — with the same
		// exception the JSON objects have: the first one is unconditional.
		if first {
			fields = append(fields, field(ident(name), member))
			continue
		}
		elem := o.b.nameFor(owner + "_q_" + ident(name))
		o.b.s.Types[elem] = member
		fields = append(fields, field(ident(name), optOf(elem)))
	}
	if len(fields) == 0 {
		return nil
	}
	return structOf(uniqueFields(fields)...)
}

// paramValue is a path parameter: a value with no delimiters around it.
func (o *openAPIImport) paramValue(owner, name string, params []map[string]any,
	in, where string) *schema.Type {

	for _, p := range params {
		if pin, _ := p["in"].(string); pin != in {
			continue
		}
		if pn, _ := p["name"].(string); pn == name {
			return o.paramText(owner, name, p, where)
		}
	}
	// A template segment the document never declares. It is still a value the
	// service parses, so it is still worth fuzzing.
	o.b.rep.Add(where, "undeclared path parameter {"+name+"}",
		"the template names it and the parameters do not; generated as a free "+
			"string of the shape an identifier usually has")
	return text("1", 1, 24)
}

// paramText renders a parameter as the text a request carries.
//
// Text, always: a path or query parameter is decimal in the URL whatever the
// document calls its type, and generating a binary integer there would produce
// a request no server routes.
func (o *openAPIImport) paramText(owner, name string, p map[string]any, where string) *schema.Type {
	sch, _ := p["schema"].(map[string]any)
	minimum, maximum := 1, 24
	filler := "1"
	if sch != nil {
		if v, ok := jsonInt(sch["minLength"]); ok && v > 0 {
			minimum = v
		}
		if v, ok := jsonInt(sch["maxLength"]); ok && v > 0 {
			maximum = v
		}
		if e, ok := sch["enum"].([]any); ok && len(e) > 0 {
			fields := make([]schema.Field, 0, len(e))
			for i, v := range e {
				fields = append(fields, field(fmt.Sprintf("v%d", i+1), magic(plainString(v))))
			}
			return choiceOf(uniqueFields(fields)...)
		}
		if ex, ok := sch["example"]; ok {
			filler = plainString(ex)
		}
	}
	if ex, ok := p["example"]; ok {
		filler = plainString(ex)
	}
	if maximum < minimum {
		maximum = minimum
	}
	if len(filler) > maximum {
		filler = filler[:maximum]
	}
	_ = owner
	return text(filler, minimum, maximum)
}

// headerParams renders the header parameters an operation declares.
func (o *openAPIImport) headerParams(owner string, op, item map[string]any, where string) []schema.Field {
	var out []schema.Field
	for _, p := range mergeParams(item, op) {
		in, _ := p["in"].(string)
		if in != "header" {
			continue
		}
		name, _ := p["name"].(string)
		if name == "" || strings.EqualFold(name, "host") ||
			strings.EqualFold(name, "content-length") {
			continue
		}
		member := structOf(
			field("name", magic(name+": ")),
			field("value", o.paramText(owner, name, p, where)),
			field("eol", magic("\r\n")),
		)
		if req, _ := p["required"].(bool); req {
			out = append(out, field("h_"+ident(name), member))
			continue
		}
		elem := o.b.nameFor(owner + "_h_" + ident(name))
		o.b.s.Types[elem] = member
		out = append(out, field("h_"+ident(name), optOf(elem)))
	}
	return out
}

// body builds the request body from the operation's JSON schema.
func (o *openAPIImport) body(owner string, op map[string]any, where string) (*schema.Type, bool) {
	rb, _ := op["requestBody"].(map[string]any)
	if rb == nil {
		return nil, false
	}
	if ref, ok := rb["$ref"].(string); ok {
		if resolved := o.json.follow(ref); resolved != nil {
			rb = resolved
		}
	}
	content, _ := rb["content"].(map[string]any)
	if content == nil {
		return nil, false
	}
	media, ok := content["application/json"].(map[string]any)
	if !ok {
		for _, name := range sortedKeys(content) {
			if strings.HasSuffix(name, "+json") {
				media, ok = content[name].(map[string]any)
				break
			}
		}
	}
	if !ok || media == nil {
		types := sortedKeys(content)
		o.b.rep.Add(where, "request body media type",
			strings.Join(types, ", ")+" is not JSON; the importer describes JSON "+
				"bodies and this operation is generated without one")
		return nil, false
	}
	sch, _ := media["schema"].(map[string]any)
	if sch == nil {
		return nil, false
	}
	return o.json.typeFor(sch, where+" body", owner+"_body"), true
}

// mergeParams collects the path-item parameters and the operation's own, with
// the operation's taking precedence, which is what the specification says.
func mergeParams(item, op map[string]any) []map[string]any {
	byKey := map[string]map[string]any{}
	var order []string
	add := func(list any) {
		items, _ := list.([]any)
		for _, p := range items {
			m, _ := p.(map[string]any)
			if m == nil {
				continue
			}
			name, _ := m["name"].(string)
			in, _ := m["in"].(string)
			key := in + ":" + name
			if _, seen := byKey[key]; !seen {
				order = append(order, key)
			}
			byKey[key] = m
		}
	}
	add(item["parameters"])
	add(op["parameters"])
	sort.Strings(order)
	out := make([]map[string]any, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}

// plainString renders a scalar the way a URL carries it.
func plainString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}
