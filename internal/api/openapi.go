package api

import (
	"encoding/json"
	"strings"

	"github.com/rom/Xfuzz/internal/version"
)

// OpenAPI generates this API's description from the route table.
//
// Generated, not written: ADR-0024 chose HTTP/JSON over gRPC partly on the
// argument that a schema is real value and not exclusive to protobuf — which is
// only true if the schema is derived from the surface rather than maintained
// beside it. A description written by hand drifts on the first route added, and
// a description that lies is worse than none, because a generated client will
// call the route it describes.
func (s *Server) OpenAPI() ([]byte, error) {
	paths := map[string]map[string]any{}

	for _, r := range s.Routes() {
		item, ok := paths[r.Path]
		if !ok {
			item = map[string]any{}
			paths[r.Path] = item
		}
		op := map[string]any{
			"operationId": r.Name,
			"summary":     r.Summary,
			"tags":        []string{string(r.Service)},
			"responses": map[string]any{
				"200": map[string]any{"description": "success"},
				"400": errorResponse("the request was malformed or the campaign invalid"),
				"401": errorResponse("a bearer token is required"),
				"404": errorResponse("no such campaign, finding, or corpus entry"),
				"409": errorResponse("the campaign is not in a state that permits this"),
			},
		}
		if params := pathParams(r.Path); len(params) > 0 {
			op["parameters"] = params
		}
		item[strings.ToLower(r.Method)] = op
	}

	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Xfuzz daemon API",
			"version": version.Get().Version,
			"description": "The single source of truth for campaign state. The CLI and the web " +
				"console are both clients of this surface, and a parity test asserts neither has a " +
				"capability the other lacks. Generated from the route table; see ADR-0024.",
		},
		"servers": []any{
			map[string]any{"url": "/", "description": "the daemon's Unix socket, or its TCP listener"},
		},
		"paths": paths,
		"components": map[string]any{
			"schemas": map[string]any{
				"Error": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"error": map[string]any{"type": "string"},
						"details": map[string]any{
							"type":        "array",
							"items":       map[string]any{"type": "string"},
							"description": "One entry per problem. A campaign with nine mistakes reports nine.",
						},
					},
					"required": []string{"error"},
				},
			},
			"securitySchemes": map[string]any{
				"bearer": map[string]any{"type": "http", "scheme": "bearer"},
			},
		},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func errorResponse(desc string) map[string]any {
	return map[string]any{
		"description": desc,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/Error"},
			},
		},
	}
}

// pathParams extracts {placeholders} from a route path.
func pathParams(path string) []any {
	var out []any
	for _, seg := range strings.Split(path, "/") {
		if !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		name := seg[1 : len(seg)-1]
		out = append(out, map[string]any{
			"name": name, "in": "path", "required": true,
			"schema": map[string]any{"type": "string"},
		})
	}
	return out
}
