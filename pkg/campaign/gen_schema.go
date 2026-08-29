//go:build ignore

// Command gen_schema writes the published campaign JSON Schema.
//
//	go run ./pkg/campaign/gen_schema.go
//
// The output is checked in and verified by a test, so regenerating it is a
// deliberate act that shows up in review rather than something a build does
// silently.
package main

import (
	"log"
	"os"

	"github.com/rom/Xfuzz/pkg/campaign"
)

func main() {
	b, err := campaign.JSONSchema()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("pkg/campaign/schema/campaign.v1.json", b, 0o644); err != nil {
		log.Fatal(err)
	}
}
