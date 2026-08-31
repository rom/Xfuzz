package schemaio_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/schema"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

// A .proto of the shape a service repository carries: scalars of every wire
// type, a nested message, a repeated field, a map, a oneof, an enum, and a
// field number past 15 so the key needs two varint bytes.
const orderProto = `
syntax = "proto3";
package shop.v1;

import "google/protobuf/timestamp.proto";

enum Status {
  STATUS_UNKNOWN = 0;
  STATUS_PAID = 1;
}

message Order {
  string id = 1;
  Status status = 2;
  int32 quantity = 3;
  bool express = 4;
  double weight = 5;
  fixed32 checksum = 6;
  bytes note = 7;
  Address ship_to = 8;
  repeated Line lines = 9;
  map<string, string> labels = 10;
  string long_field_number = 2000;

  oneof payment {
    Card card = 11;
    string invoice_ref = 12;
  }

  message Line {
    string sku = 1;
    int32 qty = 2;
  }
}

message Address {
  string street = 1;
  string city = 2;
}

message Card {
  string last4 = 1;
}

service Orders {
  rpc Create (Order) returns (Order);
}
`

func TestProtoGeneratesAWellFormedFrame(t *testing.T) {
	s, rep := mustImport(t, schemaio.Proto{}, orderProto, "order.proto")
	t.Logf("%s", rep)

	for i := 0; i < 16; i++ {
		out := generates(t, s)
		if i == 0 {
			t.Logf("generated %d bytes: %x", len(out), out)
		}
		// Read it the way a protobuf runtime does: key varint, wire type,
		// payload, repeat. A frame that does not walk is a frame every decoder
		// rejects at the first field, and the campaign never gets past it.
		if err := walkProto(out); err != nil {
			t.Fatalf("sample %d is not a well-formed protobuf frame: %v\n%x", i, err, out)
		}
	}
}

// walkProto reads a message the way a decoder does, and reports the first thing
// that does not add up.
func walkProto(b []byte) error {
	for len(b) > 0 {
		key, n := readVarint(b)
		if n == 0 {
			return errAt("truncated key", len(b))
		}
		b = b[n:]
		switch key & 7 {
		case 0:
			_, n := readVarint(b)
			if n == 0 {
				return errAt("truncated varint", len(b))
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return errAt("truncated fixed64", len(b))
			}
			b = b[8:]
		case 2:
			l, n := readVarint(b)
			if n == 0 {
				return errAt("truncated length", len(b))
			}
			b = b[n:]
			if uint64(len(b)) < l {
				return errAt("length past the end of the message", len(b))
			}
			b = b[l:]
		case 5:
			if len(b) < 4 {
				return errAt("truncated fixed32", len(b))
			}
			b = b[4:]
		default:
			return errAt("wire type 3, 4 or 6", len(b))
		}
	}
	return nil
}

func readVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

type protoErr struct{ what string }

func (e protoErr) Error() string { return e.what }
func errAt(what string, left int) error {
	return protoErr{what: what + " (" + itoa(left) + " bytes left)"}
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// TestProtoKeysAreExact. A field's key is a constant, so its varint is computed
// once and written as a literal however many bytes it needs — which means the
// field-number limit that applies to values does not apply to keys.
func TestProtoKeysAreExact(t *testing.T) {
	s, _ := mustImport(t, schemaio.Proto{}, orderProto, "order.proto")
	order, ok := s.Lookup("Order")
	if !ok {
		t.Fatal("Order is missing")
	}
	keys := map[string][]byte{}
	for _, f := range order.Fields {
		if strings.HasSuffix(f.Name, "_key") && f.Type.HasLiteral {
			keys[strings.TrimSuffix(f.Name, "_key")] = f.Type.Literal
		}
	}
	// id is field 1, wire type 2: (1<<3)|2 = 0x0a, one byte.
	if got := keys["id"]; len(got) != 1 || got[0] != 0x0a {
		t.Errorf("the key for field 1 is %x, want 0a", got)
	}
	// long_field_number is 2000, wire type 2: (2000<<3)|2 = 16002, two bytes.
	got := keys["long_field_number"]
	if len(got) != 2 {
		t.Fatalf("the key for field 2000 is %x, want two bytes", got)
	}
	if v, _ := readVarint(got); v != 2000<<3|2 {
		t.Errorf("the key for field 2000 decodes to %d", v)
	}
	// Every key is immutable: a mutated key is a different field, and usually
	// one the message does not have.
	for _, f := range order.Fields {
		if strings.HasSuffix(f.Name, "_key") && !f.Type.Immutable {
			t.Errorf("%s is mutable", f.Name)
		}
	}
}

func TestProtoWireTypes(t *testing.T) {
	s, _ := mustImport(t, schemaio.Proto{}, orderProto, "order.proto")
	order, _ := s.Lookup("Order")
	byName := map[string]schema.Field{}
	for _, f := range order.Fields {
		byName[f.Name] = f
	}
	// A double is eight fixed bytes and a fixed32 is four; those are exact,
	// because their width does not depend on their value.
	if got := byName["weight"].Type; got.Min != 8 || got.Max != 8 {
		t.Errorf("a double became %s", got)
	}
	if got := byName["checksum"].Type; got.Min != 4 || got.Max != 4 {
		t.Errorf("a fixed32 became %s", got)
	}
	// A bool has two values and both are one byte, so it is exact too.
	if got := byName["express"].Type; got.Kind != schema.KindChoice || len(got.Fields) != 2 {
		t.Errorf("a bool became %s", got)
	}
}

func TestProtoOneofBecomesAChoice(t *testing.T) {
	s, _ := mustImport(t, schemaio.Proto{}, orderProto, "order.proto")
	order, _ := s.Lookup("Order")
	for _, f := range order.Fields {
		if f.Name != "payment" {
			continue
		}
		if f.Type.Kind != schema.KindChoice || len(f.Type.Fields) != 2 {
			t.Errorf("the oneof became %s with %d alternatives", f.Type.Kind, len(f.Type.Fields))
		}
		return
	}
	t.Errorf("the oneof is not a field:\n%s", order)
}

func TestProtoNestedAndReferencedMessages(t *testing.T) {
	s, _ := mustImport(t, schemaio.Proto{}, orderProto, "order.proto")
	for _, name := range []string{"Order", "Address", "Card", "Order_Line"} {
		if _, ok := s.Lookup(name); !ok {
			t.Errorf("%s is not in the grammar; it declares %s", name,
				strings.Join(s.TypeNames(), ", "))
		}
	}
}

// TestProtoReportsTheVarint is the one approximation in the file, and the report
// has to name it: a value above 127 needs a multi-byte varint, which is not a
// fixed-width integer.
func TestProtoReportsTheVarint(t *testing.T) {
	_, rep := mustImport(t, schemaio.Proto{}, orderProto, "order.proto")
	joined := strings.Join(rep.Summarise(), "\n")
	for _, want := range []string{"varint", "127", "imported definition", "service"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q was not reported:\n%s", want, joined)
		}
	}
}

func TestProtoRefusesAFileWithNoMessages(t *testing.T) {
	if _, _, err := (schemaio.Proto{}).Import(
		[]byte("syntax = \"proto3\";\npackage x;\n"), "x.proto"); err == nil {
		t.Error("a file with no messages imported successfully")
	}
}

func TestProtoIsDeterministic(t *testing.T) {
	first, _, err := schemaio.Proto{}.Import([]byte(orderProto), "o.proto")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		got, _, err := schemaio.Proto{}.Import([]byte(orderProto), "o.proto")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != first.String() {
			t.Fatalf("import %d differed:\n%s\n---\n%s", i+1, first, got)
		}
	}
}
