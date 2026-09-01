// Package strictjson provides the small strict-decoding contract shared by
// e-signature provider adapters. It rejects duplicate names, unknown struct
// fields, invalid UTF-8, excessive nesting, and trailing JSON values.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const maxDepth = 100

var (
	rawMessageType  = reflect.TypeOf(json.RawMessage{})
	unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
)

// Decode decodes exactly one JSON value into target. Callers that surface
// errors to workflow logs should replace the returned parser detail with a
// fixed message because an unknown JSON member name is attacker-controlled.
func Decode(raw []byte, target any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	if err := validateJSONStringSurrogates(raw); err != nil {
		return err
	}
	targetType := reflect.TypeOf(target)
	if targetType == nil {
		return errors.New("JSON target is required")
	}
	if err := inspectNames(raw, targetType); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// validateJSONStringSurrogates rejects the one Unicode ambiguity left by
// encoding/json: it replacement-decodes unpaired escaped UTF-16 surrogates to
// U+FFFD. Walk raw JSON strings so a signed payload is never canonicalized into
// different text. Escaped backslashes are skipped, while a high surrogate must
// be immediately followed by one escaped low surrogate.
func validateJSONStringSurrogates(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch {
		case !inString && raw[index] == '"':
			inString = true
		case !inString:
			continue
		case raw[index] == '"':
			inString = false
		case raw[index] == '\\':
			if index+1 >= len(raw) {
				continue // The JSON decoder reports the incomplete escape.
			}
			if raw[index+1] != 'u' {
				index++ // An escaped backslash cannot introduce a surrogate.
				continue
			}
			code, ok := decodeJSONHexQuad(raw, index+2)
			if !ok {
				return errors.New("invalid JSON Unicode escape")
			}
			index += 5
			switch {
			case code >= 0xd800 && code <= 0xdbff:
				pairStart := index + 1
				if pairStart+5 >= len(raw) || raw[pairStart] != '\\' || raw[pairStart+1] != 'u' {
					return errors.New("JSON strings must contain paired Unicode surrogate escapes")
				}
				low, valid := decodeJSONHexQuad(raw, pairStart+2)
				if !valid || low < 0xdc00 || low > 0xdfff {
					return errors.New("JSON strings must contain paired Unicode surrogate escapes")
				}
				index = pairStart + 5
			case code >= 0xdc00 && code <= 0xdfff:
				return errors.New("JSON strings must contain paired Unicode surrogate escapes")
			}
		}
	}
	return nil
}

func decodeJSONHexQuad(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, encoded := range raw[start : start+4] {
		value <<= 4
		switch {
		case encoded >= '0' && encoded <= '9':
			value |= uint16(encoded - '0')
		case encoded >= 'a' && encoded <= 'f':
			value |= uint16(encoded-'a') + 10
		case encoded >= 'A' && encoded <= 'F':
			value |= uint16(encoded-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func inspectNames(raw []byte, targetType reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(decoder, 0, targetType); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanValue(decoder *json.Decoder, depth int, targetType reflect.Type) error {
	if depth > maxDepth {
		return fmt.Errorf("JSON exceeds maximum nesting depth %d", maxDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		fields, strictObject, err := exactStructFields(targetType)
		if err != nil {
			return err
		}
		valueType := mapValueType(targetType)
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("invalid JSON object member")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate JSON object member")
			}
			seen[name] = struct{}{}
			childType := valueType
			if strictObject {
				var exists bool
				childType, exists = fields[name]
				if !exists {
					// Do not echo an attacker-controlled member name into an error
					// that a generated workflow may persist or log.
					return errors.New("unknown JSON object member")
				}
			}
			if err := scanValue(decoder, depth+1, childType); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		elementType := sequenceElementType(targetType)
		for decoder.More() {
			if err := scanValue(decoder, depth+1, elementType); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func dereference(targetType reflect.Type) reflect.Type {
	for targetType != nil && targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	return targetType
}

func exactStructFields(targetType reflect.Type) (map[string]reflect.Type, bool, error) {
	targetType = dereference(targetType)
	if targetType == nil || targetType == rawMessageType || targetType.Kind() != reflect.Struct {
		return nil, false, nil
	}
	if reflect.PointerTo(targetType).Implements(unmarshalerType) || targetType.Implements(unmarshalerType) {
		return nil, false, nil
	}
	fields := make(map[string]reflect.Type)
	if err := collectStructFields(targetType, fields); err != nil {
		return nil, false, err
	}
	return fields, true, nil
}

func collectStructFields(targetType reflect.Type, fields map[string]reflect.Type) error {
	for index := 0; index < targetType.NumField(); index++ {
		field := targetType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag, hasTag := field.Tag.Lookup("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if field.Anonymous && (!hasTag || name == "") {
			embedded := dereference(field.Type)
			if embedded.Kind() == reflect.Struct {
				if err := collectStructFields(embedded, fields); err != nil {
					return err
				}
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		if _, exists := fields[name]; exists {
			return errors.New("ambiguous JSON struct field configuration")
		}
		fields[name] = field.Type
	}
	return nil
}

func mapValueType(targetType reflect.Type) reflect.Type {
	targetType = dereference(targetType)
	if targetType != nil && targetType.Kind() == reflect.Map && targetType.Key().Kind() == reflect.String {
		return targetType.Elem()
	}
	return nil
}

func sequenceElementType(targetType reflect.Type) reflect.Type {
	targetType = dereference(targetType)
	if targetType != nil && (targetType.Kind() == reflect.Array || targetType.Kind() == reflect.Slice) {
		if targetType == rawMessageType {
			return nil
		}
		return targetType.Elem()
	}
	return nil
}
