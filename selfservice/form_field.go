package selfservice

import (
	"encoding/json"

	"github.com/ory/x/jsonx"
)

type FormErrorCode string

type FormField struct {
	Name     string      `json:"name"`
	Type     string      `json:"type,omitempty"`
	Required bool        `json:"required,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Error    *FormError  `json:"error,omitempty"`
}

type FormError struct {
	Code    FormErrorCode `json:"id,omitempty"`
	Message string        `json:"message"`
	Field   string        `json:"field,omitempty"`
}

type FormFields map[string]FormField

func NewFormFieldsFromJSON(raw json.RawMessage, prefix string) FormFields {
	fields := FormFields{}
	for name, value := range jsonx.Flatten(raw) {
		var t = "text"
		switch value.(type) {
		case float64, int64, int32, float32, json.Number:
			t = "number"
		case bool:
			t = "checkbox"
		}

		if prefix != "" {
			name = prefix + "." + name
		}

		fields[name] = FormField{
			Name:  name,
			Type:  t,
			Value: value,
		}
	}

	return fields
}

func (fs FormFields) Reset() {
	for k, f := range fs {
		f.Error = nil
		f.Value = nil
		fs[k] = f
	}
}

func (fs FormFields) SetValue(name string, value interface{}) {
	var field FormField
	if ff, ok := fs[name]; ok {
		field = ff
	}

	field.Name = name
	field.Value = value
	fs[name] = field
}

func (fs FormFields) SetError(name string, err *FormError) {
	var field FormField
	if ff, ok := fs[name]; ok {
		field = ff
	}

	field.Name = name
	field.Error = err
	fs[name] = field
}
