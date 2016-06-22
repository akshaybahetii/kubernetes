// Copyright 2013-2014 Apcera Inc. All rights reserved.

package claims

import (
	"bytes"
	"fmt"
	"strconv"
)

type ClaimType string

type QuotedString string
type LiteralString string

const (
	TEMPLATE_OPEN      = '['
	TEMPLATE_CLOSE     = ']'
	TEMPLATE_OPEN_STR  = "["
	TEMPLATE_CLOSE_STR = "]"
	QUOTE_OPEN         = '"'
	QUOTE_CLOSE        = '"'
	QUOTE_OPEN_STR     = `"`
	ISS_ENGINE         = "ENGINE"
	QUOTE_CLOSE_STR    = `"`
	TICK               = '\''
	TICK_STR           = "'"
	LIST_OPEN          = '['
	LIST_CLOSE         = ']'
)

// This Claim type is a generic type used in the pengine and in other parts of
// the code.
type Claim struct {
	Issuer string      // descriptor of the entity making the assertion (Principal.Name)
	Type   ClaimType   // type of assertion (e.g. role, userid, action, etc.)
	Value  interface{} // value of the assertion (e.g. admin, 12345, deploy)
}

// Creates and returns a Claim.
func NewClaim(issuer string, key string, value interface{}) *Claim {
	if issuer == "" {
		issuer = "ENGINE"
	}
	return &Claim{
		Issuer: issuer,
		Type:   ClaimType(key),
		Value:  value,
	}
}

// Returns a string representation of the claim, suppressing
// the showing of ENGINE when it is the issuer as is done in
// LHS claims
func (c *Claim) String() string {
	return c.stringRep(false)
}

// Returns a string representation of the claim with explicit
// issuer as is required for a Claim to be present on the
// right-hand-side of a RuleClaim
// see ENGT-4041
func (c *Claim) RHSString() string {
	return c.stringRep(true)
}

func (c *Claim) stringRep(showEngineIssuer bool) string {
	if c == nil {
		return "<nil>"
	}

	buf := &bytes.Buffer{}

	if len(c.Issuer) > 0 &&
		(showEngineIssuer || c.Issuer != "ENGINE") {
		buf.WriteString(c.Issuer)
		buf.Write([]byte{'-', '>'})
	}

	buf.WriteString(string(c.Type))

	if c.Value != nil {
		buf.WriteByte(' ')
		buf.Write(appendValueBytes(nil, c.Value))
	}

	return buf.String()
}

func appendValueBytes(buf []byte, value interface{}) []byte {
	return appendValueBytesExt(buf, value, false, false)
}

// The values are not expected to be anything other than max size (64) int,
// uint, and float values but just in case the smaller types are
// handled. The intent is to reduce errors as much as possible. If
// showEngineIssuer is true then claims with the default issuer (ENGINE)
// are shown with ENGINE-> preceeding the claimType. If quoteAllStrings is
// true then the ambiguity between engine claims and plain strings is
// completely eliminated by quoting all strings
func appendValueBytesExt(buf []byte, value interface{}, showEngineIssuer, quoteAllStrings bool) []byte {
	switch typedValue := value.(type) {
	case bool:
		buf = append(buf, []byte(strconv.FormatBool(typedValue))...)
	case QuotedString:
		buf = append(buf, QUOTE_OPEN)
		buf = append(buf, []byte(string(typedValue))...)
		buf = append(buf, QUOTE_CLOSE)
	case LiteralString:
		buf = append(buf, TICK)
		buf = append(buf, []byte(string(typedValue))...)
		buf = append(buf, TICK)
	case string:
		//if quoteAllStrings || needsQuotes(typedValue) {
		//	buf = append(buf, QUOTE_OPEN)
		//	buf = append(buf, []byte(typedValue)...)
		//	buf = append(buf, QUOTE_CLOSE)
		//} else {
		buf = append(buf, []byte(typedValue)...)
		//}
	/*case *ByteSizeValue:
		s := typedValue.Num.Format("%f", typedValue.Unit, false)
		buf = append(buf, []byte(s)...)
	case *BitRateValue:
		s := typedValue.Num.Format("%f", typedValue.Unit, false)
		buf = append(buf, []byte(s)...)*/
	case int8:
		buf = append(buf, []byte(strconv.FormatInt(int64(typedValue), 10))...)
	case int16:
		buf = append(buf, []byte(strconv.FormatInt(int64(typedValue), 10))...)
	case int32:
		buf = append(buf, []byte(strconv.FormatInt(int64(typedValue), 10))...)
	case int64:
		buf = append(buf, []byte(strconv.FormatInt(typedValue, 10))...)

	case uint8:
		buf = append(buf, []byte(strconv.FormatUint(uint64(typedValue), 10))...)
	case uint16:
		buf = append(buf, []byte(strconv.FormatUint(uint64(typedValue), 10))...)
	case uint32:
		buf = append(buf, []byte(strconv.FormatUint(uint64(typedValue), 10))...)
	case uint64:
		buf = append(buf, []byte(strconv.FormatUint(typedValue, 10))...)

	case float32:
		buf = append(buf, []byte(strconv.FormatFloat(float64(typedValue), 'f', -1, 32))...)
	case float64:
		buf = append(buf, []byte(strconv.FormatFloat(typedValue, 'f', -1, 64))...)

	/*case TempVal:
	buf = append(buf, TEMPLATE_OPEN)
	buf = append(buf, []byte(string(typedValue))...)
	buf = append(buf, TEMPLATE_CLOSE)*/
	case ClaimType:
		buf = append(buf, []byte(string(typedValue))...)
	/*case *ExpandedString:
		buf = append(buf, QUOTE_OPEN)
		for _, part := range typedValue.Parts {
			switch p := part.(type) {
			case string:
				buf = append(buf, []byte(p)...)
			case TempVal:
				buf = append(buf, TEMPLATE_OPEN)
				buf = append(buf, []byte(p)...)
				buf = append(buf, TEMPLATE_CLOSE)
			default:
				buf = append(buf, []byte(fmt.Sprintf("%v", p))...)
			}
		}
		buf = append(buf, QUOTE_CLOSE)
	case []interface{}:
		for i, vc := range typedValue {
			if i > 0 {
				buf = append(buf, ',', ' ')
			}
			buf = appendValueBytesExt(buf, vc, showEngineIssuer, quoteAllStrings)
		}*/
	case *Claim:
		if showEngineIssuer && typedValue.Issuer == ISS_ENGINE {
			buf = append(buf, []byte(ISS_ENGINE+"->")...)
		}
		buf = append(buf, []byte(typedValue.String())...)
		/*	case *RuleClaim:
			if showEngineIssuer && typedValue.Issuer == ISS_ENGINE {
				buf = append(buf, []byte(ISS_ENGINE+"->")...)
			}
			buf = append(buf, []byte(typedValue.String())...)*/
	/*case ExpandedRefValue:
		buf = append(buf, []byte(typedValue.String())...)
	case fmt.Stringer:
		if quoteAllStrings {
			buf = append(buf, QUOTE_OPEN)
			buf = append(buf, []byte(typedValue.String())...)
			buf = append(buf, QUOTE_CLOSE)
		} else {
			buf = append(buf, []byte(typedValue.String())...)
		}
	*/
	default:
		buf = append(buf, []byte(fmt.Sprintf("%#v", value))...)
	}
	return buf
}
