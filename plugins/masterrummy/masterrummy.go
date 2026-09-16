// Package masterrummy decodes the a572 APK's /i.php protocol.
package masterrummy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

const PackageName = "com.x69l.r916z.a572"

// ASCII bytes, NOT hex-decoded. Verified against the a572 offline analyzer.
const aesKey = "5059b898a9420817732621e597de65a7"
const aesIV = "1102736404060702"

type Decoded struct {
	Action, UID                         string
	RequestPlaintext, ResponsePlaintext string
	RequestJSON, ResponseJSON           []byte
}

// Decode accepts entity bodies (HTTP chunking/compression already removed).
// Both sides must decrypt and parse; the request channel identifies a572.
func Decode(target string, requestBody, responseBody []byte) (*Decoded, error) {
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Path != "/i.php" {
		return nil, errors.New("not a masterrummy endpoint")
	}
	encrypted := u.RawQuery
	if encrypted == "" {
		encrypted = strings.TrimSpace(string(requestBody))
	}
	// PathUnescape preserves literal Base64 '+', unlike QueryUnescape.
	encrypted, err = url.PathUnescape(encrypted)
	if err != nil {
		return nil, errors.New("invalid request encoding")
	}
	request, err := decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	fields, err := url.ParseQuery(string(request))
	if err != nil || fields.Get("action") == "" || len(fields["action"]) != 1 || len(fields["param"]) != 1 {
		return nil, errors.New("invalid decrypted request")
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fields.Get("param")), &params); err != nil || params == nil || scalar(params["channel_id"]) != "2000572" {
		return nil, errors.New("request is not from a572")
	}
	requestJSON := make(map[string]json.RawMessage, len(fields))
	for key, values := range fields {
		if len(values) != 1 {
			return nil, errors.New("duplicate request field")
		}
		requestJSON[key], _ = json.Marshal(values[0])
	}
	requestJSON["param"] = json.RawMessage(fields.Get("param"))
	responseBody = bytes.TrimSpace(responseBody)
	if !bytes.HasPrefix(responseBody, []byte("aes#")) {
		return nil, errors.New("response is not encrypted")
	}
	response, err := decrypt(string(responseBody[4:]))
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(response, &obj); err != nil || obj == nil {
		return nil, errors.New("decrypted response is not a JSON object")
	}
	action := fields.Get("action")
	if raw, ok := obj["action"]; ok && scalar(raw) != action {
		return nil, errors.New("response action does not match request")
	}
	uid := scalar(obj["uid"])
	if uid == "" {
		var data map[string]json.RawMessage
		if json.Unmarshal(obj["data"], &data) == nil {
			uid = scalar(data["uid"])
		}
	}
	parsedRequest, _ := json.Marshal(requestJSON)
	var parsedResponse bytes.Buffer
	_ = json.Compact(&parsedResponse, response)
	return &Decoded{Action: action, UID: uid, RequestPlaintext: string(request),
		ResponsePlaintext: string(response), RequestJSON: parsedRequest, ResponseJSON: parsedResponse.Bytes()}, nil
}

func scalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func decrypt(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid AES ciphertext")
	}
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return nil, err
	}
	cipher.NewCBCDecrypter(block, []byte(aesIV)).CryptBlocks(data, data)
	n := int(data[len(data)-1])
	if n < 1 || n > aes.BlockSize || !bytes.Equal(data[len(data)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, errors.New("invalid AES padding")
	}
	data = data[:len(data)-n]
	if !utf8.Valid(data) {
		return nil, errors.New("invalid decrypted UTF-8")
	}
	return data, nil
}
