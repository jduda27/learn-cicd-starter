package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetApiKeyNoAuthErr(t *testing.T) {
	mockHeader := http.Header{}
	expErr := errors.New("no authorization header included")

	_, err := GetAPIKey(mockHeader)

	if !reflect.DeepEqual(expErr, err) {
		t.Fatalf("expected: %v, got: %v", expErr, err)
	}

}

func TestGetApiKeyBadFormatErr(t *testing.T) {
	mockHeader := http.Header{}
	badKey := "API notgood"
	expErr := errors.New("malformed authorization header")
	mockHeader.Add("Authorization", badKey)

	_, err := GetAPIKey(mockHeader)

	if !reflect.DeepEqual(expErr, err) {
		t.Fatalf("expected: %v, got: %v", expErr, err)
	}
}

func TestGetApiKeyTooShortErr(t *testing.T) {
	mockHeader := http.Header{}
	badKey := "API"
	expErr := errors.New("malformed authorization header")
	mockHeader.Add("Authorization", badKey)

	_, err := GetAPIKey(mockHeader)

	if !reflect.DeepEqual(expErr, err) {
		t.Fatalf("expected: %v, got: %v", expErr, err)
	}
}

func TestGetApitKey(t *testing.T) {
	mockHeader := http.Header{}
	expKey := "ABC1234567"
	mockHeader.Add("Authorization", "ApiKey "+expKey)

	myKey, err := GetAPIKey(mockHeader)

	if !reflect.DeepEqual(expKey, myKey) {
		t.Fatalf("expected: %v, got: %v", expKey, myKey)
	}

	if err != nil {
		t.Fatalf("Unexpected error in Test with message: %v", err)
	}

}
