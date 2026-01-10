package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestMissingAuthorizationHeader(t *testing.T) {
	// Missing key
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected: NoAuthHeaderIncluded error")
	}

	// Missing value
	headers.Add("Autorization", "")
	_, err = GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected: NoAuthHeaderIncluded error")
	}
}

func TestMalformedAuthorizationHeader(t *testing.T) {
	// Bad scheme
	headers := http.Header{}
	headers.Add("Autorization", "Basic xxxxxxxxxxxxxx")
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected: malformed error")
	}

	// Missing part
	headers.Set("Autorization", "ApiKey")
	_, err = GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected: malformed error")
	}
}

func TestGoodAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey 123456789")
	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("falied: %v", err)
	}

	want := "0123456789"
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("expected: %v, got: %v", want, got)
	}
}
