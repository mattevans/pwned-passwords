package hibp

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// TestClientCustomHTTPClient will test using a custom HTTP client.
func TestClientCustomHTTPClient(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()
	client.SetHTTPClient(&http.Client{
		Timeout: 3 * time.Second,
	})

	compromised, err := client.Compromised("p@ssword")
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if !compromised {
		t.Fatalf("Expected compromised hash (p@ssword) to be true but got: %v", compromised)
	}
}

// TestCompromisedHash will test a compromised value against the HIBP API.
func TestCompromisedHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()

	compromised, err := client.Compromised("p@ssword")
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if !compromised {
		t.Fatalf("Expected compromised hash (p@ssword) to be true but got: %v", compromised)
	}
}

// TestCompromisedCountHash will test a compromised value against the HIBP API.
func TestCompromisedCountHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()

	compromised, count, err := client.CompromisedCount("p@ssword")
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if !compromised {
		t.Fatalf("Expected compromised hash (p@ssword) to be true but got: %v", compromised)
	}

	if count == 0 {
		t.Fatalf("Expected compromised hash (p@ssword) to have been compromised at least once but got: %v", count)
	}
}

// TestNonCompromisedHash will test a non-compromised value against the HIBP API.
func TestNonCompromisedHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()

	// Check if input is compromised.
	value := fmt.Sprintf("SHOULD_NOT_BE_COMPROMISED_%s", time.Now().Format("2006-01-02 15:04:05"))

	compromised, err := client.Compromised(value)
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if compromised {
		t.Fatalf("Expected non-compromised hash to be false but got: %v", compromised)
	}
}

// TestNonCompromisedCountHash will test a non-compromised value against the HIBP API.
func TestNonCompromisedCountHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()

	// Check if input is compromised.
	value := fmt.Sprintf("SHOULD_NOT_BE_COMPROMISED_%s", time.Now().Format("2006-01-02 15:04:05"))

	compromised, count, err := client.CompromisedCount(value)
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if compromised {
		t.Fatalf("Expected non-compromised hash to be false but got: %v", compromised)
	}

	if count != 0 {
		t.Fatalf("Expected non-compromised hash to have been compromised exactly 0 times but got: %v", count)
	}
}

func TestEmptyCompromisedHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()

	// Check if input is compromised.
	compromised, err := client.Compromised("")
	if err == nil {
		t.Fatal("Expected error when checking empty value, but got: nil")
	}

	if err.Error() != "value for compromised check cannot be empty" {
		t.Fatalf("Expected err to read 'value for compromised check cannot be empty' but got: '%v'", err)
	}

	if compromised {
		t.Fatalf("Expected empty compromised hash to be false but got: %v", compromised)
	}
}

func TestEmptyCompromisedCountHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)

	client := NewClient()

	// Check if input is compromised.
	compromised, count, err := client.CompromisedCount("")
	if err == nil {
		t.Fatal("Expected error when checking empty value, but got: nil")
	}

	if err.Error() != "value for compromised check cannot be empty" {
		t.Fatalf("Expected err to read 'value for compromised check cannot be empty' but got: '%v'", err)
	}

	if compromised {
		t.Fatalf("Expected empty compromised hash to be false but got: %v", compromised)
	}

	if count != 0 {
		t.Fatalf("Expected empty compromised hash to have been compromised exactly 0 times but got: %v", count)
	}
}
