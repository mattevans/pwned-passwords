package hibp

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// TestCompromisedHash will test a compromised value against the HIBP API.
func TestCompromisedHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)
	client := NewClient()

	// Check if input is compromised.
	compromised, err := client.Pwned.Compromised("p@ssword")
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if !compromised {
		t.Fatalf("Expected compromised hash (p@ssword) to be true but got: %v", compromised)
	}
}

// TestNonCompromisedHash will test a non-compromised value against the HIBP API.
func TestNonCompromisedHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)
	client := NewClient()

	// Check if input is compromised.
	value := fmt.Sprintf("SHOULD_NOT_BE_COMPROMISED_%s", time.Now().Format("2006-01-02 15:04:05"))
	compromised, err := client.Pwned.Compromised(value)
	if err != nil {
		t.Fatalf("Unexpected error running client.Pwned.Compromised(): %s", err)
	}

	if compromised {
		t.Fatalf("Expected non-compromised hash to be false but got: %v", compromised)
	}
}

func TestEmptyCompromisedHash(t *testing.T) {
	// Register the test.
	RegisterTestingT(t)
	client := NewClient()

	// Check if input is compromised.
	compromised, err := client.Pwned.Compromised("")
	if err == nil {
		t.Fatal("Expected error when checking empty value, but got: nil")
	}

	if err.Error() != "Value for compromised check cannot be empty" {
		t.Fatalf("Expected err to read 'Value for compromised check cannot be empty' but got: '%v'", err)
	}

	if compromised {
		t.Fatalf("Expected empty compromised hash to be false but got: %v", compromised)
	}
}
