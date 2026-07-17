package legal

import "testing"

func TestServiceReturnsAndValidatesCurrentDocuments(t *testing.T) {
	service, err := NewService("terms-2026-07", "privacy-2026-07")
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	current := service.Current()
	if current.TermsVersion != "terms-2026-07" || current.PrivacyVersion != "privacy-2026-07" {
		t.Fatalf("Current() = %+v", current)
	}
	if err := service.Validate("terms-2026-07", "privacy-2026-07"); err != nil {
		t.Fatalf("Validate(current) error = %v", err)
	}
	if err := service.Validate("terms-old", "privacy-2026-07"); err == nil {
		t.Fatal("Validate() accepted stale terms")
	}
	if err := service.Validate("terms-2026-07", "privacy-old"); err == nil {
		t.Fatal("Validate() accepted stale privacy policy")
	}
}

func TestServiceRejectsEmptyOrUnsafeVersionIdentifiers(t *testing.T) {
	for _, versions := range [][2]string{
		{"", "privacy-v1"},
		{"terms-v1", ""},
		{"terms\nv1", "privacy-v1"},
		{"terms-v1", "privacy v1"},
	} {
		if _, err := NewService(versions[0], versions[1]); err == nil {
			t.Fatalf("NewService(%q, %q) succeeded", versions[0], versions[1])
		}
	}
}
