//go:build e2e

package main

import "testing"

func TestParseQualitySeedArgumentsAcceptsBoundedCanonicalProvenance(t *testing.T) {
	arguments, err := parseQualitySeedArguments([]string{
		"--definition-id", "019f0000-0000-7000-8000-000000000101",
		"--version-id", "019f0000-0000-7000-8000-000000000102",
		"--release-id", "019f0000-0000-7000-8000-000000000103",
		"--release-revision-id", "019f0000-0000-7000-8000-000000000104",
		"--from-subject", "1", "--to-subject", "9",
	})
	if err != nil {
		t.Fatalf("parse quality seed arguments: %v", err)
	}
	if arguments.FromSubject != 1 || arguments.ToSubject != 9 || arguments.DefinitionID.String() != "019f0000-0000-7000-8000-000000000101" {
		t.Fatalf("quality seed arguments = %+v", arguments)
	}
}

func TestParseQualitySeedArgumentsRejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	base := []string{
		"--definition-id", "019f0000-0000-7000-8000-000000000101",
		"--version-id", "019f0000-0000-7000-8000-000000000102",
		"--release-id", "019f0000-0000-7000-8000-000000000103",
		"--release-revision-id", "019f0000-0000-7000-8000-000000000104",
		"--from-subject", "1", "--to-subject", "9",
	}
	tests := map[string][]string{
		"missing provenance": base[2:],
		"non canonical UUID": append(append([]string{}, base[:1]...), append([]string{"019F0000-0000-7000-8000-000000000101"}, base[2:]...)...),
		"zero subject":       append(append([]string{}, base[:9]...), append([]string{"0"}, base[10:]...)...),
		"descending range":   append(append([]string{}, base[:9]...), append([]string{"10", "--to-subject", "9"}, base[12:]...)...),
		"excess range":       append(append([]string{}, base[:11]...), "101"),
		"unknown flag":       append(append([]string{}, base...), "--raw-user-id", "forbidden"),
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseQualitySeedArguments(values); err == nil {
				t.Fatal("unsafe quality seed arguments were accepted")
			}
		})
	}
}
