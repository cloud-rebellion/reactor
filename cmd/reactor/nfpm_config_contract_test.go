package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// Keep package input selection in the ordinary main/PR test suite. The release
// workflow runs only for tags, so a literal environment expression or an ignored
// architecture must be refused before the next release is cut. Real deb/rpm
// archive and executable verification remains a separate packaging check.
func TestNFPMPackageConfigSelectsTheRequestedBinaryAndArchitecture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate package configuration")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../packaging/nfpm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Architecture string `yaml:"arch"`
		Contents     []struct {
			Source      string `yaml:"src"`
			Destination string `yaml:"dst"`
			Expand      bool   `yaml:"expand"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatalf("parse actual nFPM configuration: %v", err)
	}
	binaryIndex := -1
	for i, content := range config.Contents {
		if content.Destination != "/usr/bin/reactor" {
			continue
		}
		if binaryIndex != -1 {
			t.Fatal("multiple package inputs replace /usr/bin/reactor")
		}
		binaryIndex = i
	}
	if binaryIndex == -1 {
		t.Fatal("package configuration omits its installed binary")
	}
	binary := config.Contents[binaryIndex]
	if !binary.Expand {
		t.Error("binary content must enable nFPM environment expansion")
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			requestedBinary := "dist/reactor-release-linux-" + architecture
			t.Setenv("REACTOR_ARCH", architecture)
			t.Setenv("REACTOR_BINARY", requestedBinary)
			// nFPM v2 expands with os.Expand and os.Getenv. Shell-style :-
			// defaults are not supported; missing names become empty strings.
			if got := os.ExpandEnv(config.Architecture); got != architecture {
				t.Fatalf("package architecture = %q, requested %q", got, architecture)
			}
			if got := os.ExpandEnv(binary.Source); got != requestedBinary {
				t.Fatalf("package binary = %q, requested %q", got, requestedBinary)
			}
		})
	}
}
