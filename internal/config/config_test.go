/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultIsValid(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if cfg.Scanner.ScanInterval.Duration != 30*time.Minute {
		t.Errorf("default scan interval = %s", cfg.Scanner.ScanInterval.Duration)
	}
}

func TestLoadFillsChannelDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
clusterName: production
scanner:
  scanInterval: 0s
  namespaces: {include: [app], exclude: [kube-system]}
  rules: {missingNetworkPolicy: true}
notifications:
  channels:
  - {name: discord, type: discord, secretRef: cs-discord, events: {newFinding: true}}
  - {name: slack, type: slack, secretRef: cs-slack, secretKey: url, minSeverity: CRITICAL, events: {newFinding: true}}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scanner.ScanInterval.Duration != 0 {
		t.Errorf("scanInterval 0 must disable rescans, got %s", cfg.Scanner.ScanInterval.Duration)
	}
	d, s := cfg.Notifications.Channels[0], cfg.Notifications.Channels[1]
	if d.SecretKey != "webhook-url" || d.MinSeverity != securityv1alpha1.SeverityHigh {
		t.Errorf("discord defaults not applied: %+v", d)
	}
	if s.SecretKey != "url" || s.MinSeverity != securityv1alpha1.SeverityCritical {
		t.Errorf("explicit slack values overwritten: %+v", s)
	}
	if cfg.Scanner.Profile != securityv1alpha1.ProfileRecommended {
		t.Errorf("unset fields must keep defaults, profile = %s", cfg.Scanner.Profile)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	_, err := Load(writeConfig(t, `
scanner:
  mode: enforce
  scanInterval: 10s
  profile: paranoid
  rules: {notARule: true}
  namespaces: {exclude: [Bad_Name]}
notifications:
  channels:
  - {name: a, type: email}
  - {name: a, type: slack, secretRef: x}
`))
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"scanner.mode", "scanInterval", "scanner.profile", "notARule", "Bad_Name",
		".type", ".secretRef", ".name", ".events"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	if _, err := Load(writeConfig(t, "scanner:\n  scanIntervall: 5m\n")); err == nil {
		t.Fatal("a typo in a field name must be an error, not silently ignored")
	}
}

func TestNamespaceSelected(t *testing.T) {
	const app = "app"
	cases := []struct {
		n    Namespaces
		ns   string
		want bool
	}{
		{Namespaces{}, app, true},
		{Namespaces{Exclude: []string{"kube-system"}}, "kube-system", false},
		{Namespaces{Include: []string{app}}, "other", false},
		{Namespaces{Include: []string{app}, Exclude: []string{app}}, app, false},
	}
	for _, c := range cases {
		if got := c.n.NamespaceSelected(c.ns); got != c.want {
			t.Errorf("%+v.NamespaceSelected(%q) = %v, want %v", c.n, c.ns, got, c.want)
		}
	}
}
