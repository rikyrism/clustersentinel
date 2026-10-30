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

// Package config loads the operator-wide configuration (rendered from Helm values).
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// Config is the operator-wide configuration. A namespace SecurityPolicy overrides the
// profile and rules for workloads in that namespace; everything else is set only here.
type Config struct {
	// ClusterName is shown in notifications and reports.
	ClusterName   string        `json:"clusterName"`
	Scanner       Scanner       `json:"scanner"`
	Notifications Notifications `json:"notifications"`
}

// Scanner controls what is scanned and how often.
type Scanner struct {
	// Mode is always "audit": findings are recorded, workloads are never changed.
	Mode string `json:"mode"`
	// ScanInterval is the periodic rescan interval, served from the informer cache.
	// Zero disables periodic rescans; event-driven scanning keeps working.
	ScanInterval metav1.Duration `json:"scanInterval"`
	Namespaces   Namespaces      `json:"namespaces"`
	// Profile is the default profile for namespaces without a SecurityPolicy.
	Profile securityv1alpha1.Profile `json:"profile"`
	// Rules turns individual rules on or off by key, on top of Profile.
	Rules map[string]bool `json:"rules,omitempty"`
	// ResolvedRetention is how long Resolved findings are kept before deletion.
	// Zero keeps them until their resource is deleted.
	ResolvedRetention metav1.Duration `json:"resolvedRetention"`
	// MaxConcurrentReconciles bounds parallel reconciles per controller.
	MaxConcurrentReconciles int `json:"maxConcurrentReconciles"`
}

// Namespaces selects scanned namespaces. An empty Include means all namespaces.
type Namespaces struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// ChannelType is a notification backend.
type ChannelType string

const (
	ChannelDiscord ChannelType = "discord"
	ChannelSlack   ChannelType = "slack"
	ChannelWebhook ChannelType = "webhook"
)

// Notifications lists notification channels.
type Notifications struct {
	Channels []Channel `json:"channels,omitempty"`
}

// Channel is one notification destination. The destination URL is read from a Secret
// in the operator's namespace and is never stored in CRDs or logged.
type Channel struct {
	Name string      `json:"name"`
	Type ChannelType `json:"type"`
	// SecretRef names a Secret in the operator's namespace.
	SecretRef string `json:"secretRef"`
	// SecretKey is the key holding the webhook URL. Defaults to "webhook-url".
	SecretKey string `json:"secretKey,omitempty"`
	// MinSeverity drops notifications below this severity. Defaults to HIGH.
	MinSeverity securityv1alpha1.Severity `json:"minSeverity,omitempty"`
	Events      Events                    `json:"events"`
}

// Events selects which finding transitions are announced.
type Events struct {
	NewFinding      bool `json:"newFinding"`
	SeverityChanged bool `json:"severityChanged"`
	FindingResolved bool `json:"findingResolved"`
}

// Default returns the configuration used when no file is given.
func Default() Config {
	return Config{
		ClusterName: "kubernetes",
		Scanner: Scanner{
			Mode:                    "audit",
			ScanInterval:            metav1.Duration{Duration: 30 * time.Minute},
			Namespaces:              Namespaces{Exclude: []string{"kube-system"}},
			Profile:                 securityv1alpha1.ProfileRecommended,
			ResolvedRetention:       metav1.Duration{Duration: 7 * 24 * time.Hour},
			MaxConcurrentReconciles: 2,
		},
	}
}

// Load reads a YAML config file over the defaults and validates it.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, cfg.Validate()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config %s: %w", path, err)
	}
	for i := range cfg.Notifications.Channels {
		ch := &cfg.Notifications.Channels[i]
		if ch.SecretKey == "" {
			ch.SecretKey = "webhook-url"
		}
		if ch.MinSeverity == "" {
			ch.MinSeverity = securityv1alpha1.SeverityHigh
		}
	}
	return cfg, cfg.Validate()
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Validate reports every problem in the configuration at once.
func (c Config) Validate() error {
	var errs []error
	s := c.Scanner
	if s.Mode != "audit" {
		errs = append(errs, fmt.Errorf("scanner.mode: only \"audit\" is supported, got %q", s.Mode))
	}
	if d := s.ScanInterval.Duration; d != 0 && d < time.Minute {
		errs = append(errs, fmt.Errorf("scanner.scanInterval: must be 0 (disabled) or at least 1m, got %s", d))
	}
	if s.ResolvedRetention.Duration < 0 {
		errs = append(errs, errors.New("scanner.resolvedRetention: must not be negative"))
	}
	if s.MaxConcurrentReconciles < 1 || s.MaxConcurrentReconciles > 16 {
		errs = append(errs, fmt.Errorf("scanner.maxConcurrentReconciles: must be between 1 and 16, got %d", s.MaxConcurrentReconciles))
	}
	switch s.Profile {
	case securityv1alpha1.ProfileBasic, securityv1alpha1.ProfileRecommended,
		securityv1alpha1.ProfileStrict, securityv1alpha1.ProfileCustom:
	default:
		errs = append(errs, fmt.Errorf("scanner.profile: unknown profile %q", s.Profile))
	}
	for key := range s.Rules {
		if _, ok := rules.ByKey(key); !ok {
			errs = append(errs, fmt.Errorf("scanner.rules: unknown rule key %q", key))
		}
	}
	for _, ns := range append(append([]string{}, s.Namespaces.Include...), s.Namespaces.Exclude...) {
		if !dnsLabel.MatchString(ns) || len(ns) > 63 {
			errs = append(errs, fmt.Errorf("scanner.namespaces: %q is not a valid namespace name", ns))
		}
	}
	names := map[string]bool{}
	for i, ch := range c.Notifications.Channels {
		p := fmt.Sprintf("notifications.channels[%d]", i)
		if ch.Name == "" || names[ch.Name] {
			errs = append(errs, fmt.Errorf("%s.name: must be set and unique", p))
		}
		names[ch.Name] = true
		switch ch.Type {
		case ChannelDiscord, ChannelSlack, ChannelWebhook:
		default:
			errs = append(errs, fmt.Errorf("%s.type: must be discord, slack or webhook, got %q", p, ch.Type))
		}
		if ch.SecretRef == "" {
			errs = append(errs, fmt.Errorf("%s.secretRef: must name a Secret holding the webhook URL", p))
		}
		if !ch.Events.NewFinding && !ch.Events.SeverityChanged && !ch.Events.FindingResolved {
			errs = append(errs, fmt.Errorf("%s.events: enable at least one event", p))
		}
		if ch.MinSeverity != "" && !ch.MinSeverity.IsValid() {
			errs = append(errs, fmt.Errorf("%s.minSeverity: unknown severity %q", p, ch.MinSeverity))
		}
	}
	return errors.Join(errs...)
}

// NamespaceSelected reports whether ns is in scope. Exclude wins over Include.
func (n Namespaces) NamespaceSelected(ns string) bool {
	if slices.Contains(n.Exclude, ns) {
		return false
	}
	return len(n.Include) == 0 || slices.Contains(n.Include, ns)
}
