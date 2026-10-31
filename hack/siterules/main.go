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

// Command siterules writes the rule catalog as JSON for the website, so the rules shown
// there always match the code. Run it with "make site-data".
package main

import (
	"encoding/json"
	"os"

	"github.com/rikyrism/clustersentinel/internal/rules"
)

type rule struct {
	ID             string   `json:"id"`
	Key            string   `json:"key"`
	Name           string   `json:"name"`
	Scope          string   `json:"scope"`
	Severity       string   `json:"severity"`
	Profiles       []string `json:"profiles"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

func main() {
	out := make([]rule, 0, len(rules.Catalog))
	for _, m := range rules.Catalog {
		g := rules.GuidanceFor(m.ID)
		profiles := make([]string, 0, len(m.Profiles))
		for _, p := range m.Profiles {
			profiles = append(profiles, string(p))
		}
		out = append(out, rule{
			ID: m.ID, Key: m.Key, Name: m.Name, Scope: string(m.Scope), Severity: string(m.DefaultSeverity),
			Profiles: profiles, Description: g.Description, Recommendation: g.Recommendation,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		os.Exit(1)
	}
}
