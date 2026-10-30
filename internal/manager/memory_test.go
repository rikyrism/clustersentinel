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

package manager

import "testing"

func TestSoftMemoryLimit(t *testing.T) {
	cases := map[string]int64{
		"134217728": 120795948, // 128Mi -> 90%
		"":          0,
		"0":         0,
		"-5":        0,
		"128Mi":     0, // the downward API with divisor 1 always yields plain bytes
	}
	for in, want := range cases {
		if got := softMemoryLimit(in); got != want {
			t.Errorf("softMemoryLimit(%q) = %d, want %d", in, got, want)
		}
	}
}
