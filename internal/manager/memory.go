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

import (
	"os"
	"runtime/debug"
	"strconv"
)

// MemoryLimitEnv carries the container memory limit in bytes (downward API).
const MemoryLimitEnv = "MEMORY_LIMIT_BYTES"

// SetMemoryLimit sets the Go soft memory limit to 90% of the container limit, so the
// garbage collector works harder before the kernel OOM-kills the container. An explicit
// GOMEMLIMIT always wins. It returns the limit set, or 0 if none was set.
func SetMemoryLimit() int64 {
	if os.Getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit := softMemoryLimit(os.Getenv(MemoryLimitEnv))
	if limit > 0 {
		debug.SetMemoryLimit(limit)
	}
	return limit
}

func softMemoryLimit(raw string) int64 {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n / 10 * 9
}
