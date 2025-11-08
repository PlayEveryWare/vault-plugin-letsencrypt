package backend

import "os"

// WithEnvOverrides temporarily sets environment variables
// from the provided map and returns a cleanup function that
// restores the original values.
//
// If an environment variable didn't exist before, it will be
// unset after cleanup. The returned function should be called
// with defer to ensure cleanup happens.
func WithEnvOverrides(env map[string]string) func() {
	original := make(map[string]string)
	unset := make(map[string]bool)

	for k := range env {
		if val, exists := os.LookupEnv(k); exists {
			original[k] = val
		} else {
			unset[k] = true
		}
	}

	for k, v := range env {
		os.Setenv(k, v)
	}

	// cleanup function to restore state
	return func() {
		for k := range env {
			if unset[k] {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, original[k])
			}
		}
	}
}
