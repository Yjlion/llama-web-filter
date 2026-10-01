package addons_test

import "os"

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o644) }
func readFile(p string) ([]byte, error)  { return os.ReadFile(p) }
