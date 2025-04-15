package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	dir, err := os.MkdirTemp("", "*")
	require.NoError(t, err)
	os.Setenv("PATH", os.Getenv("PATH")+":"+dir)
	f, err := os.OpenFile(filepath.Join(dir, "nft"), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0755)
	require.NoError(t, err)
	err = f.Chmod(0755)
	require.NoError(t, err)
	f.Close()
	cfg, err := Parse("./testdata/config.yaml")
	require.NoError(t, err)
	require.Len(t, cfg.Jail, 1)
	require.Len(t, cfg.Discipline, 1)
	require.Len(t, cfg.Allow, 1)
	require.Equal(t, "nft", cfg.Jail[0].ID)
	require.Equal(t, "test", cfg.Discipline[0].ID)
	require.True(t, cfg.AllowIP(net.IPv4(1, 1, 1, 1)))
	require.False(t, cfg.AllowIP(net.IPv4(2, 2, 2, 2)))
	require.False(t, cfg.AllowIP(net.IPv4(81, 6, 4, 1)))

	entries, err := os.ReadDir("./examples")
	require.NoError(t, err)
	for _, f := range entries {
		if f.IsDir() {
			continue
		}
		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		name := filepath.Join("./examples", f.Name())
		t.Run(name, func(t *testing.T) {
			cfg, err := Parse(name)
			require.NoError(t, err)
			require.NotNil(t, cfg)
		})
	}
}
