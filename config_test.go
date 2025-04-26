package main

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testSetStrictConfig(t *testing.T) {
	old := YAMLStrict
	t.Cleanup(func() {
		YAMLStrict = old
	})
	YAMLStrict = true
}

func TestParse(t *testing.T) {
	testSetStrictConfig(t)
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
	require.Len(t, cfg.Jails, 1)
	require.Len(t, cfg.Disciplines, 2)
	require.Len(t, cfg.Allows, 1)
	require.Len(t, cfg.Watches, 1)
	require.Equal(t, "nft", cfg.Jails[0].ID)
	require.Equal(t, "discipline", cfg.Disciplines[0].ID)
	require.Equal(t, Strings{"nft"}, cfg.Disciplines[1].Jails)
	require.Equal(t, Strings{"log"}, cfg.Disciplines[1].Watches)
	require.True(t, cfg.Allows.Contains(net.IPv4(1, 1, 1, 1)))
	require.False(t, cfg.Allows.Contains(net.IPv4(2, 2, 2, 2)))
	require.False(t, cfg.Allows.Contains(net.IPv4(81, 6, 4, 1)))

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
			if strings.Contains(name, "full.yaml") {
				for name := range jailProviders {
					require.True(t,
						slices.ContainsFunc(cfg.Jails, func(j *Jail) bool {
							return j.Type == name
						}),
						"jail type not found in full.yaml: %s", name,
					)
				}
				for name := range watchProviders {
					require.True(t,
						slices.ContainsFunc(cfg.Watches, func(j *Watch) bool {
							return j.Type == name
						}),
						"watch type not found in full.yaml: %s", name,
					)
				}
				for name := range disciplineProviders {
					require.True(t,
						slices.ContainsFunc(cfg.Disciplines, func(j *Discipline) bool {
							return j.Type == name
						}),
						"discipline type not found in full.yaml: %s", name,
					)
				}
				require.Greater(t, len(cfg.Allows), 0)
				require.Greater(t, len(cfg.IPLocationSources), 0)
			}
		})
	}
}
