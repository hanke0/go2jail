package main

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	f, err := os.OpenFile("/tmp/nft", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0755)
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
}
