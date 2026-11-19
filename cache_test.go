package libauth_test

import (
	"testing"

	"github.com/cupen/libauth"
	"github.com/cupen/libauth/authz"
)

func TestCacheSizeAliases(t *testing.T) {
	if libauth.DefaultCacheSize != 10_000 ||
		libauth.DefaultCacheCapacity != libauth.DefaultCacheSize ||
		authz.DefaultCacheCapacity != libauth.DefaultCacheSize {
		t.Fatalf("cache size aliases disagree: root=%d legacy=%d authz=%d",
			libauth.DefaultCacheSize, libauth.DefaultCacheCapacity, authz.DefaultCacheCapacity)
	}

	for _, tc := range []struct {
		name string
		opt  libauth.Option
	}{
		{"new", libauth.WithCacheSize(1)},
		{"legacy", libauth.WithCacheCapacity(1)},
		{"authz", authz.WithCacheCapacity(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := libauth.New(tc.opt)
			if err := e.CreateRole("viewer", []libauth.Permission{
				{Resource: "article", Action: libauth.ActionRead},
			}, ""); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"alice", "bob"} {
				if err := e.CreateUser(id, "viewer"); err != nil {
					t.Fatal(err)
				}
				if err := e.Check(id, libauth.Permission{
					Resource: "article", Action: libauth.ActionRead,
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
