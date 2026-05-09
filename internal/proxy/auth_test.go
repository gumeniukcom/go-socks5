package proxy

import (
	"context"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	t.Parallel()
	password := []byte("correct horse battery staple")
	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("unexpected encoding: %q", encoded)
	}
	auth, err := NewArgonAuth(true, map[string]string{"alice": encoded})
	if err != nil {
		t.Fatalf("NewArgonAuth: %v", err)
	}
	ctx := context.Background()
	if !auth.AuthLoginPassword(ctx, "alice", password) {
		t.Fatal("correct password rejected")
	}
	if auth.AuthLoginPassword(ctx, "alice", []byte("wrong")) {
		t.Fatal("wrong password accepted")
	}
	if auth.AuthLoginPassword(ctx, "bob", password) {
		t.Fatal("unknown user accepted")
	}
}

func TestNoAuth(t *testing.T) {
	t.Parallel()
	a := NoAuth{}
	if a.ShouldAuth() {
		t.Fatal("NoAuth.ShouldAuth must be false")
	}
	if !a.AuthLoginPassword(context.Background(), "any", []byte("any")) {
		t.Fatal("NoAuth must accept any credentials")
	}
}

func TestArgonAuthDisabled(t *testing.T) {
	t.Parallel()
	a, err := NewArgonAuth(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.ShouldAuth() {
		t.Fatal("ShouldAuth must be false when disabled")
	}
	if !a.AuthLoginPassword(context.Background(), "x", []byte("y")) {
		t.Fatal("disabled auth must short-circuit to true")
	}
}

func TestPHCParseErrors(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"not-phc",
		"$bcrypt$v=19$m=65536,t=3,p=4$xx$yy",
		"$argon2id$v=99$m=65536,t=3,p=4$xx$yy",
		"$argon2id$v=19$m=garbage$xx$yy",
		"$argon2id$v=19$m=65536,t=3,p=4$!!$yy",
	}
	for _, c := range cases {
		if _, err := parsePHC(c); err == nil {
			t.Errorf("parsePHC(%q) want err", c)
		}
	}
}

func TestArgonAuthRejectsBadHash(t *testing.T) {
	t.Parallel()
	if _, err := NewArgonAuth(true, map[string]string{"alice": "garbage"}); err == nil {
		t.Fatal("expected error for malformed hash")
	}
}
