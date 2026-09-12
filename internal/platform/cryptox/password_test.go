package cryptox

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("seven lamps beside the quiet river", TestArgon2idParams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected encoding: %s", hash)
	}
	ok, _, err := VerifyPassword("seven lamps beside the quiet river", hash)
	if err != nil || !ok {
		t.Fatalf("the correct password must verify: %v %v", ok, err)
	}
	ok, _, err = VerifyPassword("seven lamps beside the quiet rivet", hash)
	if err != nil || ok {
		t.Fatal("a wrong password must not verify")
	}
}

func TestSaltIsUniquePerHash(t *testing.T) {
	a, _ := HashPassword("seven lamps beside the quiet river", TestArgon2idParams)
	b, _ := HashPassword("seven lamps beside the quiet river", TestArgon2idParams)
	if a == b {
		t.Fatal("two hashes of the same password must differ: the salt is not unique")
	}
}

func TestRehashIsSignalledWhenParametersStrengthen(t *testing.T) {
	weak, err := HashPassword("seven lamps beside the quiet river", TestArgon2idParams)
	if err != nil {
		t.Fatal(err)
	}
	ok, needsRehash, err := VerifyPassword("seven lamps beside the quiet river", weak)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if !needsRehash {
		t.Fatal("a hash below current parameters must be flagged for upgrade")
	}
	strong, err := HashPassword("seven lamps beside the quiet river", DefaultArgon2idParams)
	if err != nil {
		t.Fatal(err)
	}
	_, needsRehash, _ = VerifyPassword("seven lamps beside the quiet river", strong)
	if needsRehash {
		t.Fatal("a current hash must not be flagged for upgrade")
	}
}

func TestMalformedHashesAreRejected(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash", "$argon2i$v=19$m=1,t=1,p=1$abc$def",
		"$argon2id$v=18$m=1,t=1,p=1$YWJjZGVmZ2hpamts$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=0,t=0,p=0$YWJjZGVmZ2hpamts$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=64,t=1,p=1$!!!$!!!",
	} {
		if _, _, err := VerifyPassword("whatever", bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestLengthBoundsAreEnforced(t *testing.T) {
	if _, err := HashPassword("short", DefaultArgon2idParams); err != ErrPasswordTooShort {
		t.Fatalf("want ErrPasswordTooShort, got %v", err)
	}
	// An unbounded password is free CPU for an attacker.
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordLength+1), DefaultArgon2idParams); err != ErrPasswordTooLong {
		t.Fatalf("want ErrPasswordTooLong, got %v", err)
	}
}

// The server-side parameter choice is load-bearing, so it is asserted rather
// than left to whoever edits the struct next.
func TestServerParametersAreSane(t *testing.T) {
	p := DefaultArgon2idParams
	if p.Memory < 19*1024 {
		t.Fatalf("memory %d KiB is below the OWASP Argon2id minimum of 19 MiB", p.Memory)
	}
	if p.Time < 2 {
		t.Fatalf("time cost %d is below the OWASP minimum of 2", p.Time)
	}
	if p.Parallelism != 1 {
		t.Fatalf("parallelism is %d: a server hash must not try to use every core, "+
			"or one sign-in saturates the machine", p.Parallelism)
	}
	if p.KeyLength < 32 || p.SaltLength < 16 {
		t.Fatalf("salt %d / key %d are too short", p.SaltLength, p.KeyLength)
	}
}

func BenchmarkHashPasswordServerParameters(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := HashPassword("seven lamps beside the quiet river", DefaultArgon2idParams); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashPasswordParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := HashPassword("seven lamps beside the quiet river", DefaultArgon2idParams); err != nil {
				b.Fatal(err)
			}
		}
	})
}
