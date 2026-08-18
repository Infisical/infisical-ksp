package infisical

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func capturedCommand(args ...string) string {
	return truncateCommand(joinCommandArgs(redactCommandArgs(args)))
}

func TestRedactCommandSecrets(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "signtool slash p",
			in:   []string{"signtool", "sign", "/fd", "SHA256", "/p", "s3cret", "/f", "cert.pfx", "app.exe"},
			want: "signtool sign /fd SHA256 /p *** /f cert.pfx app.exe",
		},
		{
			name: "jarsigner store and key passwords",
			in:   []string{"jarsigner", "-storepass", "hunter2", "-keypass", "hunter3", "app.jar", "alias"},
			want: "jarsigner -storepass *** -keypass *** app.jar alias",
		},
		{
			name: "equals form",
			in:   []string{"tool", "--password=topsecret", "--other=keep"},
			want: "tool --password=*** --other=keep",
		},
		{
			name: "case insensitive flag",
			in:   []string{"signtool", "sign", "/P", "s3cret", "app.exe"},
			want: "signtool sign /P *** app.exe",
		},
		{
			name: "nothing to redact is unchanged",
			in:   []string{"signtool", "sign", "/fd", "SHA256", "/f", "cert.cer", "/csp", "Infisical Key Storage Provider", "app.exe"},
			want: `signtool sign /fd SHA256 /f cert.cer /csp "Infisical Key Storage Provider" app.exe`,
		},
		{
			name: "flag with no value is left alone",
			in:   []string{"signtool", "sign", "/p"},
			want: "signtool sign /p",
		},
		{
			name: "redaction is idempotent",
			in:   []string{"signtool", "sign", "/p", "***", "app.exe"},
			want: "signtool sign /p *** app.exe",
		},

		// Regression cases: Windows callers quote routinely, so each of these is a realistic way a
		// credential reaches signtool.
		{
			name: "a quoted password containing a space is redacted whole",
			in:   []string{"signtool", "sign", "/p", "my secret", "app.exe"},
			want: "signtool sign /p *** app.exe",
		},
		{
			name: "an argument separated by extra whitespace is still the value",
			in:   []string{"signtool", "sign", "/p", "s3cret", "app.exe"},
			want: "signtool sign /p *** app.exe",
		},
		{
			name: "msbuild property form",
			in:   []string{"msbuild", "/p:Password=s3cret", "app.sln"},
			want: "msbuild /p:Password=*** app.sln",
		},
		{
			name: "msbuild property named with a password suffix",
			in:   []string{"msbuild", "/p:CertPassword=s3cret", "/p:Configuration=Release"},
			want: "msbuild /p:CertPassword=*** /p:Configuration=Release",
		},
		{
			name: "an empty credential still reports as redacted",
			in:   []string{"signtool", "sign", "/p", "", "app.exe"},
			want: "signtool sign /p *** app.exe",
		},
		{
			// A credential that happens to look like a flag must still be hidden.
			name: "a value that looks like a flag is still redacted",
			in:   []string{"signtool", "sign", "/p", "--notaflag", "app.exe"},
			want: "signtool sign /p *** app.exe",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := capturedCommand(c.in...); got != c.want {
				t.Fatalf("captured command\n got: %q\nwant: %q", got, c.want)
			}
		})
	}
}

// Whatever shape a credential arrives in, it must never survive into the value that is sent and
// stored. This asserts on absence rather than on an expected string, so it still fails if the
// redaction rules change shape.
func TestNoCredentialSurvivesCapture(t *testing.T) {
	const secret = "s3cret"
	argvs := [][]string{
		{"signtool", "sign", "/p", secret},
		{"signtool", "sign", "/p", secret + " with spaces"},
		{"jarsigner", "-storepass", secret},
		{"tool", "--password=" + secret},
		{"msbuild", "/p:Password=" + secret},
		{"msbuild", "/property:SignPassphrase=" + secret},
		{"tool", "-PassIn", secret},
	}

	for _, argv := range argvs {
		if got := capturedCommand(argv...); strings.Contains(got, secret) {
			t.Fatalf("a credential survived capture of %q: %q", argv, got)
		}
	}
}

func TestRedactionRunsBeforeTruncation(t *testing.T) {
	padded := []string{"signtool", "sign", "/p", "s3cret", strings.Repeat("a", maxCommandLen)}
	got := capturedCommand(padded...)

	if strings.Contains(got, "s3cret") {
		t.Fatal("the password survived into the captured command line")
	}
	if !strings.Contains(got, "/p "+redactedValue) {
		t.Fatalf("expected a redacted password, got %q", got[:40])
	}
}

// An argument the OS reports as one element must come back as one token on the server, so a
// value containing whitespace has to be re-quoted rather than joined bare.
func TestJoinCommandArgsQuotesWhitespace(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{in: []string{"a", "b"}, want: "a b"},
		{in: []string{"a", "b c"}, want: `a "b c"`},
		{in: []string{"a", "b\tc"}, want: "a \"b\tc\""},
		{in: []string{"a", "", "b"}, want: `a "" b`},
	}

	for _, c := range cases {
		if got := joinCommandArgs(c.in); got != c.want {
			t.Fatalf("joinCommandArgs(%q)\n got: %q\nwant: %q", c.in, got, c.want)
		}
	}
}

func TestTruncateCommand(t *testing.T) {
	short := "signtool sign app.exe"
	if got := truncateCommand(short); got != short {
		t.Fatalf("a short command must pass through unchanged, got %q", got)
	}

	long := strings.Repeat("x", maxCommandLen+50)
	if got := truncateCommand(long); len(got) != maxCommandLen {
		t.Fatalf("expected %d bytes, got %d", maxCommandLen, len(got))
	}

	// A multi-byte rune straddling the cut must not be split in half.
	straddling := strings.Repeat("x", maxCommandLen-1) + "é" + "tail"
	got := truncateCommand(straddling)
	if !utf8.ValidString(got) {
		t.Fatal("truncation produced invalid UTF-8")
	}
	if len(got) != maxCommandLen-1 {
		t.Fatalf("expected the cut to fall back to %d bytes, got %d", maxCommandLen-1, len(got))
	}
}

// wireKeys marshals a payload and returns the JSON object it actually sends. The struct field
// names are the compiler's job; these are the wire names, which only the tags control.
func wireKeys(t *testing.T, payload any) map[string]string {
	t.Helper()

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshalling the payload failed: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the payload did not marshal to a flat object: %v (%s)", err, raw)
	}
	return out
}

func TestClientMetadataKeysMatchScopeKeys(t *testing.T) {
	ctx := SigningContext{
		Command:         "signtool sign app.exe",
		Application:     "signtool.exe",
		ApplicationHash: "abc",
		Hostname:        "build-01",
		OSUsername:      `CORP\svc`,
	}

	md := wireKeys(t, ctx.ClientMetadata())
	scope := wireKeys(t, ctx.RequestScope("digest", nil, ""))

	// 'tool' is the sign endpoint's long-standing name for the signing application. The server
	// maps it onto the signingApplication scope parameter in buildObservedSigningContext
	// (backend/src/services/approval-policy/code-signing/code-signing-policy-fns.ts). Every other
	// key matches by name, so a rename on one side has to be mirrored on the other.
	if md["tool"] != scope["signingApplication"] {
		t.Fatalf("clientMetadata tool %q must carry the scope's signingApplication %q", md["tool"], scope["signingApplication"])
	}
	for _, key := range []string{"command", "signingApplicationHash", "hostname", "osUsername"} {
		if md[key] != scope[key] {
			t.Fatalf("key %q differs: metadata %q, scope %q", key, md[key], scope[key])
		}
	}
}

// The scope parameter names are a server contract, so they are pinned here: a renamed tag would
// otherwise leave the parameter unconstrained and silently widen every approval.
func TestScopeWireNames(t *testing.T) {
	full := SigningContext{
		Command:         "signtool sign app.exe",
		Application:     "signtool.exe",
		ApplicationHash: "abc",
		Hostname:        "build-01",
		OSUsername:      `CORP\svc`,
	}.RequestScope("digest", nil, "")

	got := wireKeys(t, full)
	want := []string{"command", "signingApplication", "signingApplicationHash", "hostname", "osUsername", "dataHash"}

	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("scope parameter %q is missing from the wire payload %v", key, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("expected exactly %d scope parameters, got %v", len(want), got)
	}
}

func TestRequestScopeOmitsEmptyFieldsAndNeverDeclaresIP(t *testing.T) {
	scope := wireKeys(t, SigningContext{Hostname: "build-01"}.RequestScope("digest", nil, ""))

	if _, ok := scope["command"]; ok {
		t.Fatal("an empty field must be omitted rather than sent blank")
	}
	if _, ok := scope["ipAddress"]; ok {
		t.Fatal("the KSP must never declare an IP address")
	}
	if scope["hostname"] != "build-01" || scope["dataHash"] != "digest" {
		t.Fatalf("expected the hostname and digest to be declared, got %v", scope)
	}
}

// The digest is what makes the scope meaningful, so an all-empty context must not produce a
// request that would grant broadly scoped signing.
func TestRequestScopeAlwaysCarriesTheDigest(t *testing.T) {
	scope := wireKeys(t, SigningContext{}.RequestScope("digest", nil, ""))
	if scope["dataHash"] != "digest" {
		t.Fatalf("expected the digest to be declared even with no other context, got %v", scope)
	}
}

func TestJustificationHandlesAnUnknownHostname(t *testing.T) {
	if got := approvalJustification(""); strings.HasSuffix(got, " on ") || strings.HasSuffix(got, " ") {
		t.Fatalf("expected no dangling machine name, got %q", got)
	}
	if got := approvalJustification("build-01"); !strings.Contains(got, "build-01") {
		t.Fatalf("expected the hostname in the justification, got %q", got)
	}
}

func TestRequestScopeOmitsExcludedFields(t *testing.T) {
	ctx := SigningContext{
		Command:         "signtool sign app.exe",
		Application:     "signtool",
		ApplicationHash: "abc",
		Hostname:        "build-01",
		OSUsername:      "svc",
	}

	scope := ctx.RequestScope("digest", []string{scopeFieldDataHash}, "")
	if scope.DataHash != "" {
		t.Fatalf("expected data_hash to be excluded, got %q", scope.DataHash)
	}
	if scope.Command != ctx.Command || scope.Hostname != ctx.Hostname || scope.OSUsername != ctx.OSUsername {
		t.Fatalf("excluding one parameter must not drop the others: %+v", scope)
	}
	if _, present := wireBody(t, scope)["dataHash"]; present {
		t.Fatal("an excluded parameter must not appear in the request body")
	}

	if kept := ctx.RequestScope("digest", nil, ""); kept.DataHash != "digest" {
		t.Fatalf("no exclusions must keep every parameter, got %+v", kept)
	}
}

func TestRequestScopeAddressIsAbsentPinnedOrSkipped(t *testing.T) {
	ctx := SigningContext{Command: "signtool sign app.exe", Hostname: "build-01"}

	if _, present := wireBody(t, ctx.RequestScope("digest", nil, ""))["ipAddress"]; present {
		t.Fatal("an address this provider did not pin must be left for Infisical to fill in")
	}

	pinned := wireBody(t, ctx.RequestScope("digest", nil, "203.0.113.10"))["ipAddress"]
	if pinned != "203.0.113.10" {
		t.Fatalf("a pinned address must reach the server verbatim, got %v", pinned)
	}

	// Null is what stops Infisical filling one in, so it has to be sent rather than omitted.
	skipped, present := wireBody(t, ctx.RequestScope("digest", []string{scopeFieldIPAddress}, ""))["ipAddress"]
	if !present || skipped != nil {
		t.Fatalf("excluding ip_address must send an explicit null, got %v (present=%v)", skipped, present)
	}

	both, present := wireBody(t, ctx.RequestScope("digest", []string{scopeFieldIPAddress}, "203.0.113.10"))["ipAddress"]
	if !present || both != nil {
		t.Fatalf("excluding must override a pinned address, got %v (present=%v)", both, present)
	}
}

func TestValidateScopeExclusions(t *testing.T) {
	if err := ValidateScopeExclusions([]string{scopeFieldDataHash, scopeFieldIPAddress}); err != nil {
		t.Fatalf("known field names must validate: %v", err)
	}
	if err := ValidateScopeExclusions(nil); err != nil {
		t.Fatalf("no exclusions must validate: %v", err)
	}
	if err := ValidateScopeExclusions([]string{"dataHash"}); err == nil {
		t.Fatal("expected the camelCase spelling to be rejected")
	}
}

func wireBody(t *testing.T, payload any) map[string]any {
	t.Helper()

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshalling the payload failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the payload did not marshal to an object: %v (%s)", err, raw)
	}
	return out
}
