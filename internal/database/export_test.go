package database

// EncryptionAsAsked is the refusal a deployment's stated transport produces,
// for the test.
//
// Exported for the test alone. What it decides is a comparison between what
// the deployment asked for and what the connection answered, and a test
// against a live server would be a test of whichever transport that server
// happened to negotiate — which passes for the wrong reason on one engine and
// says nothing on another.
func EncryptionAsAsked(server Server, target Target) error {
	return encryptionAsAsked(server, target)
}
