package v1

// GPGPublicKey describes a gpb public key
type GPGPublicKey struct {
	PK         string `json:"-" dynamodbav:"pk"`
	ASCIIArmor string `json:"ascii_armor" dynamodbav:"ascii_armor" validate:"required"`
	KeyID      string `json:"key_id" dynamodbav:"sk" validate:"required"`
}

// Platform describes a provider distribution package
type Platform struct {
	Arch string `json:"arch" dynamodbav:"arch" validate:"required"`
	OS   string `json:"os" dynamodbav:"os" validate:"required"`
}

// Provider describes a terraform provider
type Provider struct {
	Namespace string `json:"namespace" dynamodbav:"namespace" validate:"required"`
	Type      string `json:"type" dynamodbav:"type" validate:"required"`
}

// SigningKey contains information about the keys used to sign the version
type SigningKey struct {
	GPGPublicKeys []GPGPublicKey `json:"gpg_public_keys" dynamodbav:"gpg_public_keys"`
}

// Version describes a provider version
type Version struct {
	PK             string     `json:"-" dynamodbav:"pk"`
	GPGPublicKeyID string     `json:"gpg_public_key_id,omitempty" dynamodbav:"gpg_public_key_id" validate:"required"`
	Platforms      []Platform `json:"platforms" dynamodbav:"platforms" validate:"required"`
	Protocols      []string   `json:"protocols" dynamodbav:"protocols" validate:"required"`
	Version        string     `json:"version" dynamodbav:"sk" validate:"required"`
}
