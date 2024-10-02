package kms

import (
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"context"
	"fmt"
	contribCrypto "github.com/dapr/components-contrib/crypto"
	internals "github.com/dapr/kit/crypto"
	"github.com/dapr/kit/logger"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type kmsCrypto struct {
	client *kms.KeyManagementClient
	logger logger.Logger
}

func (k *kmsCrypto) SupportedEncryptionAlgorithms() []string {
	//TODO implement me
	panic("implement me")
}

func (k *kmsCrypto) SupportedSignatureAlgorithms() []string {
	//TODO implement me
	panic("implement me")
}

func (k *kmsCrypto) Init(ctx context.Context, metadata contribCrypto.Metadata) error {
	//TODO implement me
	var err error
	k.client, err = kms.NewKeyManagementClient(ctx)
	return err
}

func (k *kmsCrypto) GetKey(ctx context.Context, keyName string) (pubKey jwk.Key, err error) {
	//TODO implement me
	panic("implement me")
}

func (k *kmsCrypto) Encrypt(ctx context.Context, plaintext []byte, algorithm string, keyName string, nonce []byte, associatedData []byte) (ciphertext []byte, tag []byte, err error) {

	// Build the request.
	req := &kmspb.EncryptRequest{
		Name:      keyName,
		Plaintext: plaintext,
	}
	// Call the API.
	result, err := k.client.Encrypt(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	return result.GetCiphertext(), nil, nil
}

func (k *kmsCrypto) Decrypt(ctx context.Context, ciphertext []byte, algorithm string, keyName string, nonce []byte, tag []byte, associatedData []byte) (plaintext []byte, err error) {

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}

	// Call the API.
	result, err := k.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return result.Plaintext, nil

}

func (k *kmsCrypto) WrapKey(ctx context.Context, plaintextKey jwk.Key, algorithm string, keyName string, nonce []byte, associatedData []byte) (wrappedKey []byte, tag []byte, err error) {
	//TODO implement me
	plainKey, err := internals.SerializeKey(plaintextKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot serialize key: %w", err)
	}
	req := &kmspb.EncryptRequest{
		Name:      keyName,
		Plaintext: plainKey,
	}
	// Call the API.
	result, err := k.client.Encrypt(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	return result.GetCiphertext(), nil, nil
}

func (k *kmsCrypto) UnwrapKey(ctx context.Context, wrappedKey []byte, algorithm string, keyName string, nonce []byte, tag []byte, associatedData []byte) (plaintextKey jwk.Key, err error) {
	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: wrappedKey,
	}

	// Call the API.
	result, err := k.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	plaintextKey, err = jwk.FromRaw(result.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from raw key: %w", err)

	}
	return plaintextKey, nil
}

func (k *kmsCrypto) Sign(ctx context.Context, digest []byte, algorithm string, keyName string) (signature []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (k *kmsCrypto) Verify(ctx context.Context, digest []byte, signature []byte, algorithm string, keyName string) (valid bool, err error) {
	//TODO implement me
	panic("implement me")
}

func (k *kmsCrypto) Close() error {
	return nil
}

// NewGCPKmsCrypto returns a new Azure Key Vault crypto provider.
func NewGCPKmsCrypto(logger logger.Logger) *kmsCrypto {
	return &kmsCrypto{
		logger: logger,
	}
}
