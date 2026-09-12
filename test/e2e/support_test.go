package e2e

import (
	"bytes"

	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/storage"
)

func providerAccountRequest(handle string) payments.LinkedAccountRequest {
	return payments.LinkedAccountRequest{
		SellerReference: handle, LegalName: "Studio " + handle,
		DisplayName: "Studio " + handle, Email: handle + "@sellers.example.com",
		EntityType: "private_limited", Country: "IN",
		IdempotencyKey: "acct:" + handle,
	}
}

func putRequest(key string, content []byte) storage.PutRequest {
	return storage.PutRequest{
		Key: key, Body: bytes.NewReader(content),
		ContentType: "application/zip", Size: int64(len(content)),
	}
}
