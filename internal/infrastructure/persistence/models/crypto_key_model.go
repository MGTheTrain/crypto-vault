package models

import (
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
)

// CryptoKeyModel is the GORM database model for crypto keys (infrastructure concern)
type CryptoKeyModel struct {
	ID              string    `gorm:"primaryKey;type:uuid"`
	KeyPairID       string    `gorm:"not null;index;type:uuid"`
	Algorithm       string    `gorm:"type:varchar(20)"`
	KeySize         uint32    `gorm:"type:integer"`
	Type            string    `gorm:"type:varchar(20)"`
	DateTimeCreated time.Time `gorm:"not null"`
	UserID          string    `gorm:"not null;index;type:varchar(255)"`
}

// TableName specifies the table name for GORM
func (CryptoKeyModel) TableName() string {
	return "crypto_keys"
}

// ToDomain converts GORM model to domain entity
func (m *CryptoKeyModel) ToDomain() *keys.CryptoKeyMeta {
	return &keys.CryptoKeyMeta{
		ID:              m.ID,
		KeyPairID:       m.KeyPairID,
		Algorithm:       m.Algorithm,
		KeySize:         m.KeySize,
		Type:            m.Type,
		DateTimeCreated: m.DateTimeCreated,
		UserID:          m.UserID,
	}
}

// FromDomain converts domain entity to GORM model
func (m *CryptoKeyModel) FromDomain(k *keys.CryptoKeyMeta) {
	m.ID = k.ID
	m.KeyPairID = k.KeyPairID
	m.Algorithm = k.Algorithm
	m.KeySize = k.KeySize
	m.Type = k.Type
	m.DateTimeCreated = k.DateTimeCreated
	m.UserID = k.UserID
}
