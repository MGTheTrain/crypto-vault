package models

import (
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
)

// BlobModel is the GORM database model for blobs (infrastructure concern)
type BlobModel struct {
	ID                string    `gorm:"primaryKey;type:uuid"`
	DateTimeCreated   time.Time `gorm:"not null"`
	UserID            string    `gorm:"not null;index;type:varchar(255)"`
	Name              string    `gorm:"not null;type:varchar(255)"`
	Size              int64     `gorm:"not null"`
	Type              string    `gorm:"not null;type:varchar(50)"`
	EncryptionKeyID   *string   `gorm:"type:uuid;index"`
	SignKeyID         *string   `gorm:"type:uuid;index"`
	SignatureBlobID   *string   `gorm:"type:uuid;index"`
	SignatureFileName *string   `gorm:"type:varchar(255)"`
}

// TableName specifies the table name for GORM
func (BlobModel) TableName() string {
	return "blobs"
}

// ToDomain converts GORM model to domain entity
func (m *BlobModel) ToDomain() *blobs.BlobMeta {
	return &blobs.BlobMeta{
		ID:                m.ID,
		DateTimeCreated:   m.DateTimeCreated,
		UserID:            m.UserID,
		Name:              m.Name,
		Size:              m.Size,
		Type:              m.Type,
		EncryptionKeyID:   m.EncryptionKeyID,
		SignKeyID:         m.SignKeyID,
		SignatureBlobID:   m.SignatureBlobID,
		SignatureFileName: m.SignatureFileName,
	}
}

// FromDomain converts domain entity to GORM model
func (m *BlobModel) FromDomain(b *blobs.BlobMeta) {
	m.ID = b.ID
	m.DateTimeCreated = b.DateTimeCreated
	m.UserID = b.UserID
	m.Name = b.Name
	m.Size = b.Size
	m.Type = b.Type
	m.EncryptionKeyID = b.EncryptionKeyID
	m.SignKeyID = b.SignKeyID
	m.SignatureBlobID = b.SignatureBlobID
	m.SignatureFileName = b.SignatureFileName
}
