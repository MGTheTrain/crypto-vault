package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertToInt(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"123", 123},
		{"0", 0},
		{"-456", -456},
		{"abc", 0},   // invalid input
		{"12.34", 0}, // not an integer
		{"", 0},      // empty string
	}

	for _, test := range tests {
		result := ConvertToInt(test.input)
		assert.Equal(t, test.expected, result, "Input: %q", test.input)
	}
}

func TestConvertToInt64(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1234567890", 1234567890},
		{"0", 0},
		{"-987654321", -987654321},
		{"abc", 0},   // invalid input
		{"12.34", 0}, // not an integer
		{"", 0},      // empty string
	}

	for _, test := range tests {
		result := ConvertToInt64(test.input)
		assert.Equal(t, test.expected, result, "Input: %q", test.input)
	}
}
