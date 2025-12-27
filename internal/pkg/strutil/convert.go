package strutil

import "strconv"

// ConvertToInt safely converts a string to an integer, returning 0 if the conversion fails.
func ConvertToInt(str string) int {
	value, err := strconv.Atoi(str)
	if err != nil {
		return 0 // Return 0 if the conversion fails, or you can choose a different default value
	}
	return value
}

// ConvertToInt64 safely converts a string to an int64, returning 0 if the conversion fails.
func ConvertToInt64(str string) int64 {
	value, err := strconv.ParseInt(str, 10, 64) // Parsing as int64
	if err != nil {
		return 0 // Return 0 if the conversion fails, or you can choose a different default value
	}
	return value
}
