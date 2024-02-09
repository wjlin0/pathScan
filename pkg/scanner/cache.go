package scanner

import "crypto/sha1"

func (scanner *Scanner) findDuplicate(data string) bool {
	// check if we've already printed this data
	itemHash := sha1.Sum([]byte(data))
	if scanner.cache.Contains(itemHash) {
		return true
	}
	scanner.cache.Add(itemHash, struct{}{})
	return false
}
