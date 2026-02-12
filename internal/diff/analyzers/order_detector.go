package analyzers

// OrderChange describes a detected reordering.
type OrderChange struct {
	ID          string // UUID or identifier of the reordered element
	OldPosition int    // 0-based index in old config
	NewPosition int    // 0-based index in new config
}

// OrderDetector detects when elements are reordered without content changes.
type OrderDetector struct{}

// NewOrderDetector creates a new OrderDetector.
func NewOrderDetector() *OrderDetector {
	return &OrderDetector{}
}

// DetectReorders compares two ordered lists of identifiers and returns
// elements that changed position. Elements present in only one list are ignored
// (those are additions/removals, not reorders).
func (d *OrderDetector) DetectReorders(oldIDs, newIDs []string) []OrderChange {
	// Build position maps
	oldPos := make(map[string]int, len(oldIDs))
	for i, id := range oldIDs {
		oldPos[id] = i
	}
	newPos := make(map[string]int, len(newIDs))
	for i, id := range newIDs {
		newPos[id] = i
	}

	var reorders []OrderChange
	for id, oldIdx := range oldPos {
		newIdx, exists := newPos[id]
		if !exists {
			continue // Element removed, not a reorder
		}
		if oldIdx != newIdx {
			reorders = append(reorders, OrderChange{
				ID:          id,
				OldPosition: oldIdx,
				NewPosition: newIdx,
			})
		}
	}

	return reorders
}

// HasReorders returns true if any reordering was detected.
func (d *OrderDetector) HasReorders(oldIDs, newIDs []string) bool {
	return len(d.DetectReorders(oldIDs, newIDs)) > 0
}
