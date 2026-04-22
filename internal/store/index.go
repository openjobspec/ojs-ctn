package store

import "time"

type ledgerIndex struct {
	entries  []Entry
	byID     map[string]int
	headHash string
}

func newLedgerIndex(records []replayRecord) *ledgerIndex {
	index := &ledgerIndex{byID: make(map[string]int)}
	for _, record := range records {
		if record.entry != nil {
			index.appendEntry(*record.entry, record.entryLineSHA)
			continue
		}
		if record.cosignature != nil && index.has(record.cosignature.entryID) {
			index.cosign(record.cosignature.entryID, record.cosignature.value)
		}
	}
	return index
}

func (i *ledgerIndex) appendEntry(entry Entry, lineHash string) {
	i.entries = append(i.entries, entry)
	i.byID[entry.EntryID] = len(i.entries) - 1
	i.headHash = lineHash
}

func (i *ledgerIndex) has(entryID string) bool {
	_, ok := i.byID[entryID]
	return ok
}

func (i *ledgerIndex) get(entryID string) (Entry, bool) {
	idx, ok := i.byID[entryID]
	if !ok {
		return Entry{}, false
	}
	return copyEntry(i.entries[idx]), true
}

func (i *ledgerIndex) cosign(entryID string, cosig WitnessCosignature) Entry {
	idx := i.byID[entryID]
	replaced := false
	for position, prior := range i.entries[idx].WitnessCosignatures {
		if prior.WitnessKeyID == cosig.WitnessKeyID {
			i.entries[idx].WitnessCosignatures[position] = cosig
			replaced = true
			break
		}
	}
	if !replaced {
		i.entries[idx].WitnessCosignatures = append(i.entries[idx].WitnessCosignatures, cosig)
	}
	return copyEntry(i.entries[idx])
}

func (i *ledgerIndex) head(updatedAt time.Time) Head {
	head := Head{
		SequenceNumber: uint64(len(i.entries)),
		UpdatedAt:      updatedAt,
		LastEntrySHA:   i.headHash,
	}
	if len(i.entries) > 0 {
		head.LastEntryID = i.entries[len(i.entries)-1].EntryID
	}
	return head
}

func (i *ledgerIndex) count() int {
	return len(i.entries)
}

func copyEntry(entry Entry) Entry {
	if len(entry.WitnessCosignatures) > 0 {
		entry.WitnessCosignatures = append([]WitnessCosignature(nil), entry.WitnessCosignatures...)
	}
	return entry
}
