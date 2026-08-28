package store

import (
	"context"
	"fmt"

	"github.com/rom/Xfuzz/pkg/corpusio"
)

// ImportCorpus reads a corpus directory into a campaign.
//
// The import is audited. Bringing in someone else's corpus changes what a
// campaign will explore and therefore what it will find, and a finding whose
// seed arrived from an unrecorded directory is a finding nobody can trace.
func (s *Store) ImportCorpus(ctx context.Context, campaignID int64, dir string,
	opts corpusio.ImportOptions) (corpusio.ImportReport, error) {

	tcs, rep, err := corpusio.Import(dir, opts)
	if err != nil {
		return rep, err
	}
	if err := s.SaveTestcases(ctx, campaignID, tcs); err != nil {
		return rep, err
	}
	if _, err := s.Audit(ctx, "", AuditCorpusImport,
		fmt.Sprintf("campaign=%d dir=%s format=%s imported=%d duplicate=%d skipped=%d",
			campaignID, rep.Dir, rep.Format, rep.Imported, rep.Duplicate, rep.Skipped)); err != nil {
		return rep, err
	}
	return rep, nil
}

// ExportCorpus writes a campaign's corpus to a directory in another fuzzer's
// layout.
func (s *Store) ExportCorpus(ctx context.Context, campaignID int64, dir string,
	opts corpusio.ExportOptions) (corpusio.ExportReport, error) {

	tcs, err := s.Testcases(ctx, campaignID, TestcaseQuery{
		FavouredOnly: opts.FavouredOnly,
		WithPayload:  true,
		Order:        "coverage",
	})
	if err != nil {
		return corpusio.ExportReport{}, err
	}
	// FavouredOnly has already been applied by the query, and applying it again
	// in Export would be harmless but redundant; clearing it keeps the count in
	// the report equal to the number of rows read.
	opts.FavouredOnly = false
	return corpusio.Export(dir, tcs, opts)
}
