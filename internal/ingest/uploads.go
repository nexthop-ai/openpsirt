// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

// UploadType is one kind of document a build or its product is sent. Each
// arrives at a path of its own, because each takes a different body and
// answers a different receipt.
type UploadType string

const (
	// UploadSBOM is an inventory of what a build ships.
	UploadSBOM UploadType = "sbom"
	// UploadSARIF is a static analysis run.
	UploadSARIF UploadType = "sarif"
	// UploadVEX is a third party's VEX document about the product.
	UploadVEX UploadType = "vex"
	// UploadAdvisory is a supplier's security advisory about the product.
	UploadAdvisory UploadType = "supplier-advisory"
)

// UploadTypes is every kind of upload, in the order a build's uploads list
// them.
func UploadTypes() []UploadType {
	return []UploadType{UploadSBOM, UploadSARIF, UploadVEX, UploadAdvisory}
}

// UploadStatus is what became of one upload, in one vocabulary for every
// kind. Each kind's own receipt says it in its own words.
type UploadStatus string

const (
	// UploadInProgress is taken and still being read or applied.
	UploadInProgress UploadStatus = "in-progress"
	// UploadCompleted is read and applied, or kept beside a newer one. A VEX
	// document or a supplier advisory is recorded in this word and the next,
	// so its record is its status.
	UploadCompleted UploadStatus = "completed"
	// UploadFailed is taken and then found unusable.
	UploadFailed UploadStatus = "failed"
	// UploadRefused is turned away when it arrived, so nothing of it is held
	// but the reason.
	UploadRefused UploadStatus = "refused"
)

// UploadStatuses is every status an upload may hold.
func UploadStatuses() []UploadStatus {
	return []UploadStatus{UploadInProgress, UploadCompleted, UploadFailed, UploadRefused}
}
