// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// backlogRetry is how long a sender turned away by a full backlog is told to
// wait before sending again.
const backlogRetry = 30 * time.Second

// retiredRefusal is the refusal for an upload filed against a retired product,
// release or variant, and nil where none of them is retired. takes names what
// an upload of the kind is, as the refusal states it.
//
// A retired product, release or variant takes no upload. It is the other half
// of retiring one: the lists stop offering it and this stops a pipeline still
// configured for it filing against it anyway. The refusal says what to do,
// because what has to change is a build script somebody maintains.
//
// Asked after authorization, so that a sender who may not file against this
// product cannot learn from the refusal that the name exists at all.
//
// The outermost first: a product retired with its releases still in use is
// answered about the product, which is the thing somebody has to bring back.
// Spelled back as the sender sent it, because what they have to go and change
// is their own configuration.
func retiredRefusal(named *catalog.Named, product, branchOrTag, variant, takes string) error {
	var retired string
	switch {
	case named.ProductRetired:
		retired = fmt.Sprintf("product %q", product)
	case named.BranchOrTagRetired:
		retired = fmt.Sprintf("release %q of %q", branchOrTag, product)
	case named.VariantRetired:
		retired = fmt.Sprintf("variant %q of %q", variant, product)
	default:
		return nil
	}
	return huma.NewError(http.StatusConflict, fmt.Sprintf(
		"%s is retired and takes no %s; declare it again to bring it back", retired, takes))
}

// backlogged is the refusal for an upload arriving while the work of kind
// waiting to be done is as deep as the backlog allows, nil where it is not,
// and a fault where neither can be read. The refusal names what is waiting
// and what is to be done with it.
//
// Refused before anything is stored: deciding costs a query, and deciding
// afterwards costs however long it takes to store tens of megabytes thrown
// away, on a deployment already behind on its work. Asked after
// authorization, so that how far behind the deployment is cannot be measured
// by a sender who may not upload.
//
// The limit in force, never the one this binary was built with. Refusing
// against the built-in number makes the effective limit the smaller of the
// two, so raising the setting changes nothing for the producer the setting
// exists for.
func backlogged(ctx context.Context, in core.Deps, kind, waiting, done string) error {
	depth, err := in.Queue.Depth(ctx, kind)
	if err != nil {
		return core.WentWrong(in.Logger, "cannot tell how much work is waiting", err)
	}
	limit, err := in.Queue.Backlog(ctx)
	if err != nil {
		return core.WentWrong(in.Logger, "cannot tell how much work may wait", err)
	}
	if depth >= limit {
		return busy(fmt.Sprintf("%d %s are already waiting to be %s; try again shortly", depth, waiting, done))
	}
	return nil
}

// busy is a 503 saying when to send again, which a client honoring the
// header waits for.
func busy(message string) error {
	return huma.ErrorWithHeaders(huma.NewError(http.StatusServiceUnavailable, message),
		http.Header{"Retry-After": {fmt.Sprint(int(backlogRetry.Seconds()))}})
}

// turnedAway is whether an answer turns an upload away, as the upload's
// receipts record, rather than reporting a fault of this deployment.
func turnedAway(answer error) bool {
	var said huma.StatusError
	return errors.As(answer, &said) && said.GetStatus() != http.StatusInternalServerError
}
