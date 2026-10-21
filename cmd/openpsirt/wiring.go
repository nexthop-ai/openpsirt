// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/directory"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/published"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
	"github.com/nexthop-ai/openpsirt/internal/signing"
)

// returnsTo refuses a provider with no address to send people back to.
//
// A provider sends people back to an address, and it compares that address
// against what it was registered with. Deriving it from whatever a request
// claims its host is would make the address depend on the request — so it is
// stated, and a deployment that configured a provider without stating it stops
// here rather than at somebody's first sign-in.
func returnsTo(providers map[string]signin.Provider, baseURL string) error {
	if len(providers) > 0 && baseURL == "" {
		return errors.New("OPENPSIRT_BASE_URL has to name the address people reach this on, " +
			"because a provider is configured")
	}
	return nil
}

// publishesAs is the identity this deployment publishes under, and where what
// it publishes is reachable.
//
// One value rather than one per reader of it. A document names the publisher
// and states its own address, and the directory names the publisher and states
// every file's, so two constructions of this are two deployments the first
// time either grows a field.
//
// A deployment that serves its own documents does so at its own address, in
// the folder the standard reserves for them, and an advisory every product of
// which publishes states that address; any other states the directory's.
func publishesAs(cfg config.Config) publisher.Named {
	who := publisher.Named{
		Name: cfg.PublisherName, Namespace: cfg.PublisherNamespace,
		Category: cfg.PublisherCategory, Prefix: cfg.AdvisoryPrefix,
		Published: cfg.DirectoryURL,
	}
	if cfg.Publish {
		who.Served = strings.TrimRight(cfg.BaseURL, "/") + publish.DirectoryPath
	}
	return who
}

// publishing is the surface that serves the published documents and the pass
// that writes them, or neither where the deployment publishes nothing. The
// signer is read by publishingKey, before the database is needed.
func publishing(cfg config.Config, db *bun.DB, name string,
	logger *slog.Logger, signer *signing.Signer) (http.Handler, *publish.Pass) {

	if !cfg.Publish {
		return nil, nil
	}
	who := publishesAs(cfg)
	base := strings.TrimRight(cfg.BaseURL, "/")
	surface := published.Handler(published.Config{
		DB: db, Who: who, Base: base, Rate: cfg.PublishRate, Signer: signer,
		Proxies: access.Trust{From: cfg.TrustedSources},
		List:    cfg.DirectoryList, Mirror: cfg.DirectoryMirror, Logger: logger,
	})
	logger.Info("security documents are published to anybody, for the products an "+
		"administrator chose", "at", base+publish.WellKnown, "signed", signer != nil)
	return surface, publish.NewPass(db, publish.NewGenerator(db, who, base), name, logger)
}

// publishingKey reads the key published documents are signed with, or answers
// nil where the deployment publishes nothing or publishes unsigned.
func publishingKey(cfg config.Config) (*signing.Signer, error) {
	if !cfg.Publish || cfg.PublishKey == "" {
		return nil, nil
	}
	signer, err := signing.Read(cfg.PublishKey, cfg.PublishPassphrase)
	if err != nil {
		return nil, fmt.Errorf("OPENPSIRT_PUBLISH_KEY: %w", err)
	}
	return signer, nil
}

// onlyTheBoundProvider refuses a provider change that nobody re-granted.
//
// Identities bound by a provider that is no longer configured are not
// interpretable: the identifiers belong to somebody else's namespace. The way
// out is to withdraw the bindings deliberately, which is an administrative act
// with a record, rather than to have them silently mean something new.
func onlyTheBoundProvider(ctx context.Context, rights *access.Store, providers map[string]signin.Provider) error {
	if len(providers) == 0 {
		// Nothing is configured, so nothing reinterprets anything. A
		// deployment authenticating at a proxy is the ordinary case here.
		return nil
	}
	bound, err := rights.BoundProviders(ctx)
	if err != nil {
		return err
	}
	// Compared on the issuer rather than the name. The name is a label an
	// operator picks and may change without anything about the identities
	// moving, and repointing the issuer at a different provider while leaving
	// the label alone is the ordinary shape of a provider change — so
	// comparing names would miss the case this exists for and refuse the one
	// it does not care about.
	issuers := make(map[string]bool, len(providers))
	configured := make([]string, 0, len(providers))
	for _, provider := range providers {
		issuers[provider.Issuer()] = true
		configured = append(configured, provider.Issuer())
	}
	sort.Strings(configured)

	for _, was := range bound {
		if issuers[was] {
			continue
		}
		// The way out has to be in the message. By the time anybody reads
		// this the provider has already changed and the process will not
		// start, so the route that withdraws a binding is not serving — and
		// naming the act without saying where it is reachable from leaves an
		// operator with a stopped process and no next step.
		return fmt.Errorf(
			"identities here are bound to %q and this deployment is configured for %s: "+
				"an identifier one provider issued names somebody else at another. Point "+
				"OPENPSIRT_OIDC_ISSUER back at %[1]q, unbind each person from the Access screen, "+
				"signed in as an administrator, and change the issuer after that "+
				"— a binding is withdrawn while the provider that made it is still "+
				"configured. Where %[1]q cannot be reached either, configure the trusted "+
				"header with no provider at all and do the same from there",
			was, strings.Join(configured, ", "))
	}
	return nil
}

// signInProviders builds the way somebody may sign in.
//
// A deployment may configure none, which is the arrangement where a reverse
// proxy authenticates instead — so an empty set is not a fault. It may not
// configure two: an identity here is a username, and two providers issuing
// usernames independently would make the same name two different people or one
// person two accounts, depending on which way the ambiguity fell (REQ-41).
func signInProviders(ctx context.Context, cfg config.Config, logger *slog.Logger) (map[string]signin.Provider, error) {
	providers := map[string]signin.Provider{}

	// Refused here rather than at somebody's first sign-in, which is the point
	// of building providers at startup at all. Naming both settings is what
	// makes the message actionable: whichever one is wrong, the operator can
	// see which two are fighting.
	if cfg.OIDCIssuer != "" && cfg.GitHubClientID != "" {
		return nil, fmt.Errorf(
			"two sign-in providers are configured: OPENPSIRT_OIDC_ISSUER and " +
				"OPENPSIRT_GITHUB_CLIENT_ID. One provider is configured at a time, because an " +
				"identity here is a username and two providers issuing them independently " +
				"cannot be told apart. Remove one and start again")
	}

	if cfg.OIDCIssuer != "" {
		provider, err := signin.NewOIDC(ctx, signin.OIDCConfig{
			Name: cfg.OIDCName, Issuer: cfg.OIDCIssuer,
			ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
			GroupsClaim: cfg.OIDCGroupsClaim, UsernameClaim: cfg.OIDCUsernameClaim,
		})
		if err != nil {
			return nil, err
		}
		providers[provider.Name()] = provider
		logger.Info("sign-in configured", "provider", provider.Name(), "issuer", cfg.OIDCIssuer)
	}

	if cfg.GitHubClientID != "" {
		provider, err := signin.NewGitHub(signin.GitHubConfig{
			ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret,
			Organization: cfg.GitHubOrg,
		})
		if err != nil {
			return nil, err
		}
		providers[provider.Name()] = provider
		logger.Info("sign-in configured", "provider", provider.Name(), "organization", cfg.GitHubOrg)
	}

	return providers, nil
}

// roleMode reads where roles come from, per request.
//
// Read rather than held because replicas restart one at a time, and the one
// that applied configuration last is what every replica has to answer by. A
// read that fails answers with the mode that derives nothing, which is the
// safe direction.
func roleMode(settings *setting.Store) func(context.Context) access.Mode {
	return func(ctx context.Context) access.Mode {
		stored, _, err := settings.Get(ctx, setting.RoleMode)
		if err != nil {
			return access.Direct
		}
		return access.AsMode(stored)
	}
}

// mailChannel is the channel an operator configured, or nothing.
//
// Returned as the interface rather than the concrete type, and deliberately
// through a function that can answer nil: a typed nil pointer handed to an
// interface is not nil, and the sweep asks whether it has a channel.
// The one it got is logged, the way the attachment store logs what it
// chose. Half a configuration is refused where it is read, so what reaches
// here is either a whole one or none — and "none" is ordinary rather than a
// fault, which is exactly why it has to be said out loud.
func mailChannel(cfg config.Config, logger *slog.Logger) notify.Channel {
	mail := notify.NewMail(cfg.MailServer, cfg.MailFrom, cfg.MailUsername, cfg.MailPassword)
	if mail == nil {
		logger.Info("mail is not configured, so nothing is sent outside the application")
		return nil
	}
	logger.Info("mail is configured", "server", cfg.MailServer, "from", cfg.MailFrom)
	return mail
}

// chatPlatforms is the chat platforms an operator configured, which is often
// none. Each is logged, the way mail is, because none is ordinary and has to be
// said out loud.
func chatPlatforms(cfg config.Config, logger *slog.Logger) []notify.Chat {
	var chats []notify.Chat
	// Checked as the concrete type before it becomes the interface: a typed
	// nil pointer handed to an interface is not nil.
	if slack := notify.NewSlack(cfg.SlackToken); slack != nil {
		chats = append(chats, slack)
	}
	if zulip := notify.NewZulip(cfg.ZulipSite, cfg.ZulipEmail, cfg.ZulipKey); zulip != nil {
		chats = append(chats, zulip)
	}
	if len(chats) == 0 {
		logger.Info("no chat platform is configured, so nothing is sent to chat")
	}
	for _, chat := range chats {
		logger.Info("chat is configured", "platform", chat.Platform())
	}
	return chats
}

// noteStoreInTheClear says what a plaintext object store costs, at every start
// rather than once at the moment somebody configured it. Each store names its
// own cost in clear. An attachment is handed over as a redirect to an address
// that carries its own authorization, so anybody on the path between a browser
// and the store may fetch the file it names. A published advisory is written
// across that path, so anybody on it may change what the public reads.
//
// Its own function so that a test can watch it happen. Reached through the
// store's own report rather than through the setting, because what matters is
// the endpoint that was accepted rather than the intent that admitted it, and
// the endpoint it names has had any password taken out of it.
func noteStoreInTheClear(bucket *attach.Bucket, clear string, logger *slog.Logger) {
	if !bucket.InTheClear() {
		return
	}
	logger.Warn(clear, "endpoint", bucket.Endpoint())
}

// storeKind is what tells one configured store from the other: the settings it
// is refused under, the words its errors and its plaintext warning use, and how
// its local directory is opened.
type storeKind struct {
	// names are the settings an object store refusal names.
	names attach.SettingNames
	// what names the store in an error about its object store. An object
	// store's refusal reads the same for either of the two it backs.
	what string
	// dir is the setting that names the local directory. The local store
	// says "file directory" for either of the two it backs, so an operator
	// who has pointed this at a mount they cannot write is sent to the
	// setting they typed.
	dir string
	// clear is the warning a plaintext object store is logged with.
	clear string
	// local opens the directory on this machine, or answers nil for none.
	local func(string) (*attach.Files, error)
}

// openStore opens one configured store: its object store where a bucket is
// named, its directory on this machine otherwise, and nothing where neither
// is. The bucket wins where both are set. Every error names the store, and a
// bucket reached in the clear is warned about whichever store it backs.
//
// The store is asked to answer now rather than at its first use. A store that
// does not answer is a configuration mistake, and the moment to report one is
// while whoever made it is still watching the logs.
//
// Where there is no store the answer is an untyped nil, so that a caller
// testing it against nil sees no store rather than a nil directory.
func openStore(ctx context.Context, s config.Store, kind storeKind,
	logger *slog.Logger) (attach.Storage, error) {

	bucket, err := attach.NewBucket(ctx, bucketOf(s, kind.names))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind.what, err)
	}
	if bucket != nil {
		if err := bucket.Reachable(ctx); err != nil {
			return nil, fmt.Errorf("%s: %w", kind.what, err)
		}
		noteStoreInTheClear(bucket, kind.clear, logger)
		return bucket, nil
	}
	local, err := kind.local(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind.dir, s.Dir, err)
	}
	if local == nil {
		return nil, nil
	}
	if err := local.Reachable(ctx); err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind.dir, s.Dir, err)
	}
	return local, nil
}

// directoryStore is where the published advisory directory is written, or
// nothing where an operator configured nowhere.
//
// Its own store rather than the attachment one. Every file here is served to
// anybody who asks and every attachment is authorized before it is handed
// over (REQ-70), so one destination would have to be both — and a bucket that
// is public because half of what it holds must be is the shape that leaks the
// other half.
//
// The local directory is a deployment here, unlike for attachments: a web
// server on this machine reading the same disk is the ordinary way to serve
// static files. It is written by one process, so it wants a replica of its
// own and a volume of its own, and the configuration page says so.
//
// Its files are made readable by whoever serves them. Written the way
// attachments are, a web server running as its own user is refused every file
// and the directory looks empty.
func directoryStore(ctx context.Context, cfg config.Config,
	logger *slog.Logger) (*directory.Store, error) {

	files, err := openStore(ctx, cfg.Directory, storeKind{
		names: attach.SettingNames{ //nolint:gosec // G101: the names of settings, not their values
			AllowHTTP: "OPENPSIRT_DIRECTORY_ALLOW_HTTP",
			Key:       "OPENPSIRT_DIRECTORY_KEY",
			Secret:    "OPENPSIRT_DIRECTORY_SECRET",
			Token:     "OPENPSIRT_DIRECTORY_SESSION_TOKEN",
		},
		what:  "the published advisory directory's object store",
		dir:   "OPENPSIRT_DIRECTORY_DIR",
		clear: "published advisories are written across the network in the clear",
		local: attach.NewServedFiles,
	}, logger)
	switch files.(type) {
	case nil:
		return nil, err
	case *attach.Bucket:
		logger.Info("published advisories are written to an object store",
			"bucket", cfg.Directory.Bucket)
	default:
		logger.Info("published advisories are written to a directory on this machine",
			"directory", cfg.Directory.Dir)
	}
	return directory.Published(files), nil
}

// bucketOf is the object store one configured store names, refusing under the
// setting names given.
func bucketOf(s config.Store, names attach.SettingNames) attach.BucketConfig {
	return attach.BucketConfig{
		Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region,
		Key: s.Key, Secret: s.Secret, Token: s.Token,
		PathStyle: s.PathStyle, AllowHTTP: s.AllowHTTP,
		Names: names,
	}
}

// attachmentStore is where attachments go, or nothing where an operator
// configured nowhere.
//
// The local directory is the development backend — one process and one disk
// — and a deployment that named a bucket meant the bucket.
func attachmentStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (attach.Storage, error) {
	files, err := openStore(ctx, cfg.Attachments, storeKind{
		names: attach.SettingNames{ //nolint:gosec // G101: the names of settings, not their values
			AllowHTTP: "OPENPSIRT_ATTACHMENT_ALLOW_HTTP",
			Key:       "OPENPSIRT_ATTACHMENT_KEY",
			Secret:    "OPENPSIRT_ATTACHMENT_SECRET",
			Token:     "OPENPSIRT_ATTACHMENT_SESSION_TOKEN",
		},
		what:  "the attachment object store",
		dir:   "OPENPSIRT_ATTACHMENT_DIR",
		clear: "attachment links cross the network in the clear",
		local: attach.NewFiles,
	}, logger)
	switch files.(type) {
	case nil:
		return nil, err
	case *attach.Bucket:
		logger.Info("attachments are held in an object store", "bucket", cfg.Attachments.Bucket)
	default:
		// Said plainly, because it is the backend that is not a production
		// option: one process and one disk, and two replicas would disagree
		// about what exists.
		logger.Warn("attachments are held on this machine's disk, which is for development",
			"directory", cfg.Attachments.Dir)
	}
	return files, nil
}
