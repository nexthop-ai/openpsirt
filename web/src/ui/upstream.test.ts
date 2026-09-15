import { describe, expect, it } from "vitest";
import { named, upstream } from "./upstream";

describe("where a package is read about", () => {
  it("sends each ecosystem to its own index", () => {
    expect(upstream("pkg:golang/github.com/anchore/grype@v0.87.0")).toBe(
      "https://pkg.go.dev/github.com/anchore/grype",
    );
    // A module path that is not a repository address still resolves there.
    expect(upstream("pkg:golang/golang.org/x/crypto@v0.55.0")).toBe(
      "https://pkg.go.dev/golang.org/x/crypto",
    );
    expect(upstream("pkg:npm/lodash@4.17.21")).toBe("https://www.npmjs.com/package/lodash");
    expect(upstream("pkg:cargo/serde@1.0.0")).toBe("https://crates.io/crates/serde");
  });

  it("reads a distribution package under its own name, not the distribution's", () => {
    expect(upstream("pkg:deb/debian/curl@8.14.1-2")).toBe("https://tracker.debian.org/pkg/curl");
    expect(named("pkg:deb/debian/libcurl3t64-gnutls@8.14.1-2")).toBe("libcurl3t64-gnutls");
  });

  it("keeps a scoped name whole and encodes it", () => {
    expect(upstream("pkg:npm/@types/node@20.0.0")).toBe(
      "https://www.npmjs.com/package/%40types/node",
    );
  });

  it("does not read a scope as a version", () => {
    // An identifier with no version is ordinary — a component the scan named
    // without one. Cutting at the scope's own separator left no name at all,
    // so the row showed neither a name nor a link.
    expect(named("pkg:npm/@types/node")).toBe("@types/node");
    expect(upstream("pkg:npm/@types/node")).toBe("https://www.npmjs.com/package/%40types/node");
  });

  it("offers nothing for an ecosystem it has no address for", () => {
    // A private registry and a vendored fork both look like this, and a guessed
    // address is worse than none.
    expect(upstream("pkg:generic/something@1.0")).toBeNull();
    expect(upstream("pkg:swift/apple/swift-nio@2.0")).toBeNull();
  });

  it("offers nothing for what is not an identifier at all", () => {
    expect(upstream("")).toBeNull();
    expect(upstream(null)).toBeNull();
    expect(upstream("https://evil.example/")).toBeNull();
    // An identifier naming an ecosystem and nothing else names no package.
    expect(upstream("pkg:deb")).toBeNull();
  });

  it("encodes a name that would otherwise choose part of the address", () => {
    // The identifier comes out of a scan file, so the name is somebody else's
    // input: a query string in it must not become one in the address.
    expect(upstream("pkg:deb/debian/evil%3Fx=1@1.0")).toBe(
      "https://tracker.debian.org/pkg/evil%3Fx%3D1",
    );
  });
});
