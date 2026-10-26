// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { productAt } from "../app/routes";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { notACredential } from "../ui/noautofill";
import { Wide } from "../ui/Wide";

type Settings = Body<"RepositoriesBody">;
type Host = Body<"RepositoryHost">;
type Path = Body<"RepositoryPath">;
type Style = Host["style"];

// What each kind of server is called. Keyed on the server's own list, so a
// kind the server adds is a type error here until it has a name.
const STYLES = {
  github: "GitHub",
  gitlab: "GitLab",
  gitea: "Gitea or Forgejo",
  custom: "Custom",
} as const satisfies Record<Style, string>;

// A setting a path may state, leave to a shorter prefix, or turn off.
type Stated = "" | "yes" | "no";

const statedOf = (value: boolean | undefined): Stated =>
  value === undefined ? "" : value ? "yes" : "no";
const valueOf = (said: Stated): boolean | undefined => (said === "" ? undefined : said === "yes");

// One row being edited. The key keeps a row's inputs its own while rows
// above it are removed.
type HostRow = {
  key: number;
  remote: string;
  web: string;
  style: Style;
  file: string;
  compare: string;
};
type PathRow = {
  key: number;
  prefix: string;
  remote: string;
  branch: string;
  snippets: Stated;
  disclosed: Stated;
};

// A product's repository settings: the hosts its source links may open on,
// and what it says about the code under each path. An administrator's
// screen: the server refuses the read and the write to anybody else.
export function Repositories() {
  const { product = "" } = useParams();
  const who = useWho();
  const admin = !!who.data?.admin;
  const settings = useQuery({
    queryKey: ["repositories", product],
    enabled: admin,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/repositories", { params: { path: { product } } }),
      ),
  });

  const head = (
    <div className="screen-head">
      <h2>Repositories</h2>
      <p>
        Source links and snippets in <Link to={productAt(product)}>{product}</Link>
      </p>
    </div>
  );

  if (who.isPending) return <Loading />;
  if (!admin) {
    return (
      <div>
        {head}
        <Empty title="Administrators only." />
      </div>
    );
  }
  if (settings.isPending) return <Loading />;
  if (settings.isError) {
    return <Failed error={settings.error} what="The repository settings could not be read." />;
  }
  return (
    <div>
      {head}
      {/* Keyed on what was read, so a save that lands starts the draft again
          from what the server now holds. */}
      <Draft key={JSON.stringify(settings.data)} product={product} held={settings.data} />
    </div>
  );
}

function Draft({ product, held }: { product: string; held: Settings }) {
  const queries = useQueryClient();
  // Rows read from the server are keyed by position; a row added takes the
  // next key above every one of them.
  const next = useRef(Math.max(held.hosts?.length ?? 0, held.paths?.length ?? 0));
  const keyed = () => next.current++;
  const [hosts, setHosts] = useState<HostRow[]>(() =>
    (held.hosts ?? []).map((host, at) => ({
      key: at,
      remote: host.remote,
      web: host.web,
      style: host.style,
      file: host.file_template ?? "",
      compare: host.compare_template ?? "",
    })),
  );
  const [paths, setPaths] = useState<PathRow[]>(() =>
    (held.paths ?? []).map((path, at) => ({
      key: at,
      prefix: path.prefix,
      remote: path.remote ?? "",
      branch: path.branch ?? "",
      snippets: statedOf(path.snippets),
      disclosed: statedOf(path.disclosed_snippets),
    })),
  );
  const [changed, setChanged] = useState(false);

  const save = useMutation({
    mutationFn: async (body: Settings) =>
      unwrap(
        await api.PUT("/v1/products/{product}/repositories", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: () => {
      setChanged(false);
      void queries.invalidateQueries({ queryKey: ["repositories", product] });
      // A lead's links are built from these as it is read.
      void queries.invalidateQueries({ queryKey: ["lead"] });
    },
  });

  const editHost = (key: number, change: Partial<HostRow>) => {
    setHosts((rows) => rows.map((row) => (row.key === key ? { ...row, ...change } : row)));
    setChanged(true);
  };
  const editPath = (key: number, change: Partial<PathRow>) => {
    setPaths((rows) => rows.map((row) => (row.key === key ? { ...row, ...change } : row)));
    setChanged(true);
  };

  return (
    <>
      <div className="card">
        <h3>Hosts</h3>
        {hosts.length === 0 ? (
          <Empty title="No hosts." detail="Every repository is shown unlinked." />
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th title="A host such as github.com, or a host and the path a mirror keeps its copies under">
                    Remote
                  </th>
                  <th title="The https address links open on">Web address</th>
                  <th>Server</th>
                  <th title="Begins with {repo}/ and may name {commit}, {path}, {start} and {end}">
                    File template
                  </th>
                  <th title="Begins with {repo}/ and may name {from} and {to}">
                    Comparison template
                  </th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {hosts.map((row, at) => (
                  <tr key={row.key}>
                    <td>
                      <input
                        {...notACredential}
                        type="text"
                        aria-label={`Remote of host ${at + 1}`}
                        placeholder="github.com"
                        value={row.remote}
                        onChange={(event) => editHost(row.key, { remote: event.target.value })}
                      />
                    </td>
                    <td>
                      <input
                        {...notACredential}
                        type="text"
                        aria-label={`Web address of host ${at + 1}`}
                        placeholder="https://github.com"
                        value={row.web}
                        onChange={(event) => editHost(row.key, { web: event.target.value })}
                      />
                    </td>
                    <td>
                      <select
                        aria-label={`Server of host ${at + 1}`}
                        value={row.style}
                        onChange={(event) =>
                          editHost(row.key, { style: event.target.value as Style })
                        }
                      >
                        {(Object.keys(STYLES) as Style[]).map((style) => (
                          <option key={style} value={style}>
                            {STYLES[style]}
                          </option>
                        ))}
                      </select>
                    </td>
                    {row.style === "custom" ? (
                      <>
                        <td>
                          <input
                            {...notACredential}
                            type="text"
                            aria-label={`File template of host ${at + 1}`}
                            placeholder="{repo}/blob/{commit}/{path}#L{start}"
                            value={row.file}
                            onChange={(event) => editHost(row.key, { file: event.target.value })}
                          />
                        </td>
                        <td>
                          <input
                            {...notACredential}
                            type="text"
                            aria-label={`Comparison template of host ${at + 1}`}
                            placeholder="{repo}/compare/{from}...{to}"
                            value={row.compare}
                            onChange={(event) => editHost(row.key, { compare: event.target.value })}
                          />
                        </td>
                      </>
                    ) : (
                      <td colSpan={2} className="hint">
                        {STYLES[row.style]}&rsquo;s own
                      </td>
                    )}
                    <td>
                      <button
                        type="button"
                        className="btn quiet"
                        aria-label={`Remove host ${at + 1}`}
                        onClick={() => {
                          setHosts((rows) => rows.filter((each) => each.key !== row.key));
                          setChanged(true);
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        )}
        <button
          type="button"
          className="btn quiet"
          onClick={() => {
            setHosts((rows) => [
              ...rows,
              { key: keyed(), remote: "", web: "", style: "github", file: "", compare: "" },
            ]);
            setChanged(true);
          }}
        >
          Add host
        </button>
      </div>

      <div className="card">
        <h3>Paths</h3>
        {paths.length === 0 ? (
          <Empty title="No paths." detail="No snippets are kept, and none are disclosed." />
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th title="From the top of the checkout. Empty is the whole product">Prefix</th>
                  <th title="Where an upload names none. Named with its branch">Repository</th>
                  <th title="Links open on it, marked approximate">Branch</th>
                  <th title="Inherited takes the longest shorter prefix that says, and none is off">
                    Snippets
                  </th>
                  <th title="Disclosed with the flaw of a lead moved into a case. Inherited works as for snippets">
                    In disclosure
                  </th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {paths.map((row, at) => (
                  <tr key={row.key}>
                    <td>
                      <input
                        {...notACredential}
                        type="text"
                        aria-label={`Prefix of path ${at + 1}`}
                        placeholder="src/sonic-swss"
                        value={row.prefix}
                        onChange={(event) => editPath(row.key, { prefix: event.target.value })}
                      />
                    </td>
                    <td>
                      <input
                        {...notACredential}
                        type="text"
                        aria-label={`Repository of path ${at + 1}`}
                        placeholder="github.com/sonic-net/sonic-swss"
                        value={row.remote}
                        onChange={(event) => editPath(row.key, { remote: event.target.value })}
                      />
                    </td>
                    <td>
                      <input
                        {...notACredential}
                        type="text"
                        aria-label={`Branch of path ${at + 1}`}
                        placeholder="master"
                        value={row.branch}
                        onChange={(event) => editPath(row.key, { branch: event.target.value })}
                      />
                    </td>
                    <td>
                      <select
                        aria-label={`Snippets of path ${at + 1}`}
                        value={row.snippets}
                        onChange={(event) =>
                          editPath(row.key, { snippets: event.target.value as Stated })
                        }
                      >
                        <option value="">Inherited</option>
                        <option value="yes">Kept</option>
                        <option value="no">Not kept</option>
                      </select>
                    </td>
                    <td>
                      <select
                        aria-label={`Disclosure of path ${at + 1}`}
                        value={row.disclosed}
                        onChange={(event) =>
                          editPath(row.key, { disclosed: event.target.value as Stated })
                        }
                      >
                        <option value="">Inherited</option>
                        <option value="yes">Disclosed</option>
                        <option value="no">Stripped</option>
                      </select>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn quiet"
                        aria-label={`Remove path ${at + 1}`}
                        onClick={() => {
                          setPaths((rows) => rows.filter((each) => each.key !== row.key));
                          setChanged(true);
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        )}
        <button
          type="button"
          className="btn quiet"
          onClick={() => {
            setPaths((rows) => [
              ...rows,
              { key: keyed(), prefix: "", remote: "", branch: "", snippets: "", disclosed: "" },
            ]);
            setChanged(true);
          }}
        >
          Add path
        </button>
      </div>

      {save.error != null && (
        <Failed error={save.error} what="The repository settings were not saved." />
      )}
      <p>
        <button
          type="button"
          className="btn"
          disabled={!changed || save.isPending}
          onClick={() => save.mutate(stated(hosts, paths))}
        >
          Save
        </button>
      </p>
    </>
  );
}

// The rows as the server takes them: trimmed, with an empty optional field
// left out, and a template sent only for a custom host.
function stated(hosts: HostRow[], paths: PathRow[]): Settings {
  return {
    hosts: hosts.map((row): Host => {
      const custom = row.style === "custom";
      return {
        remote: row.remote.trim(),
        web: row.web.trim(),
        style: row.style,
        ...(custom && row.file.trim() ? { file_template: row.file.trim() } : {}),
        ...(custom && row.compare.trim() ? { compare_template: row.compare.trim() } : {}),
      };
    }),
    paths: paths.map((row): Path => {
      const snippets = valueOf(row.snippets);
      const disclosed = valueOf(row.disclosed);
      return {
        prefix: row.prefix.trim(),
        ...(row.remote.trim() ? { remote: row.remote.trim() } : {}),
        ...(row.branch.trim() ? { branch: row.branch.trim() } : {}),
        ...(snippets !== undefined ? { snippets } : {}),
        ...(disclosed !== undefined ? { disclosed_snippets: disclosed } : {}),
      };
    }),
  };
}
