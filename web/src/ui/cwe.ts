// What kind of flaw it is, by the classification the world uses.
//
// Suggested, never restricted. Anything may be recorded. A picker that
// refused an identifier it had not heard of would refuse next year's, and the
// point of recording these is to make a set of findings comparable to things
// outside this deployment — which is served by recording what somebody meant,
// not by having an opinion.
//
// The names are here rather than fetched: they are a fixed vocabulary somebody
// else maintains, and a screen that could not name a weakness because a
// network call failed would be worse than one that names a short list. What is
// here is the ones a real backlog is made of — the four most common in a
// kernel image are a memory leak, a race, improper locking and a double free,
// and none of them was named.

export type Named = { id: string; name: string };

export const COMMON: Named[] = [
  { id: "CWE-20", name: "Improper input validation" },
  { id: "CWE-22", name: "Path traversal" },
  { id: "CWE-59", name: "Link following" },
  { id: "CWE-77", name: "Command injection" },
  { id: "CWE-78", name: "OS command injection" },
  { id: "CWE-79", name: "Cross-site scripting" },
  { id: "CWE-89", name: "SQL injection" },
  { id: "CWE-94", name: "Code injection" },
  { id: "CWE-119", name: "Buffer overflow" },
  { id: "CWE-120", name: "Buffer copy without checking the size of the input" },
  { id: "CWE-121", name: "Stack-based buffer overflow" },
  { id: "CWE-122", name: "Heap-based buffer overflow" },
  { id: "CWE-125", name: "Out-of-bounds read" },
  { id: "CWE-190", name: "Integer overflow" },
  { id: "CWE-191", name: "Integer underflow" },
  { id: "CWE-193", name: "Off-by-one error" },
  { id: "CWE-200", name: "Exposure of sensitive information" },
  { id: "CWE-269", name: "Improper privilege management" },
  { id: "CWE-284", name: "Improper access control" },
  { id: "CWE-287", name: "Improper authentication" },
  { id: "CWE-295", name: "Improper certificate validation" },
  { id: "CWE-306", name: "Missing authentication for a critical function" },
  { id: "CWE-327", name: "Use of a broken or risky cryptographic algorithm" },
  { id: "CWE-330", name: "Use of insufficiently random values" },
  { id: "CWE-352", name: "Cross-site request forgery" },
  { id: "CWE-362", name: "Race condition" },
  { id: "CWE-369", name: "Divide by zero" },
  { id: "CWE-400", name: "Uncontrolled resource consumption" },
  { id: "CWE-401", name: "Missing release of memory after effective lifetime" },
  { id: "CWE-404", name: "Improper resource shutdown or release" },
  { id: "CWE-415", name: "Double free" },
  { id: "CWE-416", name: "Use after free" },
  { id: "CWE-434", name: "Unrestricted upload of a dangerous file" },
  { id: "CWE-457", name: "Use of an uninitialized variable" },
  { id: "CWE-476", name: "Null pointer dereference" },
  { id: "CWE-502", name: "Deserialization of untrusted data" },
  { id: "CWE-522", name: "Insufficiently protected credentials" },
  { id: "CWE-601", name: "Open redirect" },
  { id: "CWE-611", name: "XML external entity reference" },
  { id: "CWE-617", name: "Reachable assertion" },
  { id: "CWE-667", name: "Improper locking" },
  { id: "CWE-681", name: "Incorrect conversion between numeric types" },
  { id: "CWE-732", name: "Incorrect permission assignment for a critical resource" },
  { id: "CWE-770", name: "Allocation of resources without limits or throttling" },
  { id: "CWE-772", name: "Missing release of resource after effective lifetime" },
  { id: "CWE-787", name: "Out-of-bounds write" },
  { id: "CWE-798", name: "Hard-coded credentials" },
  { id: "CWE-835", name: "Infinite loop" },
  { id: "CWE-843", name: "Type confusion" },
  { id: "CWE-862", name: "Missing authorization" },
  { id: "CWE-863", name: "Incorrect authorization" },
  { id: "CWE-908", name: "Use of an uninitialized resource" },
  { id: "CWE-918", name: "Server-side request forgery" },
];

const NAMES = new Map(COMMON.map((each) => [each.id, each.name]));

// The two words a feed uses to say it has no classification. They are not
// classifications and drawing them as one tells a reader the flaw has been
// categorized as "other", which nobody decided.
const UNCLASSIFIED = new Set(["NVD-CWE-OTHER", "NVD-CWE-NOINFO"]);

export function unclassified(id: string): boolean {
  return UNCLASSIFIED.has(id.trim().toUpperCase());
}

// What this kind of flaw is called, where the list carries it.
export function nameOf(id: string): string {
  return NAMES.get(id.trim().toUpperCase()) ?? "";
}

// Where to read about it, built from the identifier rather than stored — the
// same way an issue's own record and a package's page are. Nothing is fetched.
// An identifier that is not a CWE number has nowhere to go, which includes the
// two words above.
export function readAbout(id: string): string | null {
  const number = /^CWE-(\d+)$/.exec(id.trim().toUpperCase());
  if (!number) return null;
  return `https://cwe.mitre.org/data/definitions/${number[1]}.html`;
}
