// What tells a password manager that a field is not a credential.
//
// Settings, filters and declaration forms are full of short text and number
// boxes, and a password manager offers to fill several of them: LastPass and
// 1Password both guess from shape and proximity rather than from anything the
// page says, so a box called "max size" beside a box called "quiet after" is
// as good a guess as any. What stops it is saying so, and each manager reads
// its own attribute — there is no common one, so all four are set.
//
// `autoComplete="off"` alone does not do it. Browsers ignore it for saved
// logins by design, and the extensions never read it in the first place.
export const notACredential = {
  autoComplete: "off",
  "data-lpignore": "true",
  "data-1p-ignore": "true",
  "data-bwignore": "true",
  "data-form-type": "other",
} as const;
