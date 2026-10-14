// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// An identity the server reads whole after a bare @: letters, digits and . _ :
// @ -, starting and ending with a letter or digit. The server trims a trailing
// . _ : - as the end of a sentence.
const plain = /^[A-Za-z0-9](?:[A-Za-z0-9._:@-]*[A-Za-z0-9])?$/;

// The characters inside the brackets that markdown would read as something
// other than text, or that would end the brackets. Each is written after a
// backslash, which the server takes off again.
const special = /[\\<>*_`[\]~]/g;

// mentionOf is how the editor writes a mention of an identity. Anything outside
// the plain form is delimited, with the bracket escaped so markdown keeps it as
// text, and the server reads the whole identity rather than a prefix of it.
export function mentionOf(identity: string): string {
  if (plain.test(identity)) return `@${identity}`;
  return `@\\<${identity.replace(special, (c) => `\\${c}`)}>`;
}
