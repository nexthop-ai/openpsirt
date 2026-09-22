// The rail's and the bar's icons: stroke paths on a 24-unit grid, the
// mockup's, so a screen is found by its shape as well as its word.

const PATHS: Record<string, string> = {
  home: '<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/>',
  inbox: '<path d="M4 4h16v16H4z"/><path d="M4 14h5l1.5 2h3L15 14h5"/>',
  letter: '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="m3.5 6 8.5 7 8.5-7"/>',
  nobody:
    '<circle cx="10" cy="8" r="3.5"/><path d="M3.5 20a6.5 6.5 0 0 1 13 0"/><path d="m17 8 4 4m0-4-4 4"/>',
  people:
    '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7"/><path d="M21.5 20a6.5 6.5 0 0 0-4.5-6.2"/>',
  bug: '<path d="M9 9V7a3 3 0 0 1 6 0v2"/><rect x="7" y="9" width="10" height="11" rx="5"/><path d="M3 13h4M17 13h4M4 19l3-2M20 19l-3-2M5 7l3 2M19 7l-3 2"/>',
  tree: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10M8 5.5c4 0 6 2 8 5M8 18.5c4 0 6-2 8-5"/>',
  scan: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 4v2M12 18v2M4 12h2M18 12h2"/>',
  box: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5 12 12l8-4.5M12 12v9"/>',
  branch:
    '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 7v10M18 10c0 4-4 4-8 5"/>',
  layers: '<path d="m12 4 9 5-9 5-9-5z"/><path d="m3 14 9 5 9-5"/>',
  link: '<path d="M10.5 13.5a4 4 0 0 0 5.7 0l2.8-2.8a4 4 0 0 0-5.7-5.7l-1.4 1.4"/><path d="M13.5 10.5a4 4 0 0 0-5.7 0L5 13.3a4 4 0 0 0 5.7 5.7l1.4-1.4"/>',
  paperclip:
    '<path d="M19.5 11.5 12 19a4.5 4.5 0 0 1-6.4-6.4l7.7-7.7a3 3 0 0 1 4.2 4.2l-7.6 7.6a1.5 1.5 0 0 1-2.1-2.1l6.9-6.9"/>',
  // A screen is found by its shape, which only works while no two share one.
  // These four were added because four pairs did: teams and people drew the
  // byte-identical glyph, as did settings and routing, the record and an
  // inventory, and recording a flaw and a finding.
  teams:
    '<circle cx="12" cy="6.5" r="2.8"/><circle cx="4.8" cy="10.5" r="2.2"/><circle cx="19.2" cy="10.5" r="2.2"/><path d="M6.5 19.5a5.5 5.5 0 0 1 11 0"/><path d="M1.5 17.2a3.8 3.8 0 0 1 3.3-3.4"/><path d="M22.5 17.2a3.8 3.8 0 0 0-3.3-3.4"/>',
  roles:
    '<circle cx="9.5" cy="8" r="3.5"/><path d="M3 20a6.5 6.5 0 0 1 10.5-5.1"/><circle cx="17" cy="15" r="2.5"/><path d="m18.8 16.8 3.2 3.2M20.6 18.6l-1.2 1.2"/>',
  gear: '<circle cx="12" cy="12" r="3.2"/><path d="M12 2.6v2.8M12 18.6v2.8M21.4 12h-2.8M5.4 12H2.6M18.6 5.4l-2 2M7.4 16.6l-2 2M18.6 18.6l-2-2M7.4 7.4l-2-2"/>',
  route:
    '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="M7 12h3"/><path d="M10 12c0-3.6 2.3-6 7-6"/><path d="M10 12c0 3.6 2.3 6 7 6"/>',
  ledger:
    '<path d="M5.5 4h12a1 1 0 0 1 1 1v15h-12a1 1 0 0 1-1-1z"/><path d="M5.5 16.5h13"/><path d="M9 8h6M9 11h6"/>',
  chart: '<path d="M4 20h16"/><path d="M7.5 20v-5.5M12 20V5.5M16.5 20v-8.5"/>',
  flag: '<path d="M6 21V3.5"/><path d="M6 4.5h11l-2.2 3.6L17 11.7H6"/>',
  record:
    '<path d="M6.5 3H14l4.5 4.5V21h-12z"/><path d="M14 3v4.5h4.5"/><path d="M12.5 12v5M10 14.5h5"/>',
  sliders:
    '<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21h4"/>',
  // A sheet that leaves. The record's sheet carries a plus because it is
  // something being written down; this one carries an arrow because it is
  // something being sent.
  advisory:
    '<path d="M4 4.5h10v15H4z"/><path d="M7 8.5h4M7 12h4M7 15.5h2"/><path d="M16 12h5"/><path d="m18.5 9.5 2.5 2.5-2.5 2.5"/>',
  upload: '<path d="M12 16V4M6 10l6-6 6 6"/><path d="M4 20h16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  // The other half of the pair a row's preview control is drawn with.
  minus: '<path d="M5 12h14"/>',
  quote: '<path d="M5 5v14"/><path d="M10 8h9M10 12h9M10 16h5"/>',
  triage: '<path d="M4 7h16M4 12h10M4 17h7"/><path d="m16 15 2 2 4-4"/>',
  pulse:
    '<rect x="3.5" y="4" width="17" height="6" rx="1.5"/><path d="M3.5 14.5h4l1.5-3 2.5 6 2-3h7"/><path d="M3.5 20h17"/>',
  shield:
    '<path fill="currentColor" stroke="none" d="M12 2.2 4.6 5.9v5.4c0 4.6 3.1 8.4 7.4 10.5 4.3-2.1 7.4-5.9 7.4-10.5V5.9Z" opacity=".35"/><path fill="currentColor" stroke="none" d="M12 4.2 6.4 7v4.3c0 3.5 2.3 6.5 5.6 8.2Z"/>',
};

export function Icon({ name, size }: { name: string; size?: number }) {
  const markup = PATHS[name] ?? "";
  return (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
      width={size}
      height={size}
      // The stroke an icon is drawn with, carried here so a caller with no
      // rule of its own still gets one. A scoped rule overrides these.
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      // Fixed markup from the table above, never from anything typed.
      dangerouslySetInnerHTML={{ __html: markup }}
    />
  );
}
