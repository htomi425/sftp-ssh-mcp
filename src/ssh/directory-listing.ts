export interface DirectoryEntry {
  filename: string;
  longname: string;
}

export function formatDirectoryListing(entries: readonly DirectoryEntry[]): string {
  return entries.map((entry) => `${entry.filename} (${entry.longname})`).join('\n');
}
