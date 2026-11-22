// The project label of an artifact: a group name, and for Shahin's report_publish the owner's user name.
import { ApiError } from './errors.js';

// A plain name: 1-64 letters, digits, marks, spaces and . _ - starting with a letter or digit.
export const PROJECT_RE = /^[\p{L}\p{N}][\p{L}\p{N}\p{M} ._-]{0,63}$/u;
// PLATFORM-834: an e-mail as the user name (sites whose identity provider signs people in by e-mail). The local part
// starts and ends with a letter or digit; the domain is two or more dot-separated labels, each starting and ending with a
// letter or digit; no "..", no space, slash, %, # or ?; at most 254 characters, as an e-mail address.
const LABEL = '[\\p{L}\\p{N}](?:[\\p{L}\\p{N}-]*[\\p{L}\\p{N}])?';
const EMAIL_PROJECT_RE = new RegExp(`^[\\p{L}\\p{N}](?:[\\p{L}\\p{N}._+-]*[\\p{L}\\p{N}])?@${LABEL}(?:\\.${LABEL})+$`, 'u');
const EMAIL_MAX = 254;

function isEmailProject(project) {
  return project.length <= EMAIL_MAX && !project.includes('..') && EMAIL_PROJECT_RE.test(project);
}

// Returns a trimmed project name, or '' to clear it. null/'' both mean clear.
export function parseProject(value) {
  if (value === null) return '';
  if (typeof value !== 'string') {
    throw new ApiError(400, 'project must be a string');
  }
  const project = value.trim().replace(/\s+/g, ' '); // collapse internal whitespace
  if (!project) return '';
  if (!PROJECT_RE.test(project) && !isEmailProject(project)) {
    throw new ApiError(
      400,
      'project must be 1–64 chars of letters, digits, spaces, and - _ . (starting with a letter or digit), or an e-mail address',
    );
  }
  return project;
}
