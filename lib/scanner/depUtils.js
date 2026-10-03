function daysSince(dateStr) {
  const now = new Date();
  const date = dateStr instanceof Date ? dateStr : new Date(dateStr);
  const diff = now - date;
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

function formatDate(dateStr) {
  return new Date(dateStr).toISOString().split('T')[0];
}

function parseVersion(version) {
  return version.replace(/^v/, '');
}

module.exports = {
  daysSince,
  formatDate,
  parseVersion
};