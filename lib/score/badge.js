module.exports.badgeMarkdown = function badgeMarkdown(score) {
  return `![Shrine Score ${score}/100](https://img.shields.io/badge/shrine-${score}-blue)`;
}
