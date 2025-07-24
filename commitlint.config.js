// commitlint.config.js
module.exports = {
    extends: ["@commitlint/config-conventional"],
    formatter: "@commitlint/format",
    rules: {
        "body-max-line-length": [2, "always", 500],
    },
    defaultIgnores: true,
};
