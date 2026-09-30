const {baseConfig} = require('@virmator/spellcheck/configs/cspell.config.base.cjs');

module.exports = {
    ...baseConfig,
    ignorePaths: [
        ...baseConfig.ignorePaths,
        'packages/auth-vir/src/generated/',
    ],
    words: [
        ...baseConfig.words,
    ],
};
