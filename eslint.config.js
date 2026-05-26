import globals from "globals";

export default [
    {
        files: ["frontend/js/**/*.js"],
        ignores: ["frontend/js/lib/**"],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: "script",
            globals: {
                ...globals.browser,
                // IIFE module globals exposed on the page
                Config: "readonly",
                Auth: "readonly",
                Api: "readonly",
                App: "readonly",
                Crypto: "readonly",
                Files: "readonly",
                Upload: "readonly",
                Download: "readonly",
                Teams: "readonly",
                Shares: "readonly",
                Admin: "readonly",
                AccessLogs: "readonly",
                Permissions: "readonly",
                Wizard: "readonly",
                TransferManager: "readonly",
                Utils: "readonly",
                Theme: "readonly",
                StepUp: "readonly",
                // standalone helpers in crypto.js used across files
                hashPayload: "readonly",
                computeOpaqueStepUpHmac: "readonly",
            },
        },
        rules: {
            "no-unused-vars": ["error", {
                varsIgnorePattern: "^(_|[A-Z])",  // _ prefix = intentional; PascalCase = IIFE module globals
                argsIgnorePattern: "^_",
                caughtErrorsIgnorePattern: "^_",
                args: "after-used",
            }],
            "no-undef": "error",
            "no-var": "error",
            "prefer-const": "error",
            "eqeqeq": ["error", "always", { "null": "ignore" }],
            "no-console": "off",
        },
    },
];
