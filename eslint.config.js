import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: "module",
        },
        rules: {
            // Allow any for legacy code - migrate gradually
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/explicit-function-return-type": "off",
            "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
            "no-console": ["warn", { allow: ["warn", "error"] }],
            // Allow case block declarations
            "no-case-declarations": "off",
        },
    },
    {
        ignores: ["**/dist/**", "**/node_modules/**", "**/*.js", "**/*.mjs"],
    }
);
