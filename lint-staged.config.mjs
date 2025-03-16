// https://github.com/lint-staged/lint-staged#using-js-configuration-files
const MODULES = [
  { name: "web", parent: "apps" },
  { name: "docs", parent: "apps" },
  { name: "@repo/design-system", parent: "packages" },
];

const typeCheckConfigs = MODULES.reduce(
  (prev, { name, parent }) => ({
    ...prev,
    [`./${parent}/${name}/**/*.{ts,tsx}`]: () => [
      `echo "🚀 Running type-check for ${name}..."`,
      `pnpm run --filter=${name} type-check`,
      `echo "✅ Type-check passed for ${name}"`,
    ],
  }),
  {}
);

const lintConfigs = MODULES.reduce(
  (prev, { name, parent }) => ({
    ...prev,
    [`./${parent}/${name}/**/*.{ts,tsx}`]: () => [
      `echo "🚀 Running lint for ${name}..."`,
      `pnpm run --filter=${name} lint`,
      `echo "✅ Lint passed for ${name}"`,
    ],
  }),
  {}
);

export default {
  // linting
  // ...lintConfigs,
  "*.{js,ts,tsx}": ["npm run format", "pnpm run lint"],

  // type check
  ...typeCheckConfigs,
};
