import eslint from '@eslint/js';
import importPlugin from 'eslint-plugin-import';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['eslint.config.mjs', 'webpack.config.cjs'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  eslintPluginPrettierRecommended,
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      importPlugin.flatConfigs.recommended,
      importPlugin.flatConfigs.typescript,
    ],
    rules: {
      // ✅ import 정렬 규칙 추가
      'import/order': [
        'error',
        {
          groups: [
            'builtin', // Node.js 기본 모듈 (fs, path 등)
            'external', // npm 패키지 (express, lodash 등)
            'internal', // 프로젝트 내부 모듈 (@/ 경로 등)
            'parent', // 부모 디렉토리 모듈 (../)
            'sibling', // 같은 폴더 내 모듈 (./)
            'index', // 현재 폴더의 index 파일
          ],
          'newlines-between': 'always', // ✅ 그룹 간 개행 추가
          alphabetize: { order: 'asc', caseInsensitive: true }, // 알파벳순 정렬
          pathGroups: [
            {
              pattern: '@/**', // 내부 모듈을 `internal` 그룹에 포함
              group: 'internal',
              position: 'after',
            },
          ],
          pathGroupsExcludedImportTypes: ['builtin'],
        },
      ],
    },
  },
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      ecmaVersion: 5,
      sourceType: 'module',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      'import/resolver': {
        node: {
          paths: ['.'],
        },
      },
    },
  },
);
