import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import nodeResolve from "@rollup/plugin-node-resolve";
import replace from "@rollup/plugin-replace";
import peerDepsExternal from "rollup-plugin-peer-deps-external";
import { terser } from "rollup-plugin-terser";

import packageJson from "./package.json";

const env = process.env.NODE_ENV;
const extensions = [".js", ".cjs", ".mjs"];
const minify_cjs_Extension = (pathToFile) =>
  pathToFile.replace(/\.cjs$/, ".min.cjs");
const minify_js_Extension = (pathToFile) =>
  pathToFile.replace(/\.js$/, ".min.js");

const EXTERNALS = [
  "compression",
  "cors",
  "dotenv-defaults",
  "esm",
  "express",
  "express-fileupload",
  "helmet",
  "knex",
  "log4js",
  "moment",
  "path-to-regexp",
  "socket.io",
  "pg",
  "uuid",
  "lodash",
];

export default [
  {
    input: packageJson.source,
    output: [
      {
        file: packageJson.main,
        format: "cjs",
        exports: "named" /** Disable warning for default imports */,
        sourcemap: true,
      },
      {
        file: minify_cjs_Extension(packageJson.main),
        format: "cjs",
        exports: "named" /** Disable warning for default imports */,
        plugins: [terser()],
      },
      {
        file: packageJson.module,
        format: "es",
        sourcemap: true,
      },
      {
        file: minify_js_Extension(packageJson.module),
        format: "es",
        plugins: [terser()],
      },
    ],
    external: EXTERNALS,
    plugins: [
      json(),
      peerDepsExternal(),
      nodeResolve({ extensions }),
      replace({
        preventAssignment: true,
        "process.env.NODE_ENV": JSON.stringify(env),
      }),
      commonjs({
        dynamicRequireTargets: [
          // include using a glob pattern (either a string or an array of strings)
        ],
      }),
    ],
  },
];
