import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { terser } from 'rollup-plugin-terser';
import localResolve from '@haensl/rollup-plugin-local-resolve';
import pkg from './package.json';

const production = !process.env.ROLLUP_WATCH;
export default [

    {
        input: 'src/index.js',
        output: [
            { file: pkg.main, format: 'cjs' },
            // { file: pkg.main, format: 'es' }
        ],
        plugins: [
            json(),
            // nodeResolve({
            //     preferBuiltins: true
            // }), // tells Rollup how to find date-fns in node_modules
            localResolve(),
            // commonjs(), // converts date-fns to ES modules
            //production && terser() // minify, but only in production
        ]
    }
];