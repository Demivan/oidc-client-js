import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import babel from 'rollup-plugin-babel';
import uglify from 'rollup-plugin-uglify';
import pkg from './package.json';

export default [
	// browser-friendly UMD build
	{
		input: 'index.js',
		output: {
			name: 'Oidc',
			file: pkg.browser,
			format: 'umd',
			exports: 'named'
		},
		plugins: [
			resolve({
				browser: true
			}),
			commonjs(),
			babel({
				exclude: 'node_modules/**'
			}),
			uglify()
		]
	},

	// CommonJS (for Node) and ES module (for bundlers) build.
	{
		input: 'index.js',
		external: [
			'base64-js',
			'core-js',
			'crypto-js',
			'eslint',
			'jsbn',
			'crypto-js/sha256',
			'core-js/es6/promise',
			'core-js/fn/function/bind',
			'core-js/fn/object/assign',
			'core-js/fn/array/find',
			'core-js/fn/array/some',
			'core-js/fn/array/is-array',
			'core-js/fn/array/splice'
		],
		output: [
			{ file: pkg.main, format: 'cjs', exports: 'named' },
			{ file: pkg.module, format: 'es', exports: 'named' }
		]
	}
];
