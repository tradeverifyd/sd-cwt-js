/**
 * Build script for browser bundle
 * 
 * Creates docs/js/sd-cwt.js for use in the browser playground
 */

import * as esbuild from 'esbuild';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

// Plugin to replace node:crypto with browser-compatible version
const browserPolyfillPlugin = {
  name: 'browser-polyfills',
  setup(build) {
    // Redirect node:crypto imports to our browser shim
    build.onResolve({ filter: /^node:crypto$|^crypto$/ }, () => {
      return { path: join(rootDir, 'src/crypto-browser.js') };
    });
    
    // Redirect node:buffer or buffer to our shim
    build.onResolve({ filter: /^node:buffer$|^buffer$/ }, () => {
      return { path: join(rootDir, 'src/buffer-shim.js') };
    });
  },
};

async function build() {
  console.log('Building browser bundle...');

  try {
    const result = await esbuild.build({
      entryPoints: [join(rootDir, 'src/browser.js')],
      bundle: true,
      format: 'iife',
      globalName: 'SDCWT',
      outfile: join(rootDir, 'docs/js/sd-cwt.js'),
      platform: 'browser',
      target: ['es2020'],
      sourcemap: true,
      minify: false, // Keep readable for debugging
      metafile: true,
      plugins: [browserPolyfillPlugin],
      define: {
        'process.env.NODE_ENV': '"production"',
        'global': 'globalThis',
      },
      inject: [join(rootDir, 'src/buffer-shim.js')],
    });

    // Print bundle size
    const outputs = result.metafile.outputs;
    for (const [file, info] of Object.entries(outputs)) {
      if (file.endsWith('.js')) {
        const sizeKB = (info.bytes / 1024).toFixed(1);
        console.log(`  ${file}: ${sizeKB} KB`);
      }
    }

    console.log('Build complete!');
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

build();

