import { defineConfig } from 'vite';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import tailwindcss from '@tailwindcss/vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig(({ mode }) => {
  const isLocal = mode === 'standalone';

  return {
    plugins: [
      tailwindcss(),
      ...(isLocal ? [viteSingleFile()] : []),
    ],

    base: isLocal ? './' : '/',

    define: isLocal
      ? { 'import.meta.env.VITE_LOCAL_MODE': 'true' }
      : {},

    resolve: {
      alias: [
        {
          // @carto/api is the switchable storage adapter.
          // In standalone builds: localStorage (no Amplify).
          // In cloud builds: Cognito + API Gateway.
          find: '@carto/api',
          replacement: isLocal
            ? resolve(__dirname, 'src/js/data/adapters/local.js')
            : resolve(__dirname, 'src/js/data/adapters/cloud.js'),
        },
      ],
    },

    build: {
      outDir: isLocal ? 'dist-local' : 'dist',
      rollupOptions: {
        input: isLocal
          ? resolve(__dirname, 'index.local.html')
          : {
              main:  resolve(__dirname, 'index.html'),
              login: resolve(__dirname, 'login.html'),
            },
      },
    },
  };
});
