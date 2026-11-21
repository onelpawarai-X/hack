import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [
      react(),
      tailwindcss(),
      // Copies src/assets into dist/ so root-relative URLs like
      // "/src/assets/images/..." (e.g. generate_image output) still resolve
      // in production builds. Do not remove.
      {
        name: 'copy-unbundled-src-assets',
        apply: 'build',
        closeBundle(error?: Error): void {
          if (error) {
            return;
          }
          const distDir = path.resolve(__dirname, 'dist');
          const srcAssets = path.resolve(__dirname, 'src/assets');
          const distAssets = path.resolve(distDir, 'src/assets');
          if (fs.existsSync(distDir) && fs.existsSync(srcAssets)) {
            fs.cpSync(srcAssets, distAssets, {recursive: true, force: true});
          }
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    build: {
      chunkSizeWarningLimit: 700,
      rolldownOptions: {
        output: {
          codeSplitting: {
            groups: [
              {
                name: 'vendor-react',
                test: /node_modules[\\/](react|react-dom|scheduler|react-is)[\\/]/,
                priority: 30,
              },
              {
                name: 'vendor-map',
                test: /node_modules[\\/](leaflet|react-leaflet)[\\/]/,
                priority: 20,
              },
              {
                name: 'vendor-charts',
                test: /node_modules[\\/](recharts|d3-[^\\/]+|victory-[^\\/]+)[\\/]/,
                priority: 20,
              },
              {
                name: 'vendor-pdf',
                test: /node_modules[\\/](jspdf|html2canvas|dompurify)[\\/]/,
                priority: 20,
              },
              {
                name: 'vendor-motion',
                test: /node_modules[\\/](motion|framer-motion)[\\/]/,
                priority: 20,
              },
              {
                name: 'vendor',
                test: /node_modules[\\/]/,
                priority: 10,
              },
            ],
          },
        },
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
      allowedHosts: [
        '.prod-runtime.all-hands.dev',
        'localhost',
        '127.0.0.1',
      ],
    },
  };
});
