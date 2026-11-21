module.exports = {
  apps: [
    {
      name: 'sentinelglobe',
      cwd: __dirname,
      script: './node_modules/tsx/dist/cli.mjs',
      args: 'server.ts',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_memory_restart: '1G',
      time: true,
      env: {
        NODE_ENV: 'production',
        PORT: '12001',
      },
      out_file: './logs/pm2-out.log',
      error_file: './logs/pm2-error.log',
      merge_logs: true,
    },
  ],
};
