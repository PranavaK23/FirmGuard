import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e', workers: 1, timeout: 60000, fullyParallel: false,
  use: {baseURL:'http://127.0.0.1:8765', headless:true, screenshot:'only-on-failure'},
  webServer: {command:'python ../scripts/serve_test.py',url:'http://127.0.0.1:8765/api/health',reuseExistingServer:false,timeout:30000},
});
