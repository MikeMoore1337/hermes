import {defineConfig,devices} from "@playwright/test";
export default defineConfig({
 testDir:"./qa",timeout:30000,workers:1,retries:0,
 reporter:[["list"]],
 use:{baseURL:"http://127.0.0.1:9133",trace:"retain-on-failure",screenshot:"only-on-failure"},
 projects:[{name:"chromium",use:{...devices["Desktop Chrome"],browserName:"chromium",launchOptions:process.env.HERMES_CHROMIUM_EXECUTABLE?{executablePath:process.env.HERMES_CHROMIUM_EXECUTABLE}:{}}}],
 webServer:{command:(process.platform==="win32"?"py -3":"python3")+" -m control_center.server --port 9133",cwd:"../..",
   url:"http://127.0.0.1:9133/healthz",timeout:20000,reuseExistingServer:false,
   stdout:"pipe",stderr:"pipe"},
 outputDir:"./.artifacts/playwright-results"
});
