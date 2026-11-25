import { initializeAppRuntime } from '../src/server.js';

let runtimePromise = null;

function getServerlessRuntime() {
  if (!runtimePromise) {
    runtimePromise = initializeAppRuntime().catch((err) => {
      runtimePromise = null;
      throw err;
    });
  }
  return runtimePromise;
}

export default async function handler(req, res) {
  const { handler: appHandler } = await getServerlessRuntime();
  return appHandler(req, res);
}
