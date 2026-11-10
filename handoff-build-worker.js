const { parentPort, workerData } = require("node:worker_threads");
const Database = require("better-sqlite3");
const { mountHandoff } = require("./handoff");
const db = new Database(workerData.database, { timeout: 5000 });
db.pragma("journal_mode = WAL");
const app = { get() {}, post() {} };
(async () => {
  try {
    const engine = mountHandoff(app, {
      db,
      workerMode: true,
      onProgress: (p) => parentPort.postMessage({ progress: p }),
    });
    const result = await engine.build(workerData.input);
    parentPort.postMessage({ packageId: result.id });
  } catch (e) {
    parentPort.postMessage({ error: e.message });
  } finally {
    db.close();
  }
})();
