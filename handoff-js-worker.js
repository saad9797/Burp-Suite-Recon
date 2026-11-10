const { parentPort, workerData } = require("node:worker_threads");
const { analyzeJavaScript } = require("./handoff-analysis");
try {
  const result = analyzeJavaScript(
    Buffer.from(workerData.bytes),
    "__content__",
    workerData.options,
  );
  parentPort.postMessage({ result });
} catch (error) {
  parentPort.postMessage({ error: error.message });
}
