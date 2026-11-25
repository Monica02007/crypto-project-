import fs from 'node:fs';
import path from 'node:path';
import {
  getBuiltInDataset,
  getDefaultBuiltInDataset,
  parseUrlDatasetCsv,
} from '../core/datasetData.js';

export { getBuiltInDataset, parseUrlDatasetCsv };

export function loadLocalDatasetIfExists() {
  const customCsvPath = path.resolve(process.cwd(), 'data/url-dataset.csv');
  if (fs.existsSync(customCsvPath)) {
    try {
      const content = fs.readFileSync(customCsvPath, 'utf-8');
      const parsed = parseUrlDatasetCsv(content);
      return {
        samples: parsed.samples,
        name: `Local CSV (${parsed.formatDetected})`,
      };
    } catch {
      // Fallback cleanly to built-in starter dataset
    }
  }
  return getDefaultBuiltInDataset();
}
