import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { PhishingDetectionService } from './src/server/analyzer.ts';

async function startServer(): Promise<void> {
  const app = express();
  const port = Number(process.env.PORT ?? 3000);
  const service = new PhishingDetectionService();

  app.use(express.json({ limit: '5mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'veriurl-hybrid-phishing-detector' });
  });

  app.post('/api/analyze', (req, res) => {
    try {
      const { url, forceMlInspection } = req.body ?? {};
      if (typeof url !== 'string' || !url.trim()) {
        res.status(400).json({ error: 'Please enter a valid URL to analyze.' });
        return;
      }
      const result = service.analyzeUrl(url, {
        forceMlInspection: Boolean(forceMlInspection),
      });
      res.json(result);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Failed to analyze URL.';
      res.status(400).json({ error: message });
    }
  });

  app.get('/api/threats', (_req, res) => {
    res.json({ threats: service.threatStore.getAll() });
  });

  app.post('/api/threats', (req, res) => {
    try {
      const { mode, url, sha256, labelUrl, source, category, targetBrand } =
        req.body ?? {};
      if (mode === 'hash') {
        const record = service.threatStore.addByHash({
          sha256: String(sha256 ?? ''),
          labelUrl,
          source,
          category,
          targetBrand,
        });
        res.status(201).json({ threat: record });
        return;
      }
      const record = service.threatStore.addByUrl({
        url: String(url ?? ''),
        source,
        category,
        targetBrand,
      });
      res.status(201).json({ threat: record });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Could not add threat entry.';
      res.status(400).json({ error: message });
    }
  });

  app.delete('/api/threats/:sha256', (req, res) => {
    const deleted = service.threatStore.remove(req.params.sha256);
    if (!deleted) {
      res.status(404).json({ error: 'Threat hash not found.' });
      return;
    }
    res.json({ deleted: true });
  });

  app.post('/api/threats/reset', (_req, res) => {
    const threats = service.threatStore.resetToStarterSeed();
    res.json({ threats });
  });

  app.get('/api/models', (_req, res) => {
    res.json(service.getModelReport());
  });

  app.post('/api/models/evaluate-csv', (req, res) => {
    try {
      const { csvText, datasetName } = req.body ?? {};
      if (typeof csvText !== 'string' || !csvText.trim()) {
        res.status(400).json({ error: 'CSV content is empty.' });
        return;
      }
      const report = service.evaluateCsvDataset(csvText, datasetName);
      res.json(report);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Failed to parse CSV dataset.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/models/revert', (_req, res) => {
    const report = service.revertToBuiltInDataset();
    res.json(report);
  });

  app.get('/api/history', (_req, res) => {
    res.json({ history: service.getHistory() });
  });

  app.delete('/api/history', (_req, res) => {
    service.clearHistory();
    res.json({ cleared: true });
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('/{*splat}', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`VeriURL server listening on http://localhost:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start VeriURL server:', err);
  process.exit(1);
});
