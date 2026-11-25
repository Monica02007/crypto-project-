# VeriURL — Hybrid Phishing Website Detection System

Pure **HTML, CSS, and JavaScript** web application combining deterministic URL normalization and SHA-256 threat hash lookup with classical machine learning (TF-IDF + Multinomial Naive Bayes and L2 Logistic Regression).

## Running on GitHub Pages (Static Hosting)

VeriURL automatically detects when no Node.js backend is present and runs the complete SHA-256 hashing, URL normalization, TF-IDF + Multinomial Naive Bayes, Logistic Regression, CSV dataset trainer, and `localStorage` persistence directly in your browser.

**Option A — Zero-build GitHub Pages (fastest):**
1. Push all project files to your GitHub repository (including `index.html`, `.nojekyll`, and `src/`).
2. Go to **Settings -> Pages -> Build and deployment -> Deploy from a branch**.
3. Select branch `main` and folder `/ (root)`, then click **Save**.

**Option B — GitHub Actions (`npm run build`):**
1. Go to **Settings -> Pages -> Build and deployment -> Source -> GitHub Actions**.
2. Push to `main`; the included `.github/workflows/deploy-pages.yml` workflow builds `dist/` with relative `./` asset paths and deploys automatically.

## Running Locally in VS Code

1. Unzip this folder and open it in **VS Code** (`File -> Open Folder...`).
2. Open the integrated terminal (`Ctrl + \`` or `Terminal -> New Terminal`).
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the application server:
   ```bash
   npm run dev
   ```
5. Open `http://localhost:3000` in your browser.

## Project Structure

- `index.html` — Semantic HTML5 shell (uses relative `./src/...` paths for subpath hosting)
- `.nojekyll` & `.github/workflows/deploy-pages.yml` — GitHub Pages configuration
- `src/css/styles.css` — Pure CSS layout, theme tokens, and components
- `src/js/` — Vanilla JavaScript UI views (`app.js`, `analyzerView.js`, `gauge.js`, `threatLedgerView.js`, `modelsView.js`, `historyView.js`, `filesView.js`, `utils.js`)
- `src/core/` — Shared browser-safe URL normalization (`normalizer.js`), lexical features (`features.js`), classical ML (`mlEngine.js`), SHA-256 (`sha256.js`), built-in dataset (`datasetData.js`), threat seeds (`threatSeeds.js`), and client-side static engine (`clientEngine.js`)
- `src/server/` — Node/Express persistence & server-side ZIP builder (`dataset.js`, `threatStore.js`, `analyzer.js`, `zipBuilder.js`)
- `server.js` — Express server & REST API (`/api/analyze`, `/api/threats`, `/api/models`, `/api/history`, `/api/files`, `/api/download-zip`)
