import { escapeHtml, icons } from './utils.js';

export function renderFilesView(container, state, handlers) {
  const {
    projectFiles,
    selectedFilePath,
    copiedFilePath,
    downloadingZip,
    filesUnavailableReason,
  } = state;

  if (filesUnavailableReason) {
    container.innerHTML = `<div class="card card-padded empty-state">${escapeHtml(filesUnavailableReason)}</div>`;
    return;
  }

  if (!projectFiles || projectFiles.length === 0) {
    container.innerHTML = `<div class="card card-padded empty-state">Loading project source files...</div>`;
    return;
  }

  const activeFile =
    projectFiles.find((f) => f.path === selectedFilePath) ?? projectFiles[0];

  const fileListHtml = projectFiles
    .map((file) => {
      const active = file.path === activeFile.path;
      const kb = (file.size / 1024).toFixed(1);
      return `
        <button
          type="button"
          class="file-tree-item ${active ? 'active' : ''}"
          data-select-file="${escapeHtml(file.path)}"
        >
          <span class="font-mono truncate-cell" style="max-width:210px;">${escapeHtml(file.path)}</span>
          <span class="font-mono tabular-nums" style="font-size:11px;color:var(--text-muted);">${kb} KB</span>
        </button>
      `;
    })
    .join('');

  container.innerHTML = `
    <div class="stack-lg">
      <section class="card card-padded">
        <div class="section-head-row" style="border-bottom:none;padding-bottom:0;margin-bottom:0;">
          <div>
            <h2 class="section-title">Project Source Files (${projectFiles.length} files)</h2>
            <p class="section-desc">Download the entire HTML, CSS, and JavaScript codebase as a ZIP for VS Code, or inspect and download individual files below.</p>
          </div>
          <button type="button" id="files-download-zip-btn" class="btn btn-primary btn-sm" ${downloadingZip ? 'disabled' : ''}>
            ${icons.download}
            <span>${downloadingZip ? 'Preparing ZIP...' : 'Download All as ZIP'}</span>
          </button>
        </div>
      </section>

      <section class="files-layout">
        <aside class="card files-sidebar" aria-label="Project files list">
          <div class="files-sidebar-head">Files</div>
          <div class="files-tree">${fileListHtml}</div>
        </aside>

        <article class="card files-viewer">
          <header class="files-viewer-head">
            <div class="font-mono" style="font-size:13px;font-weight:600;">${escapeHtml(activeFile.path)}</div>
            <div class="toolbar-inline">
              <button type="button" id="copy-file-code-btn" class="btn btn-secondary btn-sm">
                ${copiedFilePath === activeFile.path ? `${icons.check}<span>Copied</span>` : `${icons.copy}<span>Copy Code</span>`}
              </button>
              <button type="button" id="download-single-file-btn" class="btn btn-secondary btn-sm">
                ${icons.download}
                <span>Download File</span>
              </button>
            </div>
          </header>
          <pre class="code-viewer"><code>${escapeHtml(activeFile.content)}</code></pre>
        </article>
      </section>
    </div>
  `;

  container.querySelector('#files-download-zip-btn')?.addEventListener('click', () => {
    handlers.onDownloadZip();
  });

  container.querySelectorAll('[data-select-file]').forEach((btn) => {
    btn.addEventListener('click', () => {
      handlers.onSelectFile(btn.getAttribute('data-select-file'));
    });
  });

  container.querySelector('#copy-file-code-btn')?.addEventListener('click', () => {
    handlers.onCopyFile(activeFile);
  });

  container.querySelector('#download-single-file-btn')?.addEventListener('click', () => {
    handlers.onDownloadSingleFile(activeFile);
  });
}
