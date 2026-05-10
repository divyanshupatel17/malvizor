// ──────────────────────────────────────────────
//  MalVizor — Frontend Logic
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    const progressFilename = document.getElementById('progress-filename');
    const progressStatus = document.getElementById('progress-status');
    const progressSteps = document.getElementById('progress-steps');

    // Load analysis history on page load
    loadHistory();

    // ─── Upload Zone: Click ───
    uploadZone.addEventListener('click', () => fileInput.click());

    // ─── Upload Zone: Drag & Drop ───
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadFile(files[0]);
        }
    });

    // ─── Upload Zone: File Input ───
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            uploadFile(fileInput.files[0]);
        }
    });

    // ─── Refresh Button ───
    const btnRefresh = document.getElementById('btn-refresh');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', loadHistory);
    }

    // ─── Upload File ───
    function uploadFile(file) {
        // Validate file size (50 MB limit)
        const maxSize = 50 * 1024 * 1024;
        if (file.size > maxSize) {
            alert('File is too large! Maximum size is 50 MB.');
            return;
        }

        // Show progress UI
        progressContainer.style.display = 'block';
        progressFilename.textContent = file.name;
        setStep('upload');
        setProgress(10);

        const formData = new FormData();
        formData.append('file', file);

        // Upload with progress tracking
        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const pct = Math.round((e.loaded / e.total) * 25);
                setProgress(pct);
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                const response = JSON.parse(xhr.responseText);
                if (response.success) {
                    // Simulate analysis progress steps
                    simulateAnalysisProgress(response.report_id);
                } else {
                    showError(response.error || 'Analysis failed');
                }
            } else {
                showError('Upload failed — server returned ' + xhr.status);
            }
        });

        xhr.addEventListener('error', () => {
            showError('Upload failed — network error');
        });

        xhr.open('POST', '/upload');
        xhr.send(formData);

        // Move to static analysis step after upload starts
        setTimeout(() => {
            setStep('static');
            setProgress(30);
        }, 500);
    }

    // ─── Simulate Analysis Progress ───
    function simulateAnalysisProgress(reportId) {
        setStep('static');
        setProgress(50);

        setTimeout(() => {
            setStep('dynamic');
            setProgress(75);
        }, 600);

        setTimeout(() => {
            setStep('report');
            setProgress(100);
        }, 1200);

        setTimeout(() => {
            // Redirect to the report page
            window.location.href = '/report/' + reportId;
        }, 1800);
    }

    // ─── Progress Helpers ───
    function setProgress(pct) {
        progressFill.style.width = pct + '%';
    }

    function setStep(stepName) {
        const steps = progressSteps.querySelectorAll('.step');
        let found = false;

        steps.forEach(step => {
            const name = step.getAttribute('data-step');
            if (name === stepName) {
                step.classList.add('active');
                step.classList.remove('done');
                found = true;
                progressStatus.textContent = step.querySelector('span').textContent + '...';
            } else if (!found) {
                step.classList.remove('active');
                step.classList.add('done');
            } else {
                step.classList.remove('active');
                step.classList.remove('done');
            }
        });
    }

    function showError(message) {
        progressStatus.textContent = '❌ ' + message;
        progressStatus.style.color = '#ef4444';
        progressFill.style.background = 'linear-gradient(135deg, #ef4444, #f97316)';
    }

    // ─── Load History ───
    function loadHistory() {
        fetch('/api/history')
            .then(res => res.json())
            .then(data => {
                renderHistory(data.analyses || []);
                updateStats(data.analyses || []);
            })
            .catch(err => console.error('Failed to load history:', err));
    }

    // ─── Render History Table ───
    function renderHistory(analyses) {
        const tbody = document.getElementById('history-body');
        if (!tbody) return;

        if (analyses.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="7">
                        <div class="empty-state">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="40" height="40">
                                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                            </svg>
                            <p>No analyses yet — upload a file to get started</p>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = analyses.map(a => {
            const classification = a.classification || 'unknown';
            const date = a.timestamp ? new Date(a.timestamp).toLocaleString() : 'N/A';

            return `
                <tr>
                    <td>#${a.id}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.82rem;">${escapeHtml(a.filename)}</td>
                    <td>${escapeHtml(a.file_type || 'unknown')}</td>
                    <td><span class="score-badge ${classification}">${a.threat_score}</span></td>
                    <td><span class="class-badge ${classification}">${classification}</span></td>
                    <td style="font-size: 0.8rem; color: var(--text-muted);">${date}</td>
                    <td><a href="/report/${a.id}" class="btn-view">View →</a></td>
                </tr>`;
        }).join('');
    }

    // ─── Update Header Stats ───
    function updateStats(analyses) {
        const totalEl = document.getElementById('total-analyses');
        const threatsEl = document.getElementById('threats-found');
        if (totalEl) totalEl.textContent = analyses.length;
        if (threatsEl) {
            const threats = analyses.filter(a =>
                a.classification === 'malicious' || a.classification === 'suspicious'
            ).length;
            threatsEl.textContent = threats;
        }
    }

    // ─── Escape HTML ───
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
