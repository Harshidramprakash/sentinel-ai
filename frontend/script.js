document.addEventListener('DOMContentLoaded', () => {
    console.log("Upload dataset to start analysis");

    document.getElementById('refreshBtn').addEventListener('click', () => {
        fetchLogs();
    });
});

async function fetchLogs() {
    const tbody = document.getElementById('logsBody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">Loading threat data...</td></tr>';

    try {
        const response = await fetch('/api/threats');
        const data = await response.json();


        document.getElementById('totalRequests').textContent = data.length;
        document.getElementById('activeThreats').textContent = data.filter(d => d.Status === 'Anomaly').length;
        document.getElementById('criticalAlerts').textContent = data.filter(d => d['Risk Level'] === 'Critical' || d['Risk Level'] === 'High').length;

        tbody.innerHTML = '';

        data.forEach((row, index) => {
            const tr = document.createElement('tr');

            tr.style.opacity = '0';
            tr.style.animation = `fadeIn 0.3s ease forwards ${index * 0.05}s`;

            const statusBadge = `<span class="badge ${row.Status.toLowerCase()}">${row.Status}</span>`;
            const riskClass = row['Risk Level'].toLowerCase();

            tr.innerHTML = `
                <td style="font-family: monospace;">${row.ip_address}</td>
                <td>${statusBadge}</td>
                <td>${row['Threat Type']}</td>
                <td><span class="risk-level ${riskClass}">${row['Risk Score']} (${row['Risk Level']})</span></td>
                <td class="action-text">${row['Suggested Action']}</td>
            `;

            tbody.appendChild(tr);
        });

    } catch (error) {
        console.error('Error fetching logs:', error);
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: #f85149;">Failed to load data. Ensure backend API is running.</td></tr>';
    }
}

document.getElementById('uploadBtn').addEventListener('click', async () => {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!file) {
        alert('No file selected');
        return;
    }

    if (!file.name.endsWith('.csv')) {
        alert('Invalid CSV format');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    const tbody = document.getElementById('logsBody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">Analyzing uploaded data...</td></tr>';

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            alert('Error: ' + (data.error || 'Failed to analyze file'));
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: #f85149;">Failed to process data.</td></tr>';
            return;
        }

        document.getElementById('totalRequests').textContent = data.length;
        document.getElementById('activeThreats').textContent = data.filter(d => d.Status === 'Anomaly').length;
        document.getElementById('criticalAlerts').textContent = data.filter(d => d['Risk Level'] === 'Critical' || d['Risk Level'] === 'High').length;

        tbody.innerHTML = '';

        data.forEach((row, index) => {
            const tr = document.createElement('tr');
            tr.style.opacity = '0';
            tr.style.animation = `fadeIn 0.3s ease forwards ${index * 0.05}s`;

            const statusBadge = `<span class="badge ${row.Status.toLowerCase()}">${row.Status}</span>`;
            const riskClass = row['Risk Level'].toLowerCase();

            tr.innerHTML = `
                <td style="font-family: monospace;">${row.ip_address}</td>
                <td>${statusBadge}</td>
                <td>${row['Threat Type']}</td>
                <td><span class="risk-level ${riskClass}">${row['Risk Score']} (${row['Risk Level']})</span></td>
                <td class="action-text">${row['Suggested Action']}</td>
            `;

            tbody.appendChild(tr);
        });

    } catch (error) {
        console.error('Error uploading file:', error);
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: #f85149;">Failed to upload and analyze.</td></tr>';
    }
});
