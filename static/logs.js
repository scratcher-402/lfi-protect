// Конфигурация
const API_BASE = '/api/logs';
let currentFilters = {
    priority: 1,
    limit: 25
};
let refreshInterval = null;

// Маппинг приоритетов
const PRIORITY_LEVELS = {
    0: { name: 'Debug', class: 'debug', color: '#6c757d' },
    1: { name: 'Info', class: 'info', color: '#17a2b8' },
    2: { name: 'Warning', class: 'warning', color: '#ffc107' },
    3: { name: 'Error', class: 'error', color: '#dc3545' },
    4: { name: 'Fatal', class: 'fatal', color: '#721c24' }
};

// DOM элементы
const elements = {
    tableBody: document.getElementById('logs-body'),
    priorityFilter: document.getElementById('priority-filter'),
    limitFilter: document.getElementById('limit-filter'),
    refreshBtn: document.getElementById('refresh-logs'),
};

// Функции форматирования
function formatTime(unixTime) {
    const date = new Date(unixTime * 1000);
    return date.toLocaleString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
    });
}

function getPriorityBadge(level) {
    const priority = PRIORITY_LEVELS[level] || PRIORITY_LEVELS[0];
    return `<span class="priority-badge priority-${priority.class}" style="background-color: ${priority.color}">
        ${priority.name} (${level})
    </span>`;
}

function truncateMessage(message, maxLength = 200) {
    return message
}


// Загрузка логов
async function loadLogs() {
    try {
        const params = new URLSearchParams({
            limit: currentFilters.limit,
            priority: currentFilters.priority,
        });

        const response = await fetch(`${API_BASE}?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        renderLogs(data.data.logs.reverse());
        
    } catch (error) {
        console.error('Error loading logs:', error);
        showError('Failed to load logs: ' + error.message);
    }
}

// Рендеринг таблицы
function renderLogs(logs) {
    if (logs.length === 0) {
        elements.tableBody.innerHTML = `
            <tr>
                <td colspan="4" class="no-data">No logs found</td>
            </tr>
        `;
        return;
    }

    const rows = logs.map(log => {
        const message = truncateMessage(log.Message);
        
        return `
            <tr class="log-row priority-${PRIORITY_LEVELS[log.Level]?.class || 'debug'}">
                <td class="time-column">
                    <div class="time-cell">
                        <div class="time-full">${formatTime(log.UnixTime)}</div>
                    </div>
                </td>
                <td class="category-column">
                    <span class="category-badge">${log.Category}</span>
                </td>
                <td class="priority-column">
                    ${getPriorityBadge(log.Level)}
                </td>
                <td class="message-column">
                    <div class="message-content">
                        ${message}
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    elements.tableBody.innerHTML = rows;
}


function showError(message) {
    elements.tableBody.innerHTML = `
        <tr>
            <td colspan="4" class="error-message">
                <span style="color: #dc3545">⚠️ ${message}</span>
            </td>
        </tr>
    `;
}

// Обработчики событий
function setupEventListeners() {
    elements.refreshBtn.addEventListener('click', () => {
        currentFilters = {
            priority: parseInt(elements.priorityFilter.value),
            limit: parseInt(elements.limitFilter.value)
        };
        loadLogs();
    });
}



// Инициализация
async function init() {
    setupEventListeners();
    loadLogs();
}

// Запуск при загрузке страницы
document.addEventListener('DOMContentLoaded', init);

// Экспорт функций для использования в HTML
window.expandMessage = expandMessage;