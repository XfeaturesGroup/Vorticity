export const formatRelativeTime = (dateString) => {
    if (!dateString) return '';

    let safeDateString = dateString;

    if (!isNaN(dateString) && (typeof dateString === 'number' || (typeof dateString === 'string' && /^\d+$/.test(dateString)))) {
        const ts = Number(dateString);
        safeDateString = ts < 10000000000 ? ts * 1000 : ts;
    } else if (typeof dateString === 'string' && !dateString.includes('T')) {
        safeDateString = dateString.replace(' ', 'T') + 'Z';
    }

    const date = new Date(safeDateString);
    const now = new Date();

    const diffInSeconds = Math.max(0, Math.floor((now - date) / 1000));

    if (diffInSeconds < 60) return 'Только что';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} мин. назад`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} ч. назад`;
    if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)} дн. назад`;

    return date.toLocaleDateString('ru-RU', {
        day: 'numeric',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit'
    });
};