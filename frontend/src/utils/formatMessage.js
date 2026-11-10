// Safe chat-message renderer: escape HTML first, then apply a small markdown whitelist.
export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Minimal, safe markdown: input is HTML-escaped first, then a whitelist of formatting is applied.
export function formatMessage(text) {
  if (!text) return '';
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>')
    // _emphasis_ only at word boundaries, so identifiers like GROQ_API_KEY stay intact
    .replace(/(^|[\s(])_([^\n]+?)_(?=$|[\s).,;:!?])/gm, '$1<em>$2</em>')
    .replace(/`([^`]+)`/g, '<code style="font-family:var(--font-mono);background:var(--bg-elevated);padding:1px 5px;border-radius:3px;font-size:0.9em">$1</code>')
    .replace(/^#{1,4}\s+(.+)$/gm, '<strong>$1</strong>')
    .replace(/^\s*[-•]\s+/gm, '• ')
    .replace(/\n/g, '<br />');
}
