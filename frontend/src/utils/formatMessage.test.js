import { escapeHtml, formatMessage } from './formatMessage';

describe('formatMessage', () => {
  it('neutralises HTML/script injection from model output', () => {
    const html = formatMessage('<img src=x onerror="alert(1)"> **bold**');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    expect(html).toContain('<strong>bold</strong>');
  });

  it('renders inline code, emphasis and bullets', () => {
    const html = formatMessage('Check `203.0.113.45`\n- first\n_note_');
    expect(html).toContain('<code');
    expect(html).toContain('203.0.113.45');
    expect(html).toContain('• first');
    expect(html).toContain('<em>note</em>');
    expect(html).toContain('<br />');
  });

  it('keeps underscores inside identifiers such as GROQ_API_KEY', () => {
    expect(formatMessage('Set GROQ_API_KEY to enable it.')).toContain('GROQ_API_KEY');
    expect(formatMessage('_Set GROQ_API_KEY to enable it._')).toBe('<em>Set GROQ_API_KEY to enable it.</em>');
  });

  it('handles empty input', () => {
    expect(formatMessage('')).toBe('');
    expect(formatMessage(null)).toBe('');
  });

  it('escapes quotes and ampersands', () => {
    expect(escapeHtml(`a & "b" 'c'`)).toBe('a &amp; &quot;b&quot; &#39;c&#39;');
  });
});
