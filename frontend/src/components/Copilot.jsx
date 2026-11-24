// src/components/Copilot.js
import React, { useState, useEffect, useRef } from 'react';
import api, { getApiErrorMessage, LONG_TIMEOUT } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { formatMessage } from '../utils/formatMessage';




const EXAMPLE_QUESTIONS = [
  'What are the top threat types this week?',
  'Show me all CRITICAL incidents from the last 24 hours',
  'Which IPs have been blocked automatically?',
  'List active attack campaigns and their stages',
  'What MITRE techniques have been detected?',
  'Summarize the risk posture of IP 203.0.113.45',
];

function ChatBubble({ msg }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`chat-bubble-wrap ${isUser ? 'cbw-user' : 'cbw-ai'}`}>
      <div className={`chat-avatar ${isUser ? 'ca-user' : 'ca-ai'}`}>
        {isUser ? 'U' : '🤖'}
      </div>
      <div className={`chat-bubble ${isUser ? 'cb-user' : 'cb-ai'}`}>
        <div className="chat-text" dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }} />
        {msg.timestamp && (
          <div className="chat-time">
            {new Date(msg.timestamp).toLocaleTimeString()}
            {msg.source && <span style={{ marginLeft: 8, opacity: 0.7 }}>{msg.source === 'llm' ? '· AI model' : '· rule engine'}</span>}
          </div>
        )}
      </div>
    </div>
  );
}

export default function Copilot() {
  useAuth();
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: `Hello! I'm the ThreatLens AI Copilot. I have direct access to your incident database, campaigns, blocklist, and threat intel.\n\nAsk me anything — from **"What happened in the last 24 hours?"** to **"Summarize the CRITICAL incidents this week."**`,
      timestamp: new Date().toISOString(),
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(() => `session_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`);
  const bottomRef = useRef(null);
  const [llm, setLlm] = useState(null);

  useEffect(() => {
    api.get('/system/status').then((res) => setLlm(res.data.llm)).catch(() => setLlm({ enabled: false }));
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = async (text) => {
    const question = text || input.trim();
    if (!question || loading) return;
    setInput('');
    const userMsg = { role: 'user', content: question, timestamp: new Date().toISOString() };
    setMessages(m => [...m, userMsg]);
    setLoading(true);
    try {
      const res = await api.post('/chat/ask', { session_id: sessionId, message: question }, { timeout: LONG_TIMEOUT });
      if (res.data.session_id && res.data.session_id !== sessionId) setSessionId(res.data.session_id);
      const aiMsg = {
        role: 'assistant',
        content: res.data.response || 'I could not generate a response.',
        source: res.data.generated_by,
        timestamp: new Date().toISOString(),
      };
      setMessages(m => [...m, aiMsg]);
    } catch (err) {
      setMessages(m => [...m, { role: 'assistant', content: `⚠️ ${getApiErrorMessage(err, 'Failed to reach the AI backend.')}`, timestamp: new Date().toISOString() }]);
    } finally { setLoading(false); }
  };

  const handleKey = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };
  const clearChat = () => setMessages([messages[0]]);

  return (
    <div className="copilot-layout">
      {/* Sidebar */}
      <div className="copilot-sidebar">
        <div className="copilot-sidebar-header">
          <span style={{ fontSize: 18, color: 'var(--accent-primary)' }}>🤖</span>
          <span style={{ fontSize: 14, fontWeight: 600 }}>AI Copilot</span>
        </div>
        <p className="copilot-desc">
          Answers grounded in your live incident data, campaigns, blocklist and threat intel — with memory of this conversation.
        </p>
        <div className="copilot-examples">
          <div className="copilot-examples-label">Example Questions</div>
          {EXAMPLE_QUESTIONS.map((q, i) => (
            <button key={i} className="example-btn" onClick={() => send(q)} disabled={loading}>
              {q}
            </button>
          ))}
        </div>
        <div className="copilot-actions">
          <button className="btn-ghost" style={{ fontSize: 12, width: '100%' }} onClick={clearChat}>
            ⟲ Clear Conversation
          </button>
        </div>
      </div>

      {/* Chat area */}
      <div className="copilot-chat">
        <div className="copilot-chat-header">
          <div>
            <h1 className="page-header-title" style={{ fontSize: 16, marginBottom: 0 }}>AI SOC Copilot</h1>
            <p className="page-header-sub">Session: {sessionId}</p>
          </div>
          <div className="copilot-status">
            <span className="badge-dot" style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: llm?.enabled ? 'var(--success)' : 'var(--warning)', animation: 'pulse-dot 2s ease infinite', marginRight: 6 }} />
            {llm === null ? 'Checking AI…' : llm.enabled ? `AI model: ${llm.model}` : 'Rule-engine mode (set GROQ_API_KEY for AI)'}
          </div>
        </div>

        <div className="copilot-messages">
          {messages.map((msg, i) => <ChatBubble key={i} msg={msg} />)}
          {loading && (
            <div className="cbw-ai chat-bubble-wrap">
              <div className="chat-avatar ca-ai">🤖</div>
              <div className="chat-bubble cb-ai">
                <div className="typing-indicator">
                  <span /><span /><span />
                </div>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        <div className="copilot-input-area">
          <textarea
            className="copilot-input"
            placeholder="Ask about your incidents, campaigns, blocked IPs, or threats…"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKey}
            rows={2}
            disabled={loading}
          />
          <button className="copilot-send" onClick={() => send()} disabled={loading || !input.trim()}>
            {loading ? <span className="btn-spinner" style={{ borderColor: 'rgba(0,0,0,0.3)', borderTopColor: '#000' }} /> : '↑'}
          </button>
        </div>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center', marginTop: 8 }}>
          Press Enter to send · Shift+Enter for new line
        </p>
      </div>
    </div>
  );
}
