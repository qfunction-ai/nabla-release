import { useState, useRef, useEffect } from 'react';
import { API_URL } from '../lib/api';

interface ChatMsg {
  role: 'user' | 'assistant' | 'reasoning';
  content: string;
}

export default function Chat() {
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [includeReasoning, setIncludeReasoning] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => { scrollToBottom(); }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || streaming) return;

    const userMsg = input.trim();
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: userMsg }]);
    setStreaming(true);
    abortRef.current = new AbortController();

    try {
      const res = await fetch(`${API_URL}/api/chat/stream`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: userMsg,
          include_reasoning: includeReasoning,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        setMessages((prev) => [...prev, { role: 'assistant', content: `Error: HTTP ${res.status}` }]);
        return;
      }

      const reader = res.body?.getReader();
      if (!reader) return;

      const decoder = new TextDecoder();
      let buffer = '';
      let assistantContent = '';
      let reasoningContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const event = JSON.parse(line.slice(6));
              if (event.type === 'assistant') {
                assistantContent += event.content;
                // Update the last assistant message or create one
                setMessages((prev) => {
                  const last = prev[prev.length - 1];
                  if (last && last.role === 'assistant') {
                    return [...prev.slice(0, -1), { role: 'assistant', content: assistantContent }];
                  }
                  return [...prev, { role: 'assistant', content: assistantContent }];
                });
              } else if (event.type === 'reasoning') {
                reasoningContent += event.content;
                setMessages((prev) => {
                  const last = prev[prev.length - 1];
                  if (last && last.role === 'reasoning') {
                    return [...prev.slice(0, -1), { role: 'reasoning', content: reasoningContent }];
                  }
                  return [...prev, { role: 'reasoning', content: reasoningContent }];
                });
              } else if (event.type === 'error') {
                setMessages((prev) => [...prev, { role: 'assistant', content: `Error: ${event.error}` }]);
              }
            } catch {}
          }
        }
      }
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        setMessages((prev) => [...prev, { role: 'assistant', content: `Connection error: ${String(e)}` }]);
      }
    } finally {
      setStreaming(false);
    }
  };

  const stopStream = () => {
    abortRef.current?.abort();
    setStreaming(false);
  };

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h1 className="page-title">CHAT</h1>
        <p className="page-subtitle"><span className="math">∇ψ</span> = supervisor inference</p>
      </div>

      <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
        <label style={{ fontFamily: 'var(--font-display)', fontSize: 12, color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <input
            type="checkbox"
            checked={includeReasoning}
            onChange={(e) => setIncludeReasoning(e.target.checked)}
            style={{ width: 'auto' }}
          />
          Include reasoning
        </label>
      </div>

      <div className="chat-container">
        <div className="chat-messages">
          {messages.length === 0 && (
            <div className="empty-state">
              Ask the supervisor about current threats, anomalies, or system health.
            </div>
          )}
          {messages.map((msg, i) => (
            <div key={`${msg.role}-${i}-${msg.content.slice(0, 20)}`} className={`chat-message ${msg.role}`}>
              <div className="role">{msg.role}</div>
              <div className="content">{msg.content}</div>
            </div>
          ))}
          {streaming && (
            <div className="chat-message assistant">
              <div className="role">assistant</div>
              <div className="content" style={{ color: 'var(--text-tertiary)' }}>Thinking...</div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <div className="chat-input-row">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask the supervisor..."
            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
            disabled={streaming}
          />
          <button
            className="btn btn-primary"
            onClick={streaming ? stopStream : sendMessage}
          >
            {streaming ? '■' : '▶'}
          </button>
        </div>
      </div>
    </div>
  );
}
