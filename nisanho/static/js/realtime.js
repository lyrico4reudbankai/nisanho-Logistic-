// Real-time notifications and chat for Nisanho Logistics (Socket.IO)
function initNisanhoRealtime() {
  if (!window.io || window.__nisanhoRealtimeInit) return;
  window.__nisanhoRealtimeInit = true;
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrf = meta ? meta.content : '';
  const role = (document.body && document.body.dataset && document.body.dataset.authRole) || '';
  const isAdmin = role === 'admin';
  const isCustomer = role === 'customer';

  let socket;
  try {
    socket = io({ transports: ['websocket', 'polling'], timeout: 5000, reconnectionAttempts: 5 });
  } catch (e) {
    return;
  }
  window.__nisanhoSocket = socket;

  function toast(msg, kind) {
    let wrap = document.getElementById('toast-container');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'toast-container';
      wrap.className = 'fixed top-4 right-4 z-[9999] space-y-2 max-w-sm';
      document.body.appendChild(wrap);
    }
    const el = document.createElement('div');
    el.className = 'px-4 py-3 rounded-lg border shadow-lg text-sm backdrop-blur ' + (kind === 'success' ? 'bg-emerald-900/80 border-emerald-400/40 text-emerald-50' : kind === 'error' ? 'bg-rose-900/80 border-rose-400/40 text-rose-50' : 'bg-slate-900/90 border-cyan-400/30 text-slate-50');
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(() => { el.remove(); }, 5000);
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function appendChatMessage(msg, mineRole) {
    const box = document.getElementById('chat-messages');
    if (!box) return;
    const empty = document.getElementById('chat-empty');
    if (empty) empty.remove();
    if (box.querySelector('[data-message-id="' + msg.id + '"]')) return;
    const mine = msg.sender_role === mineRole;
    const who = mine ? (mineRole === 'admin' ? 'You (Admin)' : 'You') : (msg.sender_role === 'admin' ? 'Nisanho Admin' : (msg.sender_name || 'Customer'));
    const wrap = document.createElement('div');
    wrap.className = 'flex ' + (mine ? 'justify-end' : 'justify-start');
    wrap.dataset.messageId = msg.id;
    wrap.innerHTML = '<div class="max-w-[80%] rounded-xl px-4 py-2 border ' + (mine ? 'bg-cyan-600/20 border-cyan-400/30 text-cyan-50' : 'bg-slate-800/60 border-slate-600/40 text-slate-100') + '">' +
      '<div class="text-[11px] uppercase tracking-wide opacity-70 mb-1">' + escapeHtml(who) + '</div>' +
      '<div class="whitespace-pre-wrap break-words text-sm">' + escapeHtml(msg.body) + '</div>' +
      '<div class="text-[10px] opacity-60 mt-1">' + escapeHtml(msg.created_at || '') + '</div></div>';
    box.appendChild(wrap);
    box.scrollTop = box.scrollHeight;
  }

  async function refreshUnread() {
    try {
      if (isAdmin) {
        const r = await fetch('/api/chat/admin/unread-count', { headers: { 'Accept': 'application/json' } });
        const d = await r.json();
        if (d && d.ok) {
          const b = document.getElementById('admin-chat-badge');
          if (b) { b.textContent = d.count; b.classList.toggle('hidden', !d.count); }
        }
      } else if (isCustomer) {
        const r = await fetch('/api/chat/customer/unread-count', { headers: { 'Accept': 'application/json' } });
        const d = await r.json();
        if (d && d.ok) {
          const b = document.getElementById('customer-chat-badge');
          if (b) { b.textContent = d.count; b.classList.toggle('hidden', !d.count); }
        }
      }
    } catch (e) {}
  }

  socket.on('connect', () => {
    if (isAdmin) socket.emit('join_chat', {});
    // join specific chat room if on chat page
    const cbox = document.getElementById('chat-messages');
    if (cbox && cbox.dataset.conversationId) socket.emit('join_chat', { conversation_id: Number(cbox.dataset.conversationId) });
    const aform = document.getElementById('admin-chat-form');
    if (aform && aform.dataset.conversationId) socket.emit('join_chat', { conversation_id: Number(aform.dataset.conversationId) });
  });

  socket.on('order_created', (data) => {
    if (!isAdmin) return;
    toast('New order #' + (data && data.id) + ' from ' + (data && data.full_name) + ' (' + (data && data.tracking_number) + ')', 'info');
    // if on orders page, prepend row softly by reloading section would be heavy; prefer lightweight indicator + optional reload buttonless refresh
    const badge = document.getElementById('orders-live-indicator');
    if (badge) badge.classList.remove('hidden');
    if (location.pathname.indexOf('/admin/orders') === 0 || location.pathname === '/admin') {
      // quick non-disruptive refresh after short delay
      setTimeout(() => { if (document.visibilityState === 'visible') location.reload(); }, 1200);
    }
  });

  socket.on('order_status', (data) => {
    if (!data) return;
    if (isAdmin) toast('Order #' + data.id + ' is now ' + data.status, 'info');
    if (isCustomer) toast('Your order ' + (data.tracking_number || ('#' + data.id)) + ' is now ' + data.status, 'success');
    if (location.pathname.indexOf('/admin/orders') === 0 || location.pathname.indexOf('/customer') === 0) {
      setTimeout(() => { if (document.visibilityState === 'visible') location.reload(); }, 1000);
    }
  });

  socket.on('chat_message', (payload) => {
    if (!payload || !payload.message) return;
    const msg = payload.message;
    const cbox = document.getElementById('chat-messages');
    const convId = cbox && cbox.dataset.conversationId ? Number(cbox.dataset.conversationId) : (document.getElementById('admin-chat-form') ? Number(document.getElementById('admin-chat-form').dataset.conversationId) : null);
    if (convId && Number(payload.conversation_id) === convId) {
      appendChatMessage(msg, isAdmin ? 'admin' : 'customer');
      // mark read via API best-effort
      if (isAdmin) fetch('/api/chat/admin/conversations/' + convId + '/messages', { headers: { 'Accept': 'application/json' } }).catch(()=>{});
      if (isCustomer) fetch('/api/chat/customer/messages', { headers: { 'Accept': 'application/json' } }).catch(()=>{});
    } else {
      // notify about messages in other conversations/pages
      if (isAdmin && msg.sender_role === 'customer') toast('New chat message from customer', 'info');
      if (isCustomer && msg.sender_role === 'admin') toast('New message from Nisanho admin', 'info');
    }
    refreshUnread();
  });

  function wireForm(formId, inputId, postUrlFn) {
    const form = document.getElementById(formId);
    const input = document.getElementById(inputId);
    if (!form || !input) return;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = (input.value || '').trim();
      if (!body) return;
      const url = postUrlFn(form);
      try {
        const r = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf, 'Accept': 'application/json' },
          body: JSON.stringify({ body })
        });
        const d = await r.json();
        if (d && d.ok && d.message) {
          input.value = '';
          appendChatMessage(d.message, isAdmin ? 'admin' : 'customer');
        } else {
          toast((d && d.error) || 'Failed to send message.', 'error');
        }
      } catch (err) {
        toast('Failed to send message.', 'error');
      }
    });
  }

  wireForm('admin-chat-form', 'admin-chat-input', (form) => '/api/chat/admin/conversations/' + form.dataset.conversationId + '/messages');
  wireForm('customer-chat-form', 'customer-chat-input', () => '/api/chat/customer/messages');

  refreshUnread();
  setInterval(refreshUnread, 30000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initNisanhoRealtime);
} else {
  initNisanhoRealtime();
}
