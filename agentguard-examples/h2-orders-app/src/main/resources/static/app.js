let session;
const element = id => document.getElementById(id);
const database = () => element('database').value;
const show = value => { element('response').textContent = JSON.stringify(value, null, 2); };

async function api(path, method = 'GET', payload) {
  const headers = {};
  if (session && method !== 'GET') headers[session.csrfHeader] = session.csrfToken;
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api' + path, { method, headers, body: payload === undefined ? undefined : JSON.stringify(payload) });
  if (response.status === 401) { location.href = '/login'; throw new Error('Please sign in'); }
  const text = await response.text();
  let body;
  try { body = text ? JSON.parse(text) : { status: response.status }; }
  catch { body = { message: 'Unexpected response', status: response.status }; }
  if (!response.ok) throw new Error(JSON.stringify({ status: response.status, ...body }, null, 2));
  return body;
}

function button(label, action) {
  const node = document.createElement('button');
  node.textContent = label;
  node.onclick = () => perform(node, action);
  return node;
}

async function perform(node, action) {
  node.disabled = true;
  try { await action(); }
  catch (error) { element('response').textContent = error.message; }
  finally { node.disabled = false; }
}

async function loadOrders() {
  element('orders').replaceChildren();
  const rows = await api('/databases/' + database() + '/orders');
  for (const row of rows) {
    const tr = document.createElement('tr');
    for (const value of [row.id, row.product, row.amount, row.status]) {
      const td = document.createElement('td'); td.textContent = value; tr.append(td);
    }
    const actions = document.createElement('td');
    actions.append(button('Refund', async () => {
      show(await api('/orders/' + row.id + '/refund', 'POST')); await loadOrders(); await loadApprovals(); await loadAudit();
    }), button('Delete', async () => {
      show(await api('/orders/' + row.id, 'DELETE')); await loadOrders(); await loadAudit();
    }));
    tr.append(actions); element('orders').append(tr);
  }
}

async function loadApprovals() {
  const rows = await api('/approvals');
  element('approvals').replaceChildren();
  for (const row of rows) {
    const div = document.createElement('div'); div.className = 'approval';
    const label = document.createElement('span');
    label.textContent = `Order ${row.ORDER_ID} · ${row.REQUESTED_BY} · ${row.STATUS} `;
    div.append(label);
    if (row.STATUS === 'PENDING') div.append(button('Approve refund', async () => {
      show(await api('/approvals/' + row.ID + '/approve', 'POST')); await loadApprovals(); await loadAudit();
    }));
    element('approvals').append(div);
  }
  if (!rows.length) element('approvals').textContent = 'No approval requests yet.';
}

async function loadAudit() {
  const data = await api('/audit');
  element('audit-count').textContent = `${data.sqlCount} SQL events · ${data.inMemoryCount} in-memory events`;
  element('audit').replaceChildren();
  for (const event of data.events) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = `${event.decision} · ${event.agentId} · ${event.action} · ${event.environment}`;
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(event, null, 2);
    details.append(summary, pre); element('audit').append(details);
  }
}

for (const [id, action] of Object.entries({
  load: loadOrders,
  create: async () => { show(await api('/databases/' + database() + '/orders', 'POST', JSON.parse(element('payload').value))); await loadOrders(); await loadAudit(); },
  'refresh-approvals': loadApprovals,
  'refresh-audit': loadAudit,
  preview: async () => { show(await api('/policy-preview', 'POST')); await loadAudit(); },
  logout: async () => { await fetch('/logout', { method: 'POST', headers: { [session.csrfHeader]: session.csrfToken } }); location.href = '/login'; }
})) element(id).onclick = () => perform(element(id), action);

(async () => {
  try {
    session = await api('/session');
    element('identity').textContent = session.username;
    await loadOrders(); await loadApprovals(); await loadAudit();
  } catch (error) { element('response').textContent = error.message; }
})();
