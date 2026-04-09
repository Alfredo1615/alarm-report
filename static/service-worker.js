self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('push', event => {
  let data = { title: 'New CPC alarm', body: 'A new alarm arrived' };
  try { data = event.data.json(); } catch(e) {}
  event.waitUntil(self.registration.showNotification(data.title || 'New CPC alarm', {
    body: data.body || 'A new alarm arrived',
    data: { url: data.url || '/' }
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data?.url || '/'));
});
self.addEventListener('message', event => {
  const data = event.data || {};
  if (data.type === 'notify') {
    self.registration.showNotification(data.title || 'New CPC alarm', { body: data.body || '' });
  }
});
