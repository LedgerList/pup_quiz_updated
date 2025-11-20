import Echo from 'laravel-echo';

import Pusher from 'pusher-js';
window.Pusher = Pusher;

window.Echo = new Echo({
    broadcaster: 'pusher',
    key: import.meta.env.VITE_PUSHER_APP_KEY || '8804906b3ffb07747ef5',
    cluster: import.meta.env.VITE_PUSHER_APP_CLUSTER || 'ap1',
    forceTLS: true
});