// Live notification polling with SocketIO
function initNotificationPolling(initialCount, unreadCountUrl) {
  let lastCount = initialCount;

  function updateNotificationBadge(count) {
    const bellLink = document.querySelector('.nav-link .bi-bell');
    if (!bellLink) return;
    
    const bellParent = bellLink.parentElement;
    let badge = bellParent.querySelector('.badge');
    
    if (count > 0) {
      if (!badge) {
        // Create badge if it doesn't exist
        badge = document.createElement('span');
        badge.className = 'position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger';
        bellParent.appendChild(badge);
      }
      // Update badge text
      badge.textContent = count < 10 ? count : '9+';
      
      // Show browser notification if count increased
      if (count > lastCount && 'Notification' in window && Notification.permission === 'granted') {
        new Notification('Valdosta Medicine', {
          body: 'You have new notifications',
          icon: '/static/favicon.ico'
        });
      }
    } else {
      // Remove badge if count is 0
      if (badge) {
        badge.remove();
      }
    }
    
    lastCount = count;
  }

  // Initialize SocketIO connection
  const socket = io();
  
  socket.on('connect', function() {
    console.log('Connected to notification server');
  });
  
  socket.on('disconnect', function() {
    console.log('Disconnected from notification server');
  });
  
  // Listen for real-time notifications
  socket.on('new_notification', function(data) {
    console.log('New notification received:', data);
    
    // Immediately update badge count from the event data if available
    if (data.count !== undefined) {
      updateNotificationBadge(data.count);
    } else {
      // Fallback: Fetch updated count if not included in event
      fetch(unreadCountUrl)
        .then(response => response.json())
        .then(data => {
          updateNotificationBadge(data.count);
        })
        .catch(error => console.error('Error fetching notification count:', error));
    }
    
    // Show browser notification
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(data.title, {
        body: data.message,
        icon: '/static/favicon.ico'
      });
    }
  });
  
  // Fallback: Poll every 3 seconds (in case WebSocket fails)
  setInterval(function() {
    fetch(unreadCountUrl)
      .then(response => response.json())
      .then(data => {
        updateNotificationBadge(data.count);
      })
      .catch(error => console.error('Error fetching notifications:', error));
  }, 3000);

  // Request notification permission on first load
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
  
  // Initialize badge with current count
  updateNotificationBadge(initialCount);
}

