const { ipcRenderer } = require('electron');

ipcRenderer.on('message', (event, message) => {
  const contentElement = document.getElementById('content');
  contentElement.innerHTML += `<p>${message}</p>`;
});
z