const { app, BrowserWindow } = require('electron');
const net = require('net');

let mainWindow;
let traffic_analyzer

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true
    }
  });

  mainWindow.loadFile('index.html');

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.on('ready', () => {
  createWindow();

  const ports = [8000];

  ports.forEach(port => {
    const client = new net.Socket();

    client.connect({ port: port, host: 'localhost' }, () => {
      console.log(`Connected to port ${port}.`);
    });

    client.on('data', data => {
      console.log(`Received from port ${port}: ${data.toString()}`);
    });

    client.on('error', error => {
      console.log(`Error in connection to port ${port}: ${error}`);
    });
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});