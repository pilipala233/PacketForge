import { app, BrowserWindow, ipcMain } from 'electron';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createResourcesStore, createRulesStore, createSessionsStore } from '../core/stores.js';
import { ProxyServer } from '../core/proxy.js';
import { createCertificateManager } from '../core/certs.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..', '..');
let mainWindow;
let proxy;
let rulesStore;
let resourcesStore;
let sessionsStore;
let certificateManager;

function enableHotReload() {
  try {
    const require = createRequire(import.meta.url);
    const electronReload = require('electron-reload');
    const electronPath = path.join(
      rootDir,
      'node_modules',
      '.bin',
      process.platform === 'win32' ? 'electron.cmd' : 'electron'
    );

    electronReload(rootDir, {
      electron: electronPath,
      hardResetMethod: 'exit'
    });
  } catch (error) {
    console.warn('[reload] Disabled:', error?.message ?? error);
  }
}

if (!app.isPackaged) {
  enableHotReload();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#f4efe7',
    title: 'PacketForge',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

async function initializeCore() {
  const dataDir = app.getPath('userData');
  rulesStore = createRulesStore(path.join(dataDir, 'rules.json'));
  resourcesStore = createResourcesStore(path.join(dataDir, 'resources.json'));
  sessionsStore = createSessionsStore(path.join(dataDir, 'sessions.json'), { maxEntries: 200 });
  certificateManager = createCertificateManager(path.join(dataDir, 'certs'));

  await Promise.all([rulesStore.load(), resourcesStore.load(), sessionsStore.load()]);

  proxy = new ProxyServer({
    port: 8080,
    rulesStore,
    resourcesStore,
    sessionsStore,
    certificateManager
  });

  proxy.on('session', (session) => {
    if (mainWindow) {
      mainWindow.webContents.send('session:added', session);
    }
  });
  proxy.on('status', (status) => {
    if (mainWindow) {
      mainWindow.webContents.send('proxy:status', status);
    }
  });
}

function registerIpc() {
  ipcMain.handle('proxy:start', async (_event, payload) => {
    const port = Number.parseInt(payload?.port, 10) || 8080;
    const httpsIntercept = Boolean(payload?.httpsIntercept);
    if (httpsIntercept) {
      await certificateManager.ensureCa();
    }
    proxy.setHttpsMode(httpsIntercept ? 'mitm' : 'tunnel');
    return proxy.start(port);
  });
  ipcMain.handle('proxy:stop', async () => proxy.stop());
  ipcMain.handle('proxy:status', async () => proxy.status());
  ipcMain.handle('proxy:configure', async (_event, payload) => {
    if (payload?.httpsIntercept !== undefined) {
      const enabled = Boolean(payload.httpsIntercept);
      if (enabled) {
        await certificateManager.ensureCa();
      }
      proxy.setHttpsMode(enabled ? 'mitm' : 'tunnel');
    }
    return proxy.status();
  });

  ipcMain.handle('rules:list', async () => rulesStore.list());
  ipcMain.handle('rules:create', async (_event, input) => rulesStore.add(input));
  ipcMain.handle('rules:update', async (_event, payload) => {
    return rulesStore.update(payload?.id, payload?.patch ?? {});
  });
  ipcMain.handle('rules:remove', async (_event, id) => rulesStore.remove(id));

  ipcMain.handle('resources:list', async () => resourcesStore.list());
  ipcMain.handle('resources:create', async (_event, input) => resourcesStore.add(input));
  ipcMain.handle('resources:remove', async (_event, id) => resourcesStore.remove(id));

  ipcMain.handle('sessions:list', async () => sessionsStore.list());
  ipcMain.handle('sessions:clear', async () => sessionsStore.clear());

  ipcMain.handle('certs:status', async () => certificateManager.status());
  ipcMain.handle('certs:ensure', async () => {
    await certificateManager.ensureCa();
    return certificateManager.status();
  });
}

app.whenReady().then(async () => {
  await initializeCore();
  registerIpc();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  if (proxy?.status().running) {
    void proxy.stop();
  }
});
