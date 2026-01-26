import { app, BrowserWindow, ipcMain, dialog, shell } from 'electron';
import { createRequire } from 'node:module';
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  createResourcesStore,
  createRulesStore,
  createSessionsStore,
  createSettingsStore
} from '../core/stores.js';
import { createCertificateManager } from '../core/certs.js';
import { MitmController } from '../core/mitm/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..', '..');
const execFileAsync = promisify(execFile);
let mainWindow;
let rulesStore;
let resourcesStore;
let sessionsStore;
let settingsStore;
let certificateManager;
let mitmController;
let crashLogPath;
const conversionQueue = [];
let conversionRunning = false;

function escapePowerShellString(value) {
  return value.replace(/'/g, "''");
}

function formatCrashDetail(detail) {
  if (!detail) {
    return '';
  }
  if (detail instanceof Error) {
    return detail.stack || detail.message;
  }
  if (typeof detail === 'string') {
    return detail;
  }
  try {
    return JSON.stringify(detail);
  } catch (_error) {
    return String(detail);
  }
}

const DEFAULT_PREVIEW_BYTES = 64 * 1024;

function isProbablyText(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return true;
  }
  const sampleSize = Math.min(buffer.length, 4096);
  let nonPrintable = 0;
  for (let i = 0; i < sampleSize; i += 1) {
    const byte = buffer[i];
    if (byte === 0x00) {
      nonPrintable += 2;
      continue;
    }
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d) {
      continue;
    }
    if (byte >= 0x20) {
      continue;
    }
    nonPrintable += 1;
  }
  return nonPrintable / sampleSize <= 0.2;
}

function shouldTreatAsText(contentType, buffer) {
  const lower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  if (
    lower.startsWith('text/') ||
    lower.includes('json') ||
    lower.includes('xml') ||
    lower.includes('javascript') ||
    lower.includes('x-www-form-urlencoded')
  ) {
    return true;
  }
  return isProbablyText(buffer);
}

async function readFilePreview({ filePath, maxBytes, contentType } = {}) {
  if (!filePath || typeof filePath !== 'string') {
    return { ok: false, error: 'Invalid path' };
  }
  const limit =
    Number.isFinite(maxBytes) && maxBytes > 0 ? Math.trunc(maxBytes) : DEFAULT_PREVIEW_BYTES;
  try {
    const stat = await fs.promises.stat(filePath);
    const totalBytes = stat.size;
    const readBytes = Math.max(0, Math.min(totalBytes, limit));
    const handle = await fs.promises.open(filePath, 'r');
    try {
      const buffer = Buffer.alloc(readBytes);
      const { bytesRead } = await handle.read(buffer, 0, readBytes, 0);
      const slice = buffer.slice(0, bytesRead);
      const isText = shouldTreatAsText(contentType, slice);
      return {
        ok: true,
        isText,
        truncated: totalBytes > bytesRead,
        bytesRead,
        totalBytes,
        text: isText ? slice.toString('utf8') : null,
        base64: isText ? null : slice.toString('base64')
      };
    } finally {
      await handle.close();
    }
  } catch (error) {
    return { ok: false, error: error?.message ?? String(error) };
  }
}

function resolveCrashLogPath() {
  if (crashLogPath) {
    return crashLogPath;
  }
  try {
    crashLogPath = path.join(app.getPath('userData'), 'crash.log');
  } catch (_error) {
    crashLogPath = path.join(process.cwd(), 'crash.log');
  }
  return crashLogPath;
}

function appendCrashLog(message, detail) {
  const timestamp = new Date().toISOString();
  const detailText = formatCrashDetail(detail);
  const line = `[${timestamp}] ${message}${detailText ? ` | ${detailText}` : ''}\n`;
  const targetPath = resolveCrashLogPath();
  try {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.appendFileSync(targetPath, line, 'utf8');
  } catch (_error) {
    console.error(line.trim());
  }
}

function registerCrashHandlers() {
  process.on('uncaughtException', (error) => {
    appendCrashLog('uncaughtException', error);
  });
  process.on('unhandledRejection', (reason) => {
    appendCrashLog('unhandledRejection', reason);
  });
  process.on('warning', (warning) => {
    appendCrashLog(`warning:${warning?.name ?? 'unknown'}`, warning);
  });
  process.on('exit', (code) => {
    appendCrashLog(`process exit code=${code}`);
  });
  app.on('render-process-gone', (_event, webContents, details) => {
    appendCrashLog('render-process-gone', {
      id: webContents?.id,
      reason: details?.reason,
      exitCode: details?.exitCode
    });
  });
  app.on('child-process-gone', (_event, details) => {
    appendCrashLog('child-process-gone', details);
  });
}

async function relaunchAsAdmin() {
  if (process.platform !== 'win32') {
    return { success: false, error: 'Administrator relaunch is only supported on Windows.' };
  }

  const privileges = await mitmController?.checkPrivileges?.();
  if (privileges?.elevated) {
    return { success: true, alreadyElevated: true };
  }

  const execPath = process.execPath;
  const args = process.argv.slice(1).filter((arg) => arg !== '--relaunch-admin');
  const escapedExec = escapePowerShellString(execPath);
  const escapedArgs = args.map((arg) => `'${escapePowerShellString(arg)}'`);
  const escapedCwd = escapePowerShellString(process.cwd());

  const commandParts = ['Start-Process', '-FilePath', `'${escapedExec}'`];
  if (escapedCwd) {
    commandParts.push('-WorkingDirectory', `'${escapedCwd}'`);
  }
  if (escapedArgs.length) {
    commandParts.push('-ArgumentList', escapedArgs.join(', '));
  }
  commandParts.push('-Verb', 'RunAs');

  try {
    await execFileAsync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', commandParts.join(' ')],
      { windowsHide: true }
    );
  } catch (error) {
    return { success: false, error: error?.message ?? String(error) };
  }

  setTimeout(() => {
    app.quit();
  }, 200);

  return { success: true };
}

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

function resolveFfmpegPath(settings) {
  const configured = settings?.media?.ffmpegPath;
  if (configured && typeof configured === 'string') {
    const trimmed = configured.trim();
    if (trimmed) {
      if (fs.existsSync(trimmed)) {
        const stats = fs.statSync(trimmed);
        if (stats.isDirectory()) {
          const candidate = path.join(trimmed, process.platform === 'win32' ? 'ffmpeg.exe' : 'ffmpeg');
          if (fs.existsSync(candidate)) {
            return candidate;
          }
        } else {
          return trimmed;
        }
      }
    }
  }

  const envPath = process.env.PATH || '';
  const parts = envPath.split(path.delimiter).filter(Boolean);
  const binaryName = process.platform === 'win32' ? 'ffmpeg.exe' : 'ffmpeg';
  for (const part of parts) {
    const candidate = path.join(part, binaryName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function deriveConvertedPath(inputPath, mode) {
  const parsed = path.parse(inputPath);
  if (mode === 'h264') {
    return path.join(parsed.dir, `${parsed.name}-h264.mp4`);
  }
  return path.join(parsed.dir, `${parsed.name}.mp4`);
}

function runFfmpeg(ffmpegPath, args) {
  return new Promise((resolve) => {
    let stderr = '';
    const proc = spawn(ffmpegPath, args, { windowsHide: true });
    proc.stderr.on('data', (chunk) => {
      if (stderr.length < 8192) {
        stderr += chunk.toString('utf8');
      }
    });
    proc.on('error', (error) => {
      resolve({ code: -1, error, stderr });
    });
    proc.on('close', (code) => {
      resolve({ code: Number.isFinite(code) ? code : -1, stderr });
    });
  });
}

async function processConversionQueue() {
  if (conversionRunning) {
    return;
  }
  conversionRunning = true;
  while (conversionQueue.length > 0) {
    const task = conversionQueue.shift();
    if (!task) {
      continue;
    }
    const { sessionId, inputPath, mode } = task;
    try {
      const settings = settingsStore?.get?.() ?? {};
      const ffmpegPath = resolveFfmpegPath(settings);
      if (!ffmpegPath) {
        const updated = await sessionsStore?.update?.(sessionId, {
          responseMediaConvertError: 'ffmpeg not found'
        });
        if (updated && mainWindow) {
          mainWindow.webContents.send('session:updated', updated);
        }
        continue;
      }

      const outputPath = deriveConvertedPath(inputPath, mode);
      if (fs.existsSync(outputPath) && fs.statSync(outputPath).size > 0) {
        const updated = await sessionsStore?.update?.(sessionId, {
          responseMediaConvertedPath: outputPath,
          responseMediaConvertedMode: mode,
          responseMediaConvertError: null
        });
        if (updated && mainWindow) {
          mainWindow.webContents.send('session:updated', updated);
        }
        continue;
      }

      const args =
        mode === 'h264'
          ? [
              '-hide_banner',
              '-y',
              '-i',
              inputPath,
              '-c:v',
              'libx264',
              '-preset',
              'veryfast',
              '-crf',
              '23',
              '-c:a',
              'aac',
              '-movflags',
              '+faststart',
              outputPath
            ]
          : ['-hide_banner', '-y', '-i', inputPath, '-c', 'copy', outputPath];

      const result = await runFfmpeg(ffmpegPath, args);
      if (result.code === 0 && fs.existsSync(outputPath)) {
        let sizeOk = false;
        try {
          sizeOk = fs.statSync(outputPath).size > 0;
        } catch (_error) {
          sizeOk = false;
        }
        if (sizeOk) {
          const updated = await sessionsStore?.update?.(sessionId, {
            responseMediaConvertedPath: outputPath,
            responseMediaConvertedMode: mode,
            responseMediaConvertError: null
          });
          if (updated && mainWindow) {
            mainWindow.webContents.send('session:updated', updated);
          }
          continue;
        }
      }

      const errorText =
        result.error?.message ||
        result.stderr?.trim() ||
        `ffmpeg exited with code ${result.code}`;
      if (fs.existsSync(outputPath)) {
        try {
          fs.unlinkSync(outputPath);
        } catch (_error) {}
      }
      const updated = await sessionsStore?.update?.(sessionId, {
        responseMediaConvertError: errorText
      });
      if (updated && mainWindow) {
        mainWindow.webContents.send('session:updated', updated);
      }
    } catch (error) {
      appendCrashLog('media convert error', error);
      const updated = await sessionsStore?.update?.(sessionId, {
        responseMediaConvertError: error?.message ?? String(error)
      });
      if (updated && mainWindow) {
        mainWindow.webContents.send('session:updated', updated);
      }
    }
  }
  conversionRunning = false;
}

function enqueueAutoConversion(session) {
  if (!session?.id || !session?.responseBodyPath) {
    return;
  }
  if (session.responseMedia?.container !== 'flv') {
    return;
  }
  const settings = settingsStore?.get?.() ?? {};
  const mode = settings?.media?.autoConvert ?? 'off';
  if (mode !== 'remux' && mode !== 'h264') {
    return;
  }
  conversionQueue.push({
    sessionId: session.id,
    inputPath: session.responseBodyPath,
    mode
  });
  void processConversionQueue();
}

// if (!app.isPackaged) {
//   enableHotReload();
// }

function createWindow() {
  const preloadPath = path.join(__dirname, 'preload.cjs');
  console.log('[Main] Preload path:', preloadPath);

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
      preload: preloadPath
    }
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  mainWindow.webContents.openDevTools();
}

async function initializeCore() {
  const dataDir = app.getPath('userData');
  resolveCrashLogPath();
  appendCrashLog('app start', { pid: process.pid, version: app.getVersion() });

  rulesStore = createRulesStore(path.join(dataDir, 'rules.json'));
  resourcesStore = createResourcesStore(path.join(dataDir, 'resources.json'));
  sessionsStore = createSessionsStore(path.join(dataDir, 'sessions.json'), { maxEntries: 200 });
  settingsStore = createSettingsStore(path.join(dataDir, 'settings.json'), {
    defaults: {
      capture: {
        dir: path.join(dataDir, 'captures'),
        maxBytes: 100 * 1024 * 1024
      },
      media: {
        ffmpegPath: '',
        autoConvert: 'off'
      },
      sessions: {
        maxEntries: 200
      }
    }
  });
  certificateManager = createCertificateManager(path.join(dataDir, 'certs'));

  await Promise.all([
    rulesStore.load(),
    resourcesStore.load(),
    settingsStore.load()
  ]);
  const initialSettings = settingsStore.get();
  if (typeof sessionsStore?.setMaxEntries === 'function') {
    await sessionsStore.setMaxEntries(initialSettings?.sessions?.maxEntries ?? 200);
  }
  await sessionsStore.load();

  // 初始化 MITM 控制器
  mitmController = new MitmController({
    certificateManager,
    rulesStore,
    resourcesStore,
    sessionsStore
  });

  mitmController.on('status', (status) => {
    if (mainWindow) {
      mainWindow.webContents.send('mitm:status', status);
    }
  });
  mitmController.on('device-discovered', (device) => {
    if (mainWindow) {
      mainWindow.webContents.send('mitm:device-discovered', device);
    }
  });
  mitmController.on('error', (error) => {
    appendCrashLog('mitm error', error);
    if (mainWindow) {
      mainWindow.webContents.send('mitm:error', error);
    }
  });
  mitmController.on('session', (session) => {
    if (mainWindow) {
      mainWindow.webContents.send('session:added', session);
    }
    enqueueAutoConversion(session);
  });
}

function registerIpc() {
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
  ipcMain.handle('settings:get', async () => settingsStore.get());
  ipcMain.handle('settings:update', async (_event, patch) => {
    const updated = await settingsStore.update(patch);
    if (patch?.sessions && typeof sessionsStore?.setMaxEntries === 'function') {
      await sessionsStore.setMaxEntries(updated?.sessions?.maxEntries ?? patch.sessions.maxEntries);
    }
    return updated;
  });

  ipcMain.handle('certs:status', async () => certificateManager.status());
  ipcMain.handle('certs:ensure', async () => {
    await certificateManager.ensureCa();
    return certificateManager.status();
  });

  ipcMain.handle('app:relaunch-admin', async () => relaunchAsAdmin());
  ipcMain.handle('utils:selectDirectory', async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openDirectory', 'createDirectory']
    });
    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }
    return result.filePaths[0];
  });
  ipcMain.handle('utils:showItemInFolder', async (_event, filePath) => {
    if (!filePath || typeof filePath !== 'string') {
      return false;
    }
    shell.showItemInFolder(filePath);
    return true;
  });
  ipcMain.handle('utils:selectFile', async (_event, payload) => {
    const filters = Array.isArray(payload?.filters) ? payload.filters : undefined;
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters
    });
    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }
    return result.filePaths[0];
  });
  ipcMain.handle('utils:readFile', async (_event, payload) => {
    return readFilePreview({
      filePath: payload?.path,
      maxBytes: payload?.maxBytes,
      contentType: payload?.contentType
    });
  });

  // MITM IPC handlers
  ipcMain.handle('mitm:status', async () => mitmController.status());
  ipcMain.handle('mitm:listInterfaces', async () => mitmController.listInterfaces());
  ipcMain.handle('mitm:scanNetwork', async (_event, payload) => {
    return mitmController.scanNetwork(payload?.interfaceName);
  });
  ipcMain.handle('mitm:getGateway', async (_event, payload) => {
    return mitmController.getGateway(payload?.interfaceName);
  });
  ipcMain.handle('mitm:start', async (_event, payload) => {
    console.log('[mitm] start payload:', {
      httpsIntercept: payload?.httpsIntercept ?? false,
      httpsObserve: payload?.httpsObserve ?? false,
      httpPorts: payload?.httpPorts ?? '',
      httpsPorts: payload?.httpsPorts ?? '',
      throttle: payload?.throttle ?? null
    });
    const settings = settingsStore?.get?.();
    const capture = payload?.capture ?? settings?.capture;
    return mitmController.start({ ...payload, capture });
  });
  ipcMain.handle('mitm:stop', async () => mitmController.stop());
  ipcMain.handle('mitm:pause', async () => {
    mitmController
      .pause()
      .catch((error) =>
        mitmController.emit('error', { message: error?.message ?? String(error) })
      );
    return mitmController.status();
  });
  ipcMain.handle('mitm:resume', async () => {
    mitmController
      .resume()
      .catch((error) =>
        mitmController.emit('error', { message: error?.message ?? String(error) })
      );
    return mitmController.status();
  });
  ipcMain.handle('mitm:addTarget', async (_event, payload) => {
    return mitmController.addTarget(payload);
  });
  ipcMain.handle('mitm:removeTarget', async (_event, payload) => {
    return mitmController.removeTarget(payload?.ip);
  });
  ipcMain.handle('mitm:checkPrivileges', async () => {
    return mitmController.checkPrivileges();
  });
  ipcMain.handle('mitm:requestPrivileges', async () => {
    return mitmController.requestPrivileges();
  });
}

app.whenReady().then(async () => {
  registerCrashHandlers();
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

app.on('before-quit', async () => {
  if (mitmController?.status().running) {
    await mitmController.stop();
  }
});
