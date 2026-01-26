import { clipboard, contextBridge, ipcRenderer } from 'electron';

console.log('[Preload] Script is running!');
try {
  contextBridge.exposeInMainWorld('packetforge', {
    appVersion: process.env.npm_package_version ?? '0.1.0',
    electronVersion: process.versions.electron,
    api: {
      rules: {
        list: () => ipcRenderer.invoke('rules:list'),
        create: (input) => ipcRenderer.invoke('rules:create', input),
        update: (payload) => ipcRenderer.invoke('rules:update', payload),
        remove: (id) => ipcRenderer.invoke('rules:remove', id)
      },
      resources: {
        list: () => ipcRenderer.invoke('resources:list'),
        create: (input) => ipcRenderer.invoke('resources:create', input),
        remove: (id) => ipcRenderer.invoke('resources:remove', id)
      },
      sessions: {
        list: () => ipcRenderer.invoke('sessions:list'),
        clear: () => ipcRenderer.invoke('sessions:clear')
      },
      certs: {
        status: () => ipcRenderer.invoke('certs:status'),
        ensure: () => ipcRenderer.invoke('certs:ensure')
      },
      app: {
        relaunchAsAdmin: () => ipcRenderer.invoke('app:relaunch-admin')
      },
      mitm: {
        status: () => ipcRenderer.invoke('mitm:status'),
        listInterfaces: () => ipcRenderer.invoke('mitm:listInterfaces'),
        scanNetwork: (interfaceName) => ipcRenderer.invoke('mitm:scanNetwork', { interfaceName }),
        getGateway: (interfaceName) => ipcRenderer.invoke('mitm:getGateway', { interfaceName }),
        start: (payload) => ipcRenderer.invoke('mitm:start', payload),
        stop: () => ipcRenderer.invoke('mitm:stop'),
        addTarget: (target) => ipcRenderer.invoke('mitm:addTarget', target),
        removeTarget: (ip) => ipcRenderer.invoke('mitm:removeTarget', { ip }),
        checkPrivileges: () => ipcRenderer.invoke('mitm:checkPrivileges'),
        requestPrivileges: () => ipcRenderer.invoke('mitm:requestPrivileges')
      },
      utils: {
        copyText: (text) => clipboard.writeText(text ?? ''),
        readFile: (payload) => ipcRenderer.invoke('utils:readFile', payload)
      },
      onSession: (callback) => {
        ipcRenderer.on('session:added', (_event, session) => callback(session));
      },
      onMitmStatus: (callback) => {
        ipcRenderer.on('mitm:status', (_event, status) => callback(status));
      },
      onMitmDeviceDiscovered: (callback) => {
        ipcRenderer.on('mitm:device-discovered', (_event, device) => callback(device));
      },
      onMitmError: (callback) => {
        ipcRenderer.on('mitm:error', (_event, error) => callback(error));
      }
    }
  });
  console.log('[Preload] contextBridge exposed successfully');
} catch (error) {
  console.error('[Preload] Failed to expose contextBridge:', error);
}
