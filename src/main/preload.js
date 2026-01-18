import { clipboard, contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('packetforge', {
  appVersion: process.env.npm_package_version ?? '0.1.0',
  electronVersion: process.versions.electron,
  api: {
    proxy: {
      start: (payload) => ipcRenderer.invoke('proxy:start', payload),
      stop: () => ipcRenderer.invoke('proxy:stop'),
      status: () => ipcRenderer.invoke('proxy:status'),
      configure: (payload) => ipcRenderer.invoke('proxy:configure', payload)
    },
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
    utils: {
      copyText: (text) => clipboard.writeText(text ?? '')
    },
    onSession: (callback) => {
      ipcRenderer.on('session:added', (_event, session) => callback(session));
    },
    onProxyStatus: (callback) => {
      ipcRenderer.on('proxy:status', (_event, status) => callback(status));
    }
  }
});
