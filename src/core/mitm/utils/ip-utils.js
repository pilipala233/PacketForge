/**
 * IP/MAC 地址工具函数
 */

/**
 * 验证 IP 地址格式
 * @param {string} ip
 * @returns {boolean}
 */
export function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') {
    return false;
  }
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    const num = Number.parseInt(part, 10);
    return num >= 0 && num <= 255 && String(num) === part;
  });
}

/**
 * 验证 MAC 地址格式
 * @param {string} mac
 * @returns {boolean}
 */
export function isValidMac(mac) {
  if (!mac || typeof mac !== 'string') {
    return false;
  }
  const pattern = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return pattern.test(mac);
}

/**
 * 规范化 MAC 地址格式 (转换为 aa:bb:cc:dd:ee:ff)
 * @param {string} mac
 * @returns {string}
 */
export function normalizeMac(mac) {
  if (!mac) {
    return '';
  }
  return mac.toLowerCase().replace(/-/g, ':');
}

/**
 * 计算子网中的所有 IP 地址
 * @param {string} ip - 网络接口 IP
 * @param {string} netmask - 子网掩码
 * @returns {string[]} IP 地址列表
 */
export function getSubnetIps(ip, netmask) {
  const ipParts = ip.split('.').map((p) => Number.parseInt(p, 10));
  const maskParts = netmask.split('.').map((p) => Number.parseInt(p, 10));

  const networkParts = ipParts.map((part, i) => part & maskParts[i]);
  const hostBits = maskParts.reduce((bits, part) => {
    return bits + (8 - part.toString(2).split('1').length + 1);
  }, 0);

  const hostCount = Math.pow(2, hostBits);
  if (hostCount > 256) {
    // 限制扫描范围，避免过大的子网
    return [];
  }

  const ips = [];
  for (let i = 1; i < hostCount - 1; i++) {
    const hostParts = [...networkParts];
    let carry = i;
    for (let j = 3; j >= 0; j--) {
      hostParts[j] += carry & 0xff;
      carry >>= 8;
    }
    ips.push(hostParts.join('.'));
  }

  return ips;
}

/**
 * 将 MAC 地址转换为字节数组
 * @param {string} mac
 * @returns {number[]}
 */
export function macToBytes(mac) {
  return mac.split(':').map((hex) => Number.parseInt(hex, 16));
}

/**
 * 将字节数组转换为 MAC 地址
 * @param {number[]} bytes
 * @returns {string}
 */
export function bytesToMac(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

/**
 * 将 IP 地址转换为字节数组
 * @param {string} ip
 * @returns {number[]}
 */
export function ipToBytes(ip) {
  return ip.split('.').map((part) => Number.parseInt(part, 10));
}

/**
 * 将字节数组转换为 IP 地址
 * @param {number[]} bytes
 * @returns {string}
 */
export function bytesToIp(bytes) {
  return bytes.join('.');
}

/**
 * 将 IP 地址转换为整数
 * @param {string} ip
 * @returns {number}
 */
export function ipToInt(ip) {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

/**
 * 将整数转换为 IP 地址
 * @param {number} int
 * @returns {string}
 */
export function intToIp(int) {
  return [
    (int >>> 24) & 0xff,
    (int >>> 16) & 0xff,
    (int >>> 8) & 0xff,
    int & 0xff
  ].join('.');
}
