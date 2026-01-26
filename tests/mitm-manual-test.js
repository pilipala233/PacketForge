/**
 * MITM 功能手动测试脚本
 *
 * 使用方法：
 * 1. 以管理员权限运行：node tests/mitm-manual-test.js
 * 2. 按照提示进行测试
 *
 * 注意：此脚本需要管理员权限
 */

import { MitmController } from '../src/core/mitm/index.js';

async function testMitmController() {
  console.log('='.repeat(60));
  console.log('PacketForge MITM 功能测试');
  console.log('='.repeat(60));
  console.log();

  const controller = new MitmController({
    certificateManager: null, // 测试时可以为 null
    rulesStore: null,
    resourcesStore: null,
    sessionsStore: null
  });

  try {
    // 测试 1: 列出网络接口
    console.log('[Test 1] 列出网络接口...');
    const interfaces = await controller.listInterfaces();
    console.log('✓ 找到网络接口:', interfaces.length);
    interfaces.forEach((iface, index) => {
      console.log(`  ${index + 1}. ${iface.name} - ${iface.ip} (${iface.mac})`);
    });
    console.log();

    if (interfaces.length === 0) {
      console.error('✗ 没有找到可用的网络接口');
      return;
    }

    // 测试 2: 扫描网络
    console.log('[Test 2] 扫描网络...');
    const firstInterface = interfaces[0];
    console.log(`使用接口: ${firstInterface.name} (${firstInterface.ip})`);

    const devices = await controller.scanNetwork(firstInterface.name);
    console.log(`✓ 找到设备: ${devices.length}`);
    devices.forEach((device, index) => {
      console.log(`  ${index + 1}. ${device.ip} - ${device.mac} (${device.hostname || 'Unknown'})`);
    });
    console.log();

    // 测试 3: 检查状态
    console.log('[Test 3] 检查 MITM 状态...');
    const status = controller.status();
    console.log('✓ 状态:', status);
    console.log();

    // 测试 4: 启动 MITM (仅测试初始化，不实际启动)
    console.log('[Test 4] 测试 MITM 启动参数验证...');
    console.log('⚠ 跳过实际启动，避免影响网络');
    console.log('如需完整测试，请手动调用 controller.start()');
    console.log();

    console.log('='.repeat(60));
    console.log('✓ 所有测试完成');
    console.log('='.repeat(60));
  } catch (error) {
    console.error('✗ 测试失败:', error.message);
    console.error('详细错误:', error);
  }
}

// 运行测试
testMitmController().catch((error) => {
  console.error('测试脚本错误:', error);
  process.exit(1);
});
