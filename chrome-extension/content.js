/**
 * MCP Auto Approve — ChatGPT 智能审批
 *
 * 风险分级:
 *   🟢 SAFE       → 自动点击 Approve，无延迟
 *   🟡 MUTATING    → 自动点击 Approve，300ms 延迟（可观察）
 *   🔴 DESTRUCTIVE → 不点击，保持弹框等你手动决定
 *
 * 机制:
 *   MutationObserver 监听 DOM → 匹配审批弹框 → 提取工具名 → 查风险表 → 点击
 */

const CONFIG = {
  // 哪些工具自动批、哪些不批
  safe: [
    'get_server_status', 'get_docker_containers', 'read_logs',
    'get_processes', 'get_disk_usage', 'get_network_info',
    'get_systemd_services', 'get_docker_logs', 'get_tool_risk_levels',
    'git_status', 'git_diff', 'git_log', 'git_blame', 'git_branch_list',
    'search_code', 'search_files', 'db_query',
    'docker_compose_ps', 'docker_compose_logs',
    'backup_list', 'read_config'
  ],
  mutating: [
    'restart_docker_container', 'restart_systemd_service',
    'append_file', 'run_allowed_command', 'git_checkout',
    'docker_compose_restart', 'backup_create'
  ],
  destructive: [
    'write_file', 'rollback_file', 'git_commit', 'edit_file',
    'backup_restore', 'write_config'
  ],

  // 对话框匹配关键词
  approveTexts: ['approve', 'allow', 'confirm', 'run', 'yes', 'continue',
                  'restart', 'start', 'execute', 'enable', 'accept',
                  '同意', '允许', '确认', '运行', '执行', '批准', '重启', '是'],
  denyTexts: ['deny', 'cancel', 'reject', 'block', 'decline', 'no', 'stop',
              '拒绝', '取消', '阻止', '不', '否'],

  // 延迟设置
  safeDelay: 100,       // SAFE 工具: 100ms
  mutatingDelay: 400,   // MUTATING 工具: 400ms (让你看到它在做什么)
  destructiveDelay: 0,  // DESTRUCTIVE: 不自动批

  // 同工具冷却: 相同工具5秒内不重复批
  cooldownMs: 5000,

  // 调试
  debug: true,
};

// 状态
let lastApproved = {}; // { toolName: timestamp }
let approveCount = 0;

function log(msg) {
  if (CONFIG.debug) console.log(`[MCP AutoApprove] ${msg}`);
}

// 从对话框中提取工具名和风险等级
function identifyTool(dialogText) {
  const text = (dialogText || '').toLowerCase();

  // 匹配已知工具名
  for (const name of [...CONFIG.safe, ...CONFIG.mutating, ...CONFIG.destructive]) {
    // 尝试匹配工具名（可能以不同形式出现）
    const patterns = [
      name,
      name.replace(/_/g, ' '),
      name.split('_').slice(-2).join(' '),
    ];
    for (const p of patterns) {
      if (text.includes(p.toLowerCase())) {
        if (CONFIG.mutating.includes(name)) return { name, risk: 'mutating' };
        if (CONFIG.destructive.includes(name)) return { name, risk: 'destructive' };
        if (CONFIG.safe.includes(name)) return { name, risk: 'safe' };
      }
    }
  }

  // 关键词匹配
  const destructiveWords = ['write', 'delete', 'remove', 'overwrite', 'destroy',
                            'rollback', '写入', '删除', '覆盖', '回滚'];
  const mutatingWords = ['restart', 'append', 'start', 'stop', 'execute', 'run',
                         '重启', '追加', '启动', '停止', '执行'];
  const safeWords = ['get', 'read', 'list', 'status', 'check', 'view', 'show',
                     '获取', '读取', '列表', '状态', '查看', '显示'];

  for (const w of destructiveWords) {
    if (text.includes(w)) return { name: 'unknown', risk: 'destructive' };
  }
  for (const w of mutatingWords) {
    if (text.includes(w)) return { name: 'unknown_mutating', risk: 'mutating' };
  }
  for (const w of safeWords) {
    if (text.includes(w)) return { name: 'unknown_safe', risk: 'safe' };
  }

  return { name: 'unknown', risk: 'mutating' }; // 默认当作需要审批
}

// 检查冷却时间
function isInCooldown(toolName) {
  if (!lastApproved[toolName]) return false;
  return (Date.now() - lastApproved[toolName]) < CONFIG.cooldownMs;
}

// 点击按钮
function clickButton(button) {
  if (!button) return false;

  // 确保按钮可见且可交互
  const rect = button.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return false;

  // 多种点击方式确保 React 能收到
  button.click();
  button.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
  button.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
  button.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
  button.dispatchEvent(new PointerEvent('pointerup', { bubbles: true }));

  return true;
}

// 在对话框中找 Approve 按钮
function findApproveButton(dialogContainer) {
  // 策略1: 查找包含特定文本的按钮
  const allButtons = dialogContainer.querySelectorAll('button, [role="button"], div[tabindex]');

  for (const btn of allButtons) {
    const text = (btn.textContent || '').toLowerCase().trim();
    const ariaLabel = (btn.getAttribute('aria-label') || '').toLowerCase();

    for (const approveWord of CONFIG.approveTexts) {
      if (text === approveWord || text.includes(approveWord) || ariaLabel.includes(approveWord)) {
        // 确认不是 deny 按钮
        for (const denyWord of CONFIG.denyTexts) {
          if (text === denyWord || text.includes(denyWord)) return null;
        }
        return btn;
      }
    }
  }

  // 策略2: 找最后一个主要按钮（通常是 Approve）
  const primaryBtns = dialogContainer.querySelectorAll(
    'button[class*="primary"], button[class*="danger"], button[class*="confirm"], ' +
    'button[class*="accept"], button[class*="approve"], button[class*="continue"]'
  );
  if (primaryBtns.length > 0) {
    return primaryBtns[primaryBtns.length - 1];
  }

  // 策略3: ChatGPT 通常把 approve 放在右边
  const allBtns = Array.from(dialogContainer.querySelectorAll('button'));
  if (allBtns.length >= 2) {
    return allBtns[allBtns.length - 1]; // 最后一个按钮
  }

  return null;
}

// 遍历文档找审批弹框
function findDialog() {
  // ChatGPT 的弹框通常在 portal/modal 中
  // 找包含大量文字 + 按钮的浮层

  const candidates = [];

  // 方法1: 找 role="dialog" 或 role="alertdialog"
  document.querySelectorAll('[role="dialog"], [role="alertdialog"]').forEach(el => {
    candidates.push(el);
  });

  // 方法2: 找固定定位的浮层（ChatGPT 常见模式）
  document.querySelectorAll('div[class*="overlay"], div[class*="modal"], div[class*="popup"]').forEach(el => {
    if (el.offsetParent !== null) candidates.push(el);
  });

  // 方法3: 找包含特定结构的容器（按钮组 + 文字描述）
  document.querySelectorAll('div').forEach(el => {
    const buttons = el.querySelectorAll('button');
    const text = el.textContent || '';
    if (buttons.length >= 2 && text.length > 100 && text.length < 5000) {
      // 检查是否包含 MCP 工具相关文字
      if (CONFIG.safe.some(n => text.includes(n)) ||
          CONFIG.mutating.some(n => text.includes(n)) ||
          CONFIG.destructive.some(n => text.includes(n)) ||
          text.toLowerCase().includes('restart') ||
          text.toLowerCase().includes('write') ||
          text.toLowerCase().includes('execute') ||
          text.toLowerCase().includes('run') && text.toLowerCase().includes('command')) {
        candidates.push(el);
      }
    }
  });

  return candidates[0] || null;
}

// 主处理函数
function processDialog() {
  const dialog = findDialog();
  if (!dialog) return false;

  const dialogText = (dialog.textContent || '').slice(0, 2000);
  const tool = identifyTool(dialogText);

  // 检查冷却
  if (isInCooldown(tool.name)) {
    log(`🕐 ${tool.name} 在冷却中，跳过`);
    return false;
  }

  // DESTRUCTIVE → 不处理
  if (tool.risk === 'destructive') {
    log(`🔴 ${tool.name} — destructive，不自动批`);
    return false;
  }

  // SAFE/MUTATING → 自动点击
  const delay = tool.risk === 'safe' ? CONFIG.safeDelay : CONFIG.mutatingDelay;
  const icon = tool.risk === 'safe' ? '🟢' : '🟡';

  log(`${icon} ${tool.name} — auto-approve in ${delay}ms`);

  setTimeout(() => {
    const btn = findApproveButton(dialog);
    if (btn && clickButton(btn)) {
      lastApproved[tool.name] = Date.now();
      approveCount++;
      log(`✅ [${approveCount}] 已自动批: ${tool.name}`);
    } else {
      log(`⚠️ 未找到 Approve 按钮`);
    }
  }, delay);

  return true;
}

// MutationObserver: 监听 DOM 变化
let processingTimer = null;

function startObserver() {
  const observer = new MutationObserver((mutations) => {
    // 防抖: 批量变化后统一处理
    if (processingTimer) clearTimeout(processingTimer);

    // 检查是否有新增的对话框元素
    let hasDialog = false;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1) {
          const html = node.outerHTML || '';
          if (html.includes('button') && html.length > 200) {
            hasDialog = true;
            break;
          }
        }
      }
      if (hasDialog) break;
    }

    if (hasDialog || mutations.length > 5) {
      processingTimer = setTimeout(() => {
        processDialog();
      }, 500); // 500ms 防抖
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: false,
    characterData: true,
  });

  log('🚀 MCP Auto Approve 已启动');
  log('   🟢 SAFE:    自动批 (100ms)');
  log('   🟡 MUTATING: 自动批 (400ms)');
  log('   🔴 DESTRUCTIVE: 不自动批');
  log(`   已知工具: ${CONFIG.safe.length}S + ${CONFIG.mutating.length}M + ${CONFIG.destructive.length}D`);
}

// 延迟启动，等 ChatGPT 加载完
setTimeout(startObserver, 2000);

// 也监听 URL 变化（SPA 导航）
let lastUrl = location.href;
new MutationObserver(() => {
  if (location.href !== lastUrl) {
    lastUrl = location.href;
    setTimeout(() => processDialog(), 1000);
  }
}).observe(document.querySelector('head'), { childList: true, subtree: true });
