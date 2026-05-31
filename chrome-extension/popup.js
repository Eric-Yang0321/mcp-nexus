// Popup UI logic
const TOOL_COUNTS = {
  safe: 33,
  mutating: 15,
  destructive: 10,
};

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('safeCount').textContent = `${TOOL_COUNTS.safe} 个 SAFE`;
  document.getElementById('mutatingCount').textContent = `${TOOL_COUNTS.mutating} 个 MUTATING`;
  document.getElementById('destructiveCount').textContent = `${TOOL_COUNTS.destructive} 个 DESTRUCTIVE`;

  // Load saved settings
  chrome.storage.local.get(['mutatingEnabled', 'debugEnabled', 'approveCount'], (data) => {
    document.getElementById('mutatingToggle').checked = data.mutatingEnabled !== false;
    document.getElementById('debugToggle').checked = data.debugEnabled !== false;
    document.getElementById('countDisplay').textContent = data.approveCount || 0;
  });

  // Save on toggle
  document.getElementById('mutatingToggle').addEventListener('change', (e) => {
    chrome.storage.local.set({ mutatingEnabled: e.target.checked });
    updateBadge(e.target.checked);
  });

  document.getElementById('debugToggle').addEventListener('change', (e) => {
    chrome.storage.local.set({ debugEnabled: e.target.checked });
  });

  function updateBadge(on) {
    chrome.action.setBadgeText({ text: on ? 'ON' : '!' });
    chrome.action.setBadgeBackgroundColor({ color: on ? '#4caf50' : '#f44336' });
  }
});

// Set initial badge
chrome.action.setBadgeText({ text: 'ON' });
chrome.action.setBadgeBackgroundColor({ color: '#4caf50' });
