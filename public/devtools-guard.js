/* ============================================
   DevTools Guard – Bảo vệ mã nguồn
   Chống mở DevTools (F12, Ctrl+Shift+I, ...)
   ============================================ */

(function () {
  'use strict';

  // === 1. Chặn phím tắt mở DevTools ===
  const BLOCKED_KEYS = [
    { key: 'F12' },                                    // F12
    { ctrl: true, shift: true, key: 'I' },             // Ctrl+Shift+I (Inspect)
    { ctrl: true, shift: true, key: 'J' },             // Ctrl+Shift+J (Console)
    { ctrl: true, shift: true, key: 'C' },             // Ctrl+Shift+C (Element picker)
    { ctrl: true, key: 'U' },                          // Ctrl+U (View source)
    { ctrl: true, key: 'S' },                          // Ctrl+S (Save page)
  ];

  document.addEventListener('keydown', function (e) {
    for (const combo of BLOCKED_KEYS) {
      const ctrlMatch = combo.ctrl ? (e.ctrlKey || e.metaKey) : true;
      const shiftMatch = combo.shift ? e.shiftKey : true;
      const keyMatch = e.key === combo.key || e.key === combo.key.toLowerCase();

      if (ctrlMatch && shiftMatch && keyMatch) {
        // Nếu combo chỉ có key (F12), kiểm tra không phải Ctrl/Shift combo khác
        if (!combo.ctrl && !combo.shift) {
          if (e.key === combo.key) {
            e.preventDefault();
            e.stopPropagation();
            return false;
          }
        } else {
          e.preventDefault();
          e.stopPropagation();
          return false;
        }
      }
    }
  }, true);

  // === 2. Chặn chuột phải (context menu) ===
  document.addEventListener('contextmenu', function (e) {
    e.preventDefault();
    return false;
  });

  // === 3. Phát hiện DevTools bằng kích thước cửa sổ ===
  // Khi DevTools mở docked, kích thước viewport giảm đáng kể
  let devtoolsOpen = false;

  function checkDevTools() {
    const widthThreshold = window.outerWidth - window.innerWidth > 160;
    const heightThreshold = window.outerHeight - window.innerHeight > 160;
    const isOpen = widthThreshold || heightThreshold;

    if (isOpen && !devtoolsOpen) {
      devtoolsOpen = true;
      onDevToolsDetected();
    } else if (!isOpen) {
      devtoolsOpen = false;
    }
  }

  // === 4. Phát hiện DevTools bằng debugger trick ===
  function debuggerCheck() {
    const start = performance.now();
    debugger; // eslint-disable-line no-debugger
    const duration = performance.now() - start;
    // Nếu debugger statement mất > 100ms → DevTools đang mở với pause on debugger
    if (duration > 100) {
      onDevToolsDetected();
    }
  }

  // === 5. Phát hiện DevTools bằng console.log trick ===
  // Khi DevTools đóng, toString() của object không được gọi
  // Khi DevTools mở, console.log sẽ gọi toString() để hiển thị
  const devtoolsDetector = {};
  let consoleCheckActive = true;

  Object.defineProperty(devtoolsDetector, 'id', {
    get: function () {
      if (consoleCheckActive) {
        onDevToolsDetected();
      }
    }
  });

  // === 6. Hành động khi phát hiện DevTools ===
  function onDevToolsDetected() {
    // Hiển thị cảnh báo
    showWarningOverlay();
  }

  let overlayVisible = false;

  function showWarningOverlay() {
    if (overlayVisible) return;
    overlayVisible = true;

    const overlay = document.createElement('div');
    overlay.id = 'devtools-warning-overlay';
    overlay.style.cssText = [
      'position: fixed',
      'top: 0',
      'left: 0',
      'width: 100vw',
      'height: 100vh',
      'background: rgba(0, 0, 0, 0.95)',
      'z-index: 999999',
      'display: flex',
      'align-items: center',
      'justify-content: center',
      'flex-direction: column',
      'color: #ff4444',
      'font-family: Arial, sans-serif',
      'text-align: center',
    ].join(';');

    overlay.innerHTML = [
      '<div style="font-size: 64px; margin-bottom: 20px;">⚠️</div>',
      '<div style="font-size: 24px; font-weight: bold; margin-bottom: 10px;">Developer Tools Detected</div>',
      '<div style="font-size: 16px; color: #ccc; max-width: 500px; line-height: 1.6;">',
      'Việc mở Developer Tools bị hạn chế để bảo vệ mã nguồn và khóa mã hóa.<br>',
      'Vui lòng đóng DevTools để tiếp tục sử dụng ứng dụng.',
      '</div>',
    ].join('');

    document.body.appendChild(overlay);

    // Tự động kiểm tra nếu DevTools đã đóng → gỡ overlay
    const checkInterval = setInterval(function () {
      const widthOk = window.outerWidth - window.innerWidth <= 160;
      const heightOk = window.outerHeight - window.innerHeight <= 160;
      if (widthOk && heightOk) {
        clearInterval(checkInterval);
        overlay.remove();
        overlayVisible = false;
        devtoolsOpen = false;
      }
    }, 500);
  }

  // === Chạy kiểm tra định kỳ ===
  // Kiểm tra kích thước cửa sổ mỗi 1 giây
  setInterval(checkDevTools, 1000);

  // Kiểm tra debugger mỗi 2 giây
  setInterval(debuggerCheck, 2000);

  // Kiểm tra console mỗi 3 giây
  setInterval(function () {
    consoleCheckActive = true;
    console.log('%c', devtoolsDetector);     // eslint-disable-line no-console
    console.clear();                          // eslint-disable-line no-console
    consoleCheckActive = false;
  }, 3000);

  // === 7. Chặn kéo thả (drag) để tránh kéo hình ảnh ra ngoài xem source ===
  document.addEventListener('dragstart', function (e) {
    e.preventDefault();
  });

  // === 8. Chặn chọn text (tùy chọn – có thể bỏ nếu muốn cho phép copy tin nhắn) ===
  // Không chặn toàn bộ, chỉ chặn trên source code elements
  // document.addEventListener('selectstart', function(e) { e.preventDefault(); });

})();
