// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * TSUMUJI (旋風 / Pet) — The Wind-Wisp.
 *
 * Rules:
 * 1. Zero network/API calls (strict offline local-only logic).
 * 2. Reads only the in-memory or DOM verdict string.
 * 3. Max one 500ms tick when document is visible; zero timers running when document.hidden.
 * 4. Appears only after 90s idle; hides immediately on user input.
 * 5. Fixed corner, pointer-events on itself only, aria-hidden.
 * 6. Toggled via ':pet off' / ':pet on' (saved in localStorage).
 * 7. Tiny local keyboard mini-game upon petting/interaction.
 */

(function (root) {
  'use strict';

  const STORAGE_KEY = 'kazeshini_pet_enabled';

  // Wind-Wisp ASCII Frames per mood:
  // Sleeping (CALM)
  const FRAMES_SLEEP = [
    '( -.- )~',
    '( -.- )~~',
    '( -.- )~ ',
    '( -.- )  '
  ];

  // Wandering (Idle / Normal)
  const FRAMES_WANDER = [
    '( o.o )~',
    '~( o.o )',
    '( o.o )~~',
    '~~( o.o )'
  ];

  // Alert (CRITICAL)
  const FRAMES_ALERT = [
    '( !.! )~!',
    '!( !.! )~',
    '( !.! )!!',
    '!( !.! )~!'
  ];

  // Squinting (PARTIAL / UNKNOWN / Stale)
  const FRAMES_SQUINT = [
    '( ~.~ )~?',
    '?( ~.~ )~',
    '( ~.~ )~',
    '~( ~.~ )?'
  ];

  // Playful / Pet mini-game frames
  const FRAMES_PET = [
    '( ^.^ )*',
    '*( ^.^ )~',
    '( ^.^ )**',
    '**( ^.^ )'
  ];

  class TsumujiPet {
    constructor() {
      this.enabled = this.getStoredEnabled();
      this.idleSeconds = 0;
      this.idleThreshold = 90; // 90s idle
      this.currentFrame = 0;
      this.mood = 'wander'; // sleep, wander, alert, squint, playful
      this.miniGameActive = false;
      this.miniGameScore = 0;
      this.targetKey = 'ArrowUp';

      this.timerId = null;
      this.container = null;
      this.petEl = null;
      this.dialogEl = null;

      this.initDOM();
      this.attachListeners();
      this.updateVisibility();
      this.startLoop();
    }

    getStoredEnabled() {
      try {
        const item = localStorage.getItem(STORAGE_KEY);
        return item === null ? true : item === 'true';
      } catch (e) {
        return true;
      }
    }

    setStoredEnabled(val) {
      this.enabled = !!val;
      try {
        localStorage.setItem(STORAGE_KEY, this.enabled ? 'true' : 'false');
      } catch (e) {
        // Safe fallback if localStorage disabled
      }
      this.updateVisibility();
    }

    initDOM() {
      let wrap = document.getElementById('tsumuji-pet-container');
      if (!wrap) {
        wrap = document.createElement('div');
        wrap.id = 'tsumuji-pet-container';
        wrap.className = 'tsumuji-container';
        wrap.setAttribute('aria-hidden', 'true');

        wrap.innerHTML = `
          <div id="tsumuji-dialog" class="tsumuji-dialog" style="display: none;"></div>
          <div id="tsumuji-sprite" class="tsumuji-sprite" role="img" title="Tsumuji the wind-wisp (click to pet)">
            <pre id="tsumuji-ascii">( -.- )~</pre>
          </div>
        `;
        document.body.appendChild(wrap);
      }

      this.container = wrap;
      this.petEl = document.getElementById('tsumuji-ascii');
      this.dialogEl = document.getElementById('tsumuji-dialog');

      if (this.container) {
        this.container.addEventListener('click', (e) => {
          e.stopPropagation();
          this.handlePetClick();
        });
      }
    }

    attachListeners() {
      // Reset idle timer on user activity
      const resetIdle = () => {
        this.idleSeconds = 0;
        if (!this.miniGameActive) {
          this.updateVisibility();
        }
      };

      window.addEventListener('mousemove', resetIdle, { passive: true });
      window.addEventListener('keydown', (e) => {
        if (this.miniGameActive) {
          this.handleMiniGameKey(e);
          return;
        }
        resetIdle();
      }, { passive: false });
      window.addEventListener('touchstart', resetIdle, { passive: true });
      window.addEventListener('click', () => {
        if (!this.miniGameActive) resetIdle();
      }, { passive: true });

      // Page visibility change: zero timers when document is hidden!
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
          this.stopLoop();
        } else {
          this.startLoop();
        }
      });
    }

    startLoop() {
      if (this.timerId !== null) return;
      // Single 500ms ticker for idle counting and animation
      this.timerId = setInterval(() => {
        this.tick();
      }, 500);
    }

    stopLoop() {
      if (this.timerId !== null) {
        clearInterval(this.timerId);
        this.timerId = null;
      }
    }

    tick() {
      if (!this.enabled) {
        this.hide();
        return;
      }

      // Advance idle timer every 2 ticks (1000ms)
      this.currentFrame++;
      if (this.currentFrame % 2 === 0) {
        this.idleSeconds++;
      }

      this.updateVisibility();

      if (this.isVisuallyShown()) {
        this.updateMood();
        this.renderFrame();
      }
    }

    updateVisibility() {
      if (!this.enabled) {
        this.hide();
        return;
      }
      if (this.miniGameActive || this.idleSeconds >= this.idleThreshold) {
        this.show();
      } else {
        this.hide();
      }
    }

    isVisuallyShown() {
      return this.container && this.container.style.display !== 'none';
    }

    show() {
      if (this.container && this.container.style.display !== 'flex') {
        this.container.style.display = 'flex';
      }
    }

    hide() {
      if (this.container && this.container.style.display !== 'none') {
        this.container.style.display = 'none';
      }
      if (this.dialogEl) {
        this.dialogEl.style.display = 'none';
      }
      this.miniGameActive = false;
    }

    updateMood() {
      if (this.miniGameActive) {
        this.mood = 'playful';
        return;
      }

      // Read only verdict string from DOM, no network calls!
      let verdictText = 'CALM';
      const badge = document.getElementById('chaos-badge');
      if (badge && badge.textContent) {
        verdictText = badge.textContent.toUpperCase();
      }

      if (verdictText.includes('CRITICAL')) {
        this.mood = 'alert';
      } else if (verdictText.includes('PARTIAL') || verdictText.includes('UNKNOWN')) {
        this.mood = 'squint';
      } else if (verdictText.includes('CALM')) {
        this.mood = 'sleep';
      } else {
        this.mood = 'wander';
      }
    }

    renderFrame() {
      if (!this.petEl) return;

      let frameList = FRAMES_WANDER;
      switch (this.mood) {
        case 'sleep':
          frameList = FRAMES_SLEEP;
          break;
        case 'alert':
          frameList = FRAMES_ALERT;
          break;
        case 'squint':
          frameList = FRAMES_SQUINT;
          break;
        case 'playful':
          frameList = FRAMES_PET;
          break;
      }

      const idx = this.currentFrame % frameList.length;
      this.petEl.textContent = frameList[idx];
    }

    handlePetClick() {
      if (!this.enabled) return;

      // Start tiny keyboard mini-game: Wind Catch!
      this.miniGameActive = true;
      this.miniGameScore = 0;
      this.show();
      this.nextMiniGameTarget();
    }

    nextMiniGameTarget() {
      const keys = ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'];
      const symbols = { ArrowUp: '↑', ArrowDown: '↓', ArrowLeft: '←', ArrowRight: '→' };
      this.targetKey = keys[Math.floor(Math.random() * keys.length)];

      if (this.dialogEl) {
        this.dialogEl.style.display = 'block';
        this.dialogEl.innerHTML = `
          <div style="font-size: 11px; color: var(--mint);">PETTING TSUMUJI! [Score: ${this.miniGameScore}]</div>
          <div style="font-size: 12px; margin-top: 2px;">Press <strong style="color: var(--cyan);">${symbols[this.targetKey]}</strong> key! (Esc to stop)</div>
        `;
      }
    }

    handleMiniGameKey(e) {
      if (e.key === 'Escape') {
        this.miniGameActive = false;
        if (this.dialogEl) {
          this.dialogEl.style.display = 'none';
        }
        this.idleSeconds = 0;
        this.updateVisibility();
        return;
      }

      if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
        e.preventDefault();
        if (e.key === this.targetKey) {
          this.miniGameScore++;
          this.currentFrame++;
          this.renderFrame();
          if (this.miniGameScore >= 5) {
            // Success cheer!
            if (this.dialogEl) {
              this.dialogEl.innerHTML = `<span style="color: var(--mint);">*purr* ~ Tsumuji is happy! (5/5)</span>`;
            }
            setTimeout(() => {
              this.miniGameActive = false;
              if (this.dialogEl) this.dialogEl.style.display = 'none';
              this.idleSeconds = 0;
              this.updateVisibility();
            }, 1200);
            return;
          }
          this.nextMiniGameTarget();
        } else {
          // Missed key
          if (this.dialogEl) {
            this.dialogEl.innerHTML = `<span style="color: var(--peach);">Whoosh! Missed key. Try again!</span>`;
          }
          setTimeout(() => {
            if (this.miniGameActive) this.nextMiniGameTarget();
          }, 600);
        }
      }
    }
  }

  // Instantiate singleton
  const petInstance = new TsumujiPet();

  // Export control functions globally for command palette and console
  root.Tsumuji = {
    set: function (state) {
      petInstance.setStoredEnabled(state);
      return petInstance.enabled ? 'TSUMUJI pet activated.' : 'TSUMUJI pet deactivated.';
    },
    toggle: function () {
      petInstance.setStoredEnabled(!petInstance.enabled);
      return petInstance.enabled ? 'TSUMUJI enabled.' : 'TSUMUJI disabled.';
    },
    isEnabled: function () {
      return petInstance.enabled;
    },
    triggerMiniGame: function () {
      petInstance.handlePetClick();
    }
  };

})(window);
