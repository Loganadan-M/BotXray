/**
 * Bot Challenge System
 * Presents challenges to suspicious users to verify they are human
 */

export class BotChallenge {
  constructor() {
    this.isActive = false;
    this.challengesPassed = 0;
    this.challengesFailed = 0;
  }

  /**
   * Create and display a challenge modal
   */
  createChallengeModal(reason, riskScore) {
    if (this.isActive) return;
    this.isActive = true;

    const style = `
      #bot-challenge-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999;
        backdrop-filter: blur(4px);
      }

      #bot-challenge-modal {
        background: white;
        border-radius: 15px;
        padding: 40px;
        max-width: 500px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        animation: slideIn 0.3s ease;
      }

      @keyframes slideIn {
        from { transform: translateY(-50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }

      .challenge-header {
        text-align: center;
        margin-bottom: 30px;
      }

      .challenge-header h2 {
        margin: 0;
        color: #1f2937;
        font-size: 1.5em;
      }

      .challenge-header p {
        color: #6b7280;
        margin: 10px 0 0 0;
        font-size: 0.95em;
      }

      .risk-indicator {
        display: inline-block;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        margin: 15px 0;
        font-size: 0.9em;
      }

      .risk-medium {
        background: #fef3c7;
        color: #92400e;
      }

      .risk-high {
        background: #fee2e2;
        color: #7f1d1d;
      }

      .challenge-content {
        margin: 30px 0;
      }

      .challenge-item {
        margin-bottom: 20px;
      }

      .challenge-item label {
        display: block;
        margin-bottom: 8px;
        color: #1f2937;
        font-weight: 500;
      }

      .challenge-item input[type="text"],
      .challenge-item input[type="number"],
      .challenge-item select {
        width: 100%;
        padding: 10px;
        border: 2px solid #e5e7eb;
        border-radius: 8px;
        font-size: 1em;
        transition: border-color 0.3s;
      }

      .challenge-item input:focus,
      .challenge-item select:focus {
        outline: none;
        border-color: #667eea;
      }

      .puzzle-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 10px;
        margin-top: 10px;
      }

      .puzzle-item {
        width: 100%;
        aspect-ratio: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 2px solid #e5e7eb;
        border-radius: 8px;
        cursor: pointer;
        font-weight: bold;
        font-size: 1.2em;
        transition: all 0.3s;
        user-select: none;
      }

      .puzzle-item:hover {
        background: #f3f4f6;
        border-color: #d1d5db;
      }

      .puzzle-item.selected {
        background: #667eea;
        color: white;
        border-color: #667eea;
      }

      .button-group {
        display: flex;
        gap: 10px;
        margin-top: 30px;
      }

      button {
        flex: 1;
        padding: 12px;
        border: none;
        border-radius: 8px;
        font-size: 1em;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s;
      }

      .btn-verify {
        background: #667eea;
        color: white;
      }

      .btn-verify:hover {
        background: #5568d3;
        transform: translateY(-2px);
      }

      .btn-cancel {
        background: #e5e7eb;
        color: #6b7280;
      }

      .btn-cancel:hover {
        background: #d1d5db;
      }

      .error-message {
        color: #dc2626;
        font-size: 0.9em;
        margin-top: 10px;
        display: none;
      }

      .error-message.show {
        display: block;
      }
    `;

    // Create modal HTML
    const overlay = document.createElement('div');
    overlay.id = 'bot-challenge-overlay';

    const modal = document.createElement('div');
    modal.id = 'bot-challenge-modal';

    const riskLabel = riskScore > 60 ? 'HIGH' : 'MEDIUM';
    const riskClass = riskScore > 60 ? 'risk-high' : 'risk-medium';

    modal.innerHTML = `
      <style>${style}</style>
      <div class="challenge-header">
        <h2>🔐 Verify You're Human</h2>
        <p>We detected unusual activity on your account</p>
        <span class="risk-indicator ${riskClass}">${riskLabel} RISK: ${riskScore}/100</span>
      </div>

      <div class="challenge-content" id="challenge-content">
        <!-- Challenge will be injected here -->
      </div>

      <div id="error-message" class="error-message"></div>

      <div class="button-group">
        <button class="btn-verify" id="btn-submit">Verify</button>
        <button class="btn-cancel" id="btn-cancel">Cancel</button>
      </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Add stylesheet
    const styleSheet = document.createElement('style');
    styleSheet.textContent = style;
    document.head.appendChild(styleSheet);

    return { overlay, modal };
  }

  /**
   * Show a math puzzle challenge
   */
  showMathChallenge() {
    const { overlay, modal } = this.createChallengeModal('math', 65);
    const contentEl = modal.querySelector('#challenge-content');

    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;

    contentEl.innerHTML = `
      <div class="challenge-item">
        <label>What is ${num1} + ${num2}?</label>
        <input type="number" id="math-answer" placeholder="Enter the answer" autofocus>
      </div>
    `;

    const submitBtn = modal.querySelector('#btn-submit');
    const cancelBtn = modal.querySelector('#btn-cancel');
    const errorEl = modal.querySelector('#error-message');

    submitBtn.onclick = () => {
      const userAnswer = parseInt(document.getElementById('math-answer').value);
      if (userAnswer === answer) {
        this.challengesPassed++;
        this.removeChallengeModal(overlay);
        return { passed: true };
      } else {
        this.challengesFailed++;
        errorEl.textContent = `❌ Incorrect answer. The correct answer is ${answer}.`;
        errorEl.classList.add('show');
      }
    };

    cancelBtn.onclick = () => {
      this.removeChallengeModal(overlay);
    };
  }

  /**
   * Show a slider puzzle challenge
   */
  showSliderChallenge() {
    const { overlay, modal } = this.createChallengeModal('slider', 70);
    const contentEl = modal.querySelector('#challenge-content');

    const correctValue = Math.floor(Math.random() * 100) + 1;

    contentEl.innerHTML = `
      <div class="challenge-item">
        <label>Slide to the target: <strong id="target-value">${correctValue}</strong></label>
        <input type="range" id="slider" min="0" max="100" value="50" style="width: 100%; margin-top: 10px;">
        <div style="text-align: center; margin-top: 10px; color: #6b7280;">
          Current: <strong id="current-value">50</strong>
        </div>
      </div>
    `;

    const slider = modal.querySelector('#slider');
    const currentValueEl = modal.querySelector('#current-value');
    const submitBtn = modal.querySelector('#btn-submit');
    const cancelBtn = modal.querySelector('#btn-cancel');
    const errorEl = modal.querySelector('#error-message');

    slider.oninput = () => {
      currentValueEl.textContent = slider.value;
    };

    submitBtn.onclick = () => {
      if (Math.abs(parseInt(slider.value) - correctValue) <= 5) {
        this.challengesPassed++;
        this.removeChallengeModal(overlay);
        return { passed: true };
      } else {
        this.challengesFailed++;
        errorEl.textContent = `❌ Move the slider to ${correctValue}. You were at ${slider.value}.`;
        errorEl.classList.add('show');
      }
    };

    cancelBtn.onclick = () => {
      this.removeChallengeModal(overlay);
    };
  }

  /**
   * Show a pattern matching challenge
   */
  showPatternChallenge() {
    const { overlay, modal } = this.createChallengeModal('pattern', 75);
    const contentEl = modal.querySelector('#challenge-content');

    const pattern = [
      Math.floor(Math.random() * 9),
      Math.floor(Math.random() * 9),
      Math.floor(Math.random() * 9)
    ];

    const options = this.generatePatternOptions(pattern);
    let selectedIndex = null;

    contentEl.innerHTML = `
      <div class="challenge-item">
        <label>Which number comes next in the pattern?<br>
          <strong style="font-size: 1.1em;">${pattern.join(' → ')} → ?</strong>
        </label>
        <div class="puzzle-grid" id="pattern-grid">
          ${options.map((opt, i) => `
            <div class="puzzle-item" data-index="${i}" onclick="this.classList.toggle('selected'); window.selectedPatternIndex = this.classList.contains('selected') ? ${i} : null;">
              ${opt}
            </div>
          `).join('')}
        </div>
      </div>
    `;

    const submitBtn = modal.querySelector('#btn-submit');
    const cancelBtn = modal.querySelector('#btn-cancel');
    const errorEl = modal.querySelector('#error-message');

    submitBtn.onclick = () => {
      const selected = modal.querySelector('.puzzle-item.selected');
      if (!selected) {
        errorEl.textContent = '❌ Please select an answer.';
        errorEl.classList.add('show');
        return;
      }

      const selectedIdx = parseInt(selected.dataset.index);
      if (selectedIdx === 0) { // First option is correct
        this.challengesPassed++;
        this.removeChallengeModal(overlay);
        return { passed: true };
      } else {
        this.challengesFailed++;
        errorEl.textContent = '❌ Incorrect answer. Try again.';
        errorEl.classList.add('show');
      }
    };

    cancelBtn.onclick = () => {
      this.removeChallengeModal(overlay);
    };
  }

  generatePatternOptions(pattern) {
    const diff = pattern[1] - pattern[0];
    const correct = pattern[2] + diff;
    const options = [correct];

    for (let i = 0; i < 2; i++) {
      let wrong = correct + (Math.random() > 0.5 ? 1 : -1) * (Math.floor(Math.random() * 3) + 1);
      while (options.includes(wrong)) {
        wrong = correct + (Math.random() > 0.5 ? 1 : -1) * (Math.floor(Math.random() * 3) + 1);
      }
      options.push(wrong);
    }

    // Shuffle
    return options.sort(() => Math.random() - 0.5);
  }

  /**
   * Remove challenge modal
   */
  removeChallengeModal(overlay) {
    overlay.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => {
      overlay.remove();
      this.isActive = false;
    }, 300);
  }

  /**
   * Trigger a random challenge
   */
  triggerRandomChallenge(riskScore) {
    const challenges = [
      () => this.showMathChallenge(),
      () => this.showSliderChallenge(),
      () => this.showPatternChallenge()
    ];

    const randomChallenge = challenges[Math.floor(Math.random() * challenges.length)];
    randomChallenge();
  }

  /**
   * Get challenge stats
   */
  getStats() {
    return {
      passed: this.challengesPassed,
      failed: this.challengesFailed,
      totalAttempts: this.challengesPassed + this.challengesFailed
    };
  }
}

export const botChallenge = new BotChallenge();
