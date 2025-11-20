/**
 * Sound Effects Utility
 * Provides audio feedback for various quiz events
 */

class SoundManager {
    private audioContext: AudioContext | null = null;
    private sounds: Map<string, AudioBuffer> = new Map();
    private isEnabled: boolean = true;

    constructor() {
        // Initialize Web Audio API
        if (typeof window !== 'undefined' && 'AudioContext' in window) {
            this.audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
        }
    }

    /**
     * Enable or disable sound effects
     */
    setEnabled(enabled: boolean) {
        this.isEnabled = enabled;
    }

    /**
     * Generate a beep sound using Web Audio API
     */
    private generateBeep(frequency: number, duration: number, type: 'sine' | 'square' | 'triangle' = 'sine'): void {
        if (!this.audioContext || !this.isEnabled) return;

        const oscillator = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        oscillator.frequency.value = frequency;
        oscillator.type = type;

        gainNode.gain.setValueAtTime(0.3, this.audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + duration);

        oscillator.start(this.audioContext.currentTime);
        oscillator.stop(this.audioContext.currentTime + duration);
    }

    /**
     * Play a success sound (correct answer, rank up)
     */
    playSuccess(): void {
        if (!this.isEnabled) return;
        // Ascending tone sequence
        this.generateBeep(523.25, 0.1, 'sine'); // C5
        setTimeout(() => this.generateBeep(659.25, 0.1, 'sine'), 100); // E5
        setTimeout(() => this.generateBeep(783.99, 0.2, 'sine'), 200); // G5
    }

    /**
     * Play a rank up sound
     */
    playRankUp(): void {
        if (!this.isEnabled) return;
        // Exciting ascending sequence
        this.generateBeep(440, 0.15, 'sine'); // A4
        setTimeout(() => this.generateBeep(554.37, 0.15, 'sine'), 150); // C#5
        setTimeout(() => this.generateBeep(659.25, 0.2, 'sine'), 300); // E5
        setTimeout(() => this.generateBeep(783.99, 0.3, 'sine'), 500); // G5
    }

    /**
     * Play a rank down sound
     */
    playRankDown(): void {
        if (!this.isEnabled) return;
        // Descending tone
        this.generateBeep(392, 0.2, 'sine'); // G4
        setTimeout(() => this.generateBeep(329.63, 0.2, 'sine'), 200); // E4
    }

    /**
     * Play timer warning sound (when time is running low)
     */
    playTimerWarning(): void {
        if (!this.isEnabled) return;
        // Urgent beep
        this.generateBeep(800, 0.1, 'square');
    }

    /**
     * Play timer critical sound (last few seconds)
     */
    playTimerCritical(): void {
        if (!this.isEnabled) return;
        // Fast urgent beeps
        this.generateBeep(1000, 0.08, 'square');
        setTimeout(() => this.generateBeep(1200, 0.08, 'square'), 100);
    }

    /**
     * Play winner celebration sound
     */
    playWinner(): void {
        if (!this.isEnabled) return;
        // Victory fanfare
        const notes = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6
        notes.forEach((freq, index) => {
            setTimeout(() => {
                this.generateBeep(freq, 0.2, 'sine');
            }, index * 150);
        });
    }

    /**
     * Play first place sound
     */
    playFirstPlace(): void {
        if (!this.isEnabled) return;
        // Gold medal sound - triumphant
        const notes = [523.25, 659.25, 783.99, 987.77, 1174.66]; // C5, E5, G5, B5, D6
        notes.forEach((freq, index) => {
            setTimeout(() => {
                this.generateBeep(freq, 0.25, 'sine');
            }, index * 120);
        });
    }

    /**
     * Play error/wrong answer sound
     */
    playError(): void {
        if (!this.isEnabled) return;
        // Low descending tone
        this.generateBeep(200, 0.3, 'square');
    }

    /**
     * Play notification sound
     */
    playNotification(): void {
        if (!this.isEnabled) return;
        this.generateBeep(600, 0.15, 'sine');
    }
}

// Export singleton instance
export const soundManager = new SoundManager();

