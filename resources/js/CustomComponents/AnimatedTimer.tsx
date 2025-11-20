import React, { useEffect, useState } from 'react';
import { Clock, AlertTriangle } from 'lucide-react';
import { soundManager } from '../utils/soundEffects';

interface AnimatedTimerProps {
    timeLeft: number | null;
    totalTime: number;
    onTimeUp?: () => void;
}

const AnimatedTimer: React.FC<AnimatedTimerProps> = ({ timeLeft, totalTime, onTimeUp }) => {
    const [pulse, setPulse] = useState(false);
    const [shake, setShake] = useState(false);
    const [lastPlayedWarning, setLastPlayedWarning] = useState(false);

    useEffect(() => {
        if (timeLeft === null) return;

        // Visual urgency effects
        if (timeLeft <= 5 && timeLeft > 0) {
            // Critical time - fast pulse
            const interval = setInterval(() => {
                setPulse(prev => !prev);
            }, 300);
            setShake(true);

            // Play critical sound
            if (!lastPlayedWarning) {
                soundManager.playTimerCritical();
                setLastPlayedWarning(true);
            }

            return () => {
                clearInterval(interval);
                setShake(false);
            };
        } else if (timeLeft <= 10 && timeLeft > 5) {
            // Warning time - slower pulse
            const interval = setInterval(() => {
                setPulse(prev => !prev);
            }, 600);
            setLastPlayedWarning(false);

            // Play warning sound every 2 seconds
            if (timeLeft % 2 === 0) {
                soundManager.playTimerWarning();
            }

            return () => clearInterval(interval);
        } else {
            setPulse(false);
            setShake(false);
            setLastPlayedWarning(false);
        }

        // Time's up
        if (timeLeft === 0 && onTimeUp) {
            soundManager.playError();
            onTimeUp();
        }
    }, [timeLeft, onTimeUp, lastPlayedWarning]);

    if (timeLeft === null) {
        return (
            <div className="flex items-center gap-2 text-gray-600">
                <Clock className="w-5 h-5" />
                <span className="text-lg font-semibold">No time limit</span>
            </div>
        );
    }

    const percentage = (timeLeft / totalTime) * 100;
    const isCritical = timeLeft <= 5;
    const isWarning = timeLeft <= 10 && timeLeft > 5;

    // Determine color based on time remaining
    let timerColor = 'text-blue-600';
    let bgColor = 'bg-blue-100';
    let borderColor = 'border-blue-500';
    let glowColor = 'shadow-blue-500/50';

    if (isCritical) {
        timerColor = 'text-red-600';
        bgColor = 'bg-red-100';
        borderColor = 'border-red-500';
        glowColor = 'shadow-red-500/50';
    } else if (isWarning) {
        timerColor = 'text-orange-600';
        bgColor = 'bg-orange-100';
        borderColor = 'border-orange-500';
        glowColor = 'shadow-orange-500/50';
    }

    return (
        <div className={`flex items-center gap-3 ${shake ? 'animate-shake' : ''}`}>
            {isCritical && (
                <AlertTriangle className={`w-6 h-6 ${timerColor} animate-pulse`} />
            )}
            <div
                className={`
                    relative px-6 py-3 rounded-lg border-2 ${borderColor} ${bgColor}
                    ${pulse ? 'animate-pulse' : ''}
                    transition-all duration-300
                    ${isCritical ? 'shadow-lg ' + glowColor : ''}
                `}
            >
                <div className="flex items-center gap-2">
                    <Clock className={`w-5 h-5 ${timerColor}`} />
                    <span className={`text-2xl font-bold ${timerColor}`}>
                        {timeLeft}
                    </span>
                    <span className="text-sm text-gray-600">seconds</span>
                </div>

                {/* Progress bar */}
                <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-200 rounded-b-lg overflow-hidden">
                    <div
                        className={`h-full transition-all duration-1000 ${
                            isCritical ? 'bg-red-500' : isWarning ? 'bg-orange-500' : 'bg-blue-500'
                        }`}
                        style={{ width: `${percentage}%` }}
                    />
                </div>
            </div>

            <style>{`
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-4px); }
                    75% { transform: translateX(4px); }
                }
                .animate-shake {
                    animation: shake 0.3s ease-in-out infinite;
                }
            `}</style>
        </div>
    );
};

export default AnimatedTimer;

