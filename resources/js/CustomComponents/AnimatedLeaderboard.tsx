import React, { useEffect, useState, useRef } from 'react';
import { Trophy, Medal, Award, TrendingUp, TrendingDown } from 'lucide-react';
import { soundManager } from '../utils/soundEffects';

interface LeaderboardEntry {
    id: number;
    rank: number;
    team: string;
    score: number;
    prev_answer_correct?: number;
    prev_answer?: string;
}

interface AnimatedLeaderboardProps {
    leaderboard: LeaderboardEntry[];
    teamId: number;
    previousLeaderboard?: LeaderboardEntry[];
    showRankChanges?: boolean;
}

const AnimatedLeaderboard: React.FC<AnimatedLeaderboardProps> = ({
    leaderboard,
    teamId,
    previousLeaderboard = [],
    showRankChanges = true,
}) => {
    const [displayLeaderboard, setDisplayLeaderboard] = useState(leaderboard);
    const [rankChanges, setRankChanges] = useState<Map<number, number>>(new Map());
    const previousRanksRef = useRef<Map<number, number>>(new Map());

    useEffect(() => {
        // Calculate rank changes
        const changes = new Map<number, number>();
        
        if (previousLeaderboard.length > 0) {
            previousLeaderboard.forEach((entry) => {
                previousRanksRef.current.set(entry.id, entry.rank);
            });

            leaderboard.forEach((entry) => {
                const previousRank = previousRanksRef.current.get(entry.id);
                if (previousRank && previousRank !== entry.rank) {
                    const change = previousRank - entry.rank; // Positive = moved up, Negative = moved down
                    changes.set(entry.id, change);

                    // Play sound effects
                    if (change > 0) {
                        soundManager.playRankUp();
                    } else if (change < 0) {
                        soundManager.playRankDown();
                    }
                }
            });
        }

        setRankChanges(changes);

        // Animate leaderboard update
        setDisplayLeaderboard(leaderboard.map((entry, index) => ({
            ...entry,
            rank: index + 1,
        })));

        // Check for winners and play celebration sounds
        if (leaderboard.length > 0) {
            const firstPlace = leaderboard[0];
            if (firstPlace.id === teamId && firstPlace.rank === 1) {
                setTimeout(() => {
                    soundManager.playFirstPlace();
                }, 500);
            }
        }
    }, [leaderboard, previousLeaderboard, teamId]);

    const getRankIcon = (rank: number) => {
        switch (rank) {
            case 1:
                return <Trophy className="w-6 h-6 text-yellow-500" />;
            case 2:
                return <Medal className="w-6 h-6 text-gray-400" />;
            case 3:
                return <Award className="w-6 h-6 text-amber-600" />;
            default:
                return null;
        }
    };

    const getRankBadgeColor = (rank: number) => {
        switch (rank) {
            case 1:
                return 'bg-gradient-to-r from-yellow-400 via-yellow-500 to-yellow-600 shadow-yellow-500/50';
            case 2:
                return 'bg-gradient-to-r from-gray-300 via-gray-400 to-gray-500 shadow-gray-400/50';
            case 3:
                return 'bg-gradient-to-r from-amber-500 via-amber-600 to-amber-700 shadow-amber-500/50';
            default:
                return 'bg-gradient-to-r from-orange-500 to-orange-600 shadow-orange-200';
        }
    };

    const getRankChangeIndicator = (entryId: number) => {
        const change = rankChanges.get(entryId);
        if (!change || !showRankChanges) return null;

        if (change > 0) {
            return (
                <div className="flex items-center gap-1 text-green-600 animate-slide-up">
                    <TrendingUp className="w-4 h-4" />
                    <span className="text-sm font-semibold">+{change}</span>
                </div>
            );
        } else if (change < 0) {
            return (
                <div className="flex items-center gap-1 text-red-600 animate-slide-down">
                    <TrendingDown className="w-4 h-4" />
                    <span className="text-sm font-semibold">{change}</span>
                </div>
            );
        }
        return null;
    };

    return (
        <div className="space-y-2">
            {displayLeaderboard.map((entry, index) => {
                const isCurrentTeam = entry.id === teamId;
                const rankChange = rankChanges.get(entry.id);
                const isWinner = entry.rank <= 3;
                const isMoving = rankChange !== undefined && rankChange !== 0;

                return (
                    <div
                        key={entry.id}
                        className={`
                            relative p-4 rounded-lg border-2 transition-all duration-500 ease-in-out
                            ${isCurrentTeam 
                                ? 'bg-orange-500/50 border-orange-500 shadow-lg' 
                                : 'bg-white border-gray-200 hover:border-orange-300'
                            }
                            ${isWinner ? 'shadow-xl ' + (entry.rank === 1 ? 'shadow-yellow-500/30' : entry.rank === 2 ? 'shadow-gray-400/30' : 'shadow-amber-500/30') : ''}
                            ${isMoving ? (rankChange! > 0 ? 'animate-slide-up' : 'animate-slide-down') : ''}
                            ${isWinner ? 'animate-pulse-slow' : ''}
                        `}
                        style={{
                            animationDelay: `${index * 50}ms`,
                        }}
                    >
                        {/* Winner glow effect for top 3 */}
                        {isWinner && (
                            <div
                                className={`
                                    absolute inset-0 rounded-lg opacity-20 blur-xl
                                    ${entry.rank === 1 ? 'bg-yellow-400' : entry.rank === 2 ? 'bg-gray-300' : 'bg-amber-500'}
                                    animate-pulse
                                `}
                            />
                        )}

                        <div className="relative flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                {/* Rank Badge */}
                                <div
                                    className={`
                                        flex items-center justify-center w-12 h-12 rounded-lg font-bold text-white
                                        ${getRankBadgeColor(entry.rank)}
                                        ${isWinner ? 'animate-bounce-slow' : ''}
                                        transition-transform duration-300
                                    `}
                                >
                                    {getRankIcon(entry.rank) || <span>{entry.rank}</span>}
                                </div>

                                {/* Team Name */}
                                <div className="flex flex-col">
                                    <div className="flex items-center gap-2">
                                        <span className={`text-xl font-bold ${isCurrentTeam ? 'text-orange-900' : 'text-gray-900'}`}>
                                            {entry.team}
                                        </span>
                                        {isCurrentTeam && (
                                            <span className="px-2 py-1 text-xs font-semibold bg-orange-600 text-white rounded-full">
                                                You
                                            </span>
                                        )}
                                    </div>
                                    {getRankChangeIndicator(entry.id)}
                                </div>
                            </div>

                            {/* Score */}
                            <div className="flex items-center gap-3">
                                {isWinner && entry.rank === 1 && (
                                    <div className="text-yellow-500 animate-spin-slow">
                                        <Trophy className="w-6 h-6" />
                                    </div>
                                )}
                                <div
                                    className={`
                                        text-2xl font-bold px-4 py-2 rounded-lg
                                        ${isWinner 
                                            ? entry.rank === 1 
                                                ? 'bg-yellow-100 text-yellow-700' 
                                                : entry.rank === 2 
                                                    ? 'bg-gray-100 text-gray-700' 
                                                    : 'bg-amber-100 text-amber-700'
                                            : 'bg-orange-100 text-orange-700'
                                        }
                                        transition-all duration-300
                                        ${isMoving ? 'scale-110' : ''}
                                    `}
                                >
                                    {entry.score}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            })}

            <style>{`
                @keyframes slide-up {
                    0% {
                        transform: translateY(20px);
                        opacity: 0.5;
                    }
                    100% {
                        transform: translateY(0);
                        opacity: 1;
                    }
                }

                @keyframes slide-down {
                    0% {
                        transform: translateY(-20px);
                        opacity: 0.5;
                    }
                    100% {
                        transform: translateY(0);
                        opacity: 1;
                    }
                }

                @keyframes pulse-slow {
                    0%, 100% {
                        opacity: 1;
                    }
                    50% {
                        opacity: 0.8;
                    }
                }

                @keyframes bounce-slow {
                    0%, 100% {
                        transform: translateY(0);
                    }
                    50% {
                        transform: translateY(-5px);
                    }
                }

                @keyframes spin-slow {
                    from {
                        transform: rotate(0deg);
                    }
                    to {
                        transform: rotate(360deg);
                    }
                }

                .animate-slide-up {
                    animation: slide-up 0.5s ease-out;
                }

                .animate-slide-down {
                    animation: slide-down 0.5s ease-out;
                }

                .animate-pulse-slow {
                    animation: pulse-slow 2s ease-in-out infinite;
                }

                .animate-bounce-slow {
                    animation: bounce-slow 1s ease-in-out infinite;
                }

                .animate-spin-slow {
                    animation: spin-slow 3s linear infinite;
                }
            `}</style>
        </div>
    );
};

export default AnimatedLeaderboard;

