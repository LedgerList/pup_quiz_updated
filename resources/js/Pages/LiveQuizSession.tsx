import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, router, usePage } from '@inertiajs/react';
import React, { useState, useEffect, useMemo, useCallback } from 'react'; // Added useCallback
import { AlertCircle, PlayCircle, FastForward, CheckCircle, Award, User, XCircle, Loader, Download, Printer } from 'lucide-react';
import Swal from 'sweetalert2';
import AnimatedTimer from '@/CustomComponents/AnimatedTimer';

interface Option {
    id: number;
    option_text: string;
    is_correct: boolean;
}

interface Question {
    id: number;
    type: 'multiple-choice' | 'true-false' | 'short-answer';
    question_text: string;
    image_path?: string;
    time_limit?: number; // Time limit in seconds
    points?: number;
    difficulty: 'easy' | 'average' | 'hard';
    options?: Option[];
    true_false_answer?: boolean;
    short_answer?: string;
}

interface Quiz {
    id: number;
    title: string;
    code: string;
    questions: Question[];
}

interface LiveSessionData {
    quiz_id: number;
    current_question_index: number;
    show_answer: boolean;
    status: 'waiting' | 'active' | 'finished';
    session_host_id: number;
}

interface ParticipantData {
    user_id: number;
    user_name: string;
    score: number;
    last_answer_time?: string;
    answers?: { [questionId: string]: { submitted: any; is_correct: boolean; points_awarded: number; } };
}

interface LiveQuizSessionProps {
    quiz: Quiz;
}

export default function LiveQuizSession({ quiz }: LiveQuizSessionProps) {
    const { auth } = usePage().props as any;
    const currentUserId = auth.user?.id;

    const [liveSession, setLiveSession] = useState<LiveSessionData | null>(null);
    const [participants, setParticipants] = useState<ParticipantData[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [timeLeft, setTimeLeft] = useState<number | null>(null); // State for countdown timer

    const sessionId = quiz.id;

    useEffect(() => {
        const fetchSessionData = async () => {
            if (!currentUserId) {
                setError('Please log in to view the live quiz session.');
                setLoading(false);
                return;
            }

            try {
                // Get CSRF token
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
                
                // Fetch session with proper headers
                const sessionResponse = await fetch(`/api/live-quizzes/${sessionId}/session`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'include', // Include cookies for session auth
                });

                if (!sessionResponse.ok) {
                    if (sessionResponse.status === 404 && currentUserId) {
                        // Attempt to create session if not found (assuming current user is host)
                        const initialSession = {
                            quiz_id: quiz.id,
                            current_question_index: 0,
                            show_answer: false,
                            status: 'waiting',
                            session_host_id: currentUserId,
                        };
                        const createSessionResponse = await fetch(`/api/live-quizzes/${sessionId}/create-session`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json',
                                'X-CSRF-TOKEN': csrfToken,
                                'X-Requested-With': 'XMLHttpRequest',
                            },
                            credentials: 'include',
                            body: JSON.stringify(initialSession),
                        });
                        if (createSessionResponse.ok) {
                            const newSession = await createSessionResponse.json();
                            setLiveSession(newSession);
                        } else {
                            const errorData = await createSessionResponse.json().catch(() => ({}));
                            throw new Error(errorData.message || `Failed to create session: ${createSessionResponse.statusText}`);
                        }
                    } else if (sessionResponse.status === 401 || sessionResponse.status === 403) {
                        throw new Error('You are not authorized to view this session.');
                    } else {
                        const errorData = await sessionResponse.json().catch(() => ({}));
                        throw new Error(errorData.message || `Failed to fetch session: ${sessionResponse.statusText}`);
                    }
                } else {
                    const sessionData = await sessionResponse.json();
                    setLiveSession(sessionData);
                }

                // Fetch participants with proper headers
                const participantsResponse = await fetch(`/api/live-quizzes/${sessionId}/participants`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'include',
                });
                
                if (!participantsResponse.ok) {
                    // Don't throw error for participants, just set empty array
                    if (participantsResponse.status === 404) {
                        setParticipants([]);
                    } else {
                        console.warn('Failed to fetch participants:', participantsResponse.statusText);
                        setParticipants([]);
                    }
                } else {
                    const participantsData: ParticipantData[] = await participantsResponse.json();
                    participantsData.sort((a, b) => {
                        // Sort by score (descending), then by last answer time (ascending) for ties
                        if (b.score !== a.score) {
                            return b.score - a.score;
                        }
                        const dateA = a.last_answer_time ? new Date(a.last_answer_time).getTime() : 0;
                        const dateB = b.last_answer_time ? new Date(b.last_answer_time).getTime() : 0;
                        return dateA - dateB;
                    });
                    setParticipants(Array.isArray(participantsData) ? participantsData : []);
                }

            } catch (err: any) {
                console.error("Error fetching live session data or participants:", err);
                
                // Handle network errors specifically
                if (err.message?.includes('Failed to fetch') || err.message?.includes('ERR_CONNECTION_REFUSED') || err.message?.includes('NetworkError')) {
                    setError('Unable to connect to the server. Please check your internet connection and try again.');
                } else if (err.message) {
                    setError(`Failed to load data: ${err.message}`);
                } else {
                    setError('Failed to load data. Please try again.');
                }
            } finally {
                setLoading(false);
            }
        };

        fetchSessionData();

        const pollInterval = setInterval(fetchSessionData, 2000); // Poll every 2 seconds

        return () => clearInterval(pollInterval);
    }, [sessionId, quiz.id, currentUserId]);

    const currentQuestion = useMemo(() => {
        return liveSession && liveSession.current_question_index < quiz.questions.length
            ? quiz.questions[liveSession.current_question_index]
            : null;
    }, [liveSession, quiz.questions]);

    const isHost = currentUserId && liveSession?.session_host_id === currentUserId;

    // Use useCallback for host actions to provide stable function references
    const sendHostAction = useCallback(async (endpoint: string, method: string = 'POST', body?: any) => {
        if (!currentUserId || !isHost) {
            Swal.fire({
                icon: 'error',
                title: 'Authorization Error',
                text: 'You are not authorized to perform this action (Not host or not logged in).',
            });
            return;
        }
        try {
            const response = await fetch(`/api/live-quizzes/${sessionId}/${endpoint}`, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]')!.getAttribute('content')!,
                },
                body: JSON.stringify(body),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || response.statusText);
            }
        } catch (e: any) {
            console.error(`Error in ${endpoint}:`, e);
            Swal.fire({
                icon: 'error',
                title: 'Action Failed',
                text: `Error performing action: ${e.message}`,
            });
        }
    }, [currentUserId, isHost, sessionId]);

    const handleNextQuestion = useCallback(async () => {
        if (!liveSession) return;
        const nextIndex = liveSession.current_question_index + 1;

        if (nextIndex < quiz.questions.length) {
            await sendHostAction('next-question', 'POST', { next_question_index: nextIndex });
        } else {
            await sendHostAction('end-quiz');
            Swal.fire({
                icon: 'info',
                title: 'Quiz Finished!',
                text: 'The quiz has ended. You can now check the overall results.',
            });
        }
    }, [liveSession, quiz.questions.length, sendHostAction]);

    const handleStartQuiz = useCallback(async () => {
        if (!liveSession || liveSession.status === 'active') return;
        await sendHostAction('start-quiz');
    }, [liveSession, sendHostAction]);

    const handleRevealAnswer = useCallback(async () => {
        if (!liveSession || liveSession.show_answer) return;
        await sendHostAction('reveal-answer');
    }, [liveSession, sendHostAction]);

    // Timer logic
    useEffect(() => {
        let timer: NodeJS.Timeout | null = null;
        if (liveSession && liveSession.status === 'active' && currentQuestion && currentQuestion.time_limit !== undefined) {
            // Set initial time when question changes or session becomes active
            if (timeLeft === null || timeLeft === 0 || liveSession.current_question_index !== quiz.questions.indexOf(currentQuestion)) {
                   setTimeLeft(currentQuestion.time_limit);
            }

            if (isHost && timeLeft !== null && timeLeft > 0 && !liveSession.show_answer) {
                timer = setInterval(() => {
                    setTimeLeft((prevTime) => {
                        if (prevTime === null || prevTime <= 1) {
                            clearInterval(timer!); // Clear timer when it reaches 0
                            handleNextQuestion(); // Auto-advance for host
                            return 0;
                        }
                        return prevTime - 1;
                    });
                }, 1000);
            } else if (!isHost && timeLeft !== null && timeLeft > 0 && !liveSession.show_answer) {
                   // For participants, just count down based on host's state, no auto-next
                   timer = setInterval(() => {
                    setTimeLeft((prevTime) => {
                        if (prevTime === null || prevTime <= 1) {
                            clearInterval(timer!);
                            return 0;
                        }
                        return prevTime - 1;
                    });
                   }, 1000);
            }
        } else {
            setTimeLeft(null); // Reset timer if not active or no time limit
        }

        return () => {
            if (timer) {
                clearInterval(timer);
            }
        };
    }, [liveSession, currentQuestion, isHost, timeLeft, handleNextQuestion]); // Added timeLeft to dependencies as it is read

    const getCorrectAnswerText = (question: Question): string => {
        switch (question.type) {
            case 'multiple-choice':
                const correctOption = question.options?.find(opt => opt.is_correct);
                return correctOption ? correctOption.option_text : 'N/A';
            case 'true-false':
                return question.true_false_answer !== null ? (question.true_false_answer ? 'True' : 'False') : 'N/A';
            case 'short-answer':
                return question.short_answer || 'N/A';
            default:
                return 'N/A';
        }
    };

    const getParticipantAnswerForCurrentQuestion = (participant: ParticipantData) => {
        if (!currentQuestion || !participant.answers) return null;
        return participant.answers[currentQuestion.id];
    };

    const handlePrintLeaderboard = () => {
        window.print();
    };

    const handleDownloadCsv = () => {
        let csvContent = "data:text/csv;charset=utf-8,";
        // CSV Header for participant summary
        csvContent += "Rank,Participant Name,Score";

        // Add a column for each question's correct answer and participant's answer
        quiz.questions.forEach((q, index) => {
            csvContent += `,"Q${index + 1}: ${q.question_text.replace(/"/g, '""')}"`; // Escape double quotes
            csvContent += `,"Q${index + 1} Answer Status"`;
        });
        csvContent += "\n"; // End of header row

        participants.forEach((p, pIndex) => {
            let row = `${pIndex + 1},"${p.user_name.replace(/"/g, '""')}",${p.score}`; // Escape double quotes for name

            quiz.questions.forEach((q) => {
                const participantAnswer = p.answers ? p.answers[q.id] : null;
                const submittedText = participantAnswer
                    ? (typeof participantAnswer.submitted === 'boolean' ? (participantAnswer.submitted ? 'True' : 'False') : String(participantAnswer.submitted).replace(/"/g, '""')) // Ensure submitted is a string and escape quotes
                    : 'N/A';
                const isCorrectText = participantAnswer ? (participantAnswer.is_correct ? 'Correct' : 'Incorrect') : 'No Answer';

                row += `,"${submittedText}","${isCorrectText}"`;
            });
            csvContent += row + "\n";
        });

        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `leaderboard_${quiz.title.replace(/\s+/g, '_')}_${new Date().toISOString().slice(0,10)}.csv`);
        document.body.appendChild(link); // Required for Firefox
        link.click();
        document.body.removeChild(link); // Clean up
    };


    if (loading) {
        return (
            <AuthenticatedLayout>
                <Head title="Live Quiz Session" />
                <div className="py-12 text-center">
                    <p className="text-gray-600 flex items-center justify-center">
                        <Loader className="animate-spin mr-2" size={24} /> Loading live session...
                    </p>
                </div>
            </AuthenticatedLayout>
        );
    }

    if (error) {
        return (
            <AuthenticatedLayout>
                <Head title="Live Quiz Session" />
                <div className="py-12 px-4">
                    <div className="max-w-2xl mx-auto bg-red-50 border border-red-200 rounded-lg p-6 text-center">
                        <AlertCircle className="inline-block mr-2 text-red-600 mb-4" size={48} />
                        <h2 className="text-xl font-semibold text-red-800 mb-2">Failed to Load Live Quiz Session</h2>
                        <p className="text-red-600 mb-4">{error}</p>
                        <button
                            onClick={() => {
                                setError(null);
                                setLoading(true);
                                window.location.reload();
                            }}
                            className="bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-6 rounded-lg transition-colors"
                        >
                            Retry
                        </button>
                    </div>
                </div>
            </AuthenticatedLayout>
        );
    }

    if (!liveSession || !currentQuestion) {
        const isQuizFinished = liveSession?.status === 'finished';
        const isWaitingForHost = liveSession?.status === 'waiting';

        if (isWaitingForHost) {
            return (
                <AuthenticatedLayout>
                    <Head title="Live Quiz Session" />
                    <div className="py-12 text-center">
                        <p className="text-lg text-gray-700 mb-4">Waiting for the host to start the quiz.</p>
                        <p className="text-gray-600">Quiz Code: <span className="font-bold text-indigo-700">{quiz.code}</span></p>
                    </div>
                </AuthenticatedLayout>
            );
        }

        if (isQuizFinished) {
            return (
                <AuthenticatedLayout>
                    <Head title="Live Quiz Session" />
                    <div className="py-12 text-center">
                        <h3 className="text-3xl font-bold text-green-700 mb-4">Quiz Finished!</h3>
                        <p className="text-lg text-gray-700 mb-6">You can now check the final leaderboard.</p>
                        <button
                            onClick={() => router.visit(route('dashboard'))}
                            className="inline-flex items-center px-6 py-3 bg-gray-600 border border-transparent rounded-md font-semibold text-white uppercase tracking-widest hover:bg-gray-700 focus:bg-gray-700 active:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition ease-in-out duration-150"
                        >
                            Back to Dashboard
                        </button>
                    </div>
                </AuthenticatedLayout>
            );
        }

        return (
            <AuthenticatedLayout>
                <Head title="Live Quiz Session" />
                <div className="py-12 text-center">
                    <p className="text-gray-600">No active question or quiz data available for this session.</p>
                </div>
            </AuthenticatedLayout>
        );
    }

    const isQuizFinished = liveSession.status === 'finished';
    const isWaitingForHost = liveSession.status === 'waiting';
    const answerRevealed = liveSession.show_answer;

    return (
        <AuthenticatedLayout
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">Live Session: {quiz.title}</h2>}
        >
            <Head title={`Live Session: ${quiz.title}`} />

            <div className="py-12">
                <div className="max-w-7xl mx-auto sm:px-6 lg:px-8 grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-2 bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                        <h3 className="text-2xl font-bold mb-4">
                            Current Question ({liveSession.current_question_index + 1} / {quiz.questions.length})
                        </h3>
                        {!isHost && (
                            <p className="text-red-500 text-sm mb-4">You are in spectator mode. You are not the host.</p>
                        )}
                        {liveSession.status === 'waiting' && (
                            <div className="text-center py-8">
                                <p className="text-lg text-gray-700 mb-4">
                                    The quiz code is: <span className="font-bold text-indigo-700 text-3xl">{quiz.code}</span>
                                </p>
                                <p className="text-gray-600 mb-6">
                                    Share this with your participants to join.
                                </p>
                                {isHost && (
                                    <button
                                        onClick={handleStartQuiz}
                                        className="inline-flex items-center px-6 py-3 bg-green-600 border border-transparent rounded-md font-semibold text-white uppercase tracking-widest hover:bg-green-700 focus:bg-green-700 active:bg-green-900 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition ease-in-out duration-150"
                                    >
                                        <PlayCircle className="mr-2 h-5 w-5" /> Start Quiz
                                    </button>
                                )}
                                {!isHost && (
                                    <p className="text-gray-500">Waiting for the host to start the quiz...</p>
                                )}
                            </div>
                        )}

                        {liveSession.status === 'active' && (
                            <>
                                <p className="text-md text-gray-600 mb-2">
                                    Difficulty Level: <span className={`font-semibold ${
                                        currentQuestion.difficulty === 'easy' ? 'text-green-600' :
                                        currentQuestion.difficulty === 'average' ? 'text-yellow-600' :
                                        'text-red-600'
                                    }`}>
                                        {currentQuestion.difficulty.charAt(0).toUpperCase() + currentQuestion.difficulty.slice(1)}
                                    </span>
                                </p>
                                {/* Display Time Limit and Countdown Timer */}
                                {currentQuestion.time_limit !== undefined && (
                                    <div className="mb-4">
                                        <AnimatedTimer 
                                            timeLeft={timeLeft} 
                                            totalTime={currentQuestion.time_limit}
                                        />
                                    </div>
                                )}
                                <p className="text-xl mb-4 font-semibold">{currentQuestion.question_text}</p>

                                {currentQuestion.image_path && (
                                    <img
                                        src={`/storage/${currentQuestion.image_path}`}
                                        alt="Question Image"
                                        className="mb-4 max-h-80 object-contain mx-auto rounded-lg shadow-md"
                                    />
                                )}

                                {currentQuestion.type === 'multiple-choice' && (
                                    <div className="space-y-3 mt-4">
                                        <h4 className="text-lg font-semibold text-gray-700 mb-3">Choices:</h4>
                                        {currentQuestion.options && currentQuestion.options.length > 0 ? (
                                            currentQuestion.options.map((option) => (
                                                <div key={option.id} className={`p-4 rounded-md border-2 flex items-center transition-all ${
                                                    answerRevealed && option.is_correct 
                                                        ? 'bg-green-100 border-green-500 shadow-md' 
                                                        : 'bg-gray-50 border-gray-300 hover:bg-gray-100'
                                                }`}>
                                                    <span className={`text-lg font-medium ${
                                                        answerRevealed && option.is_correct ? 'text-green-800' : 'text-gray-800'
                                                    }`}>
                                                        {option.option_text}
                                                    </span>
                                                    {answerRevealed && option.is_correct && (
                                                        <CheckCircle className="ml-auto h-5 w-5 text-green-600" />
                                                    )}
                                                </div>
                                            ))
                                        ) : (
                                            <p className="text-gray-500 italic">No options available for this question.</p>
                                        )}
                                    </div>
                                )}

                                {currentQuestion.type === 'true-false' && (
                                    <div className="space-y-3">
                                        <div className={`p-3 rounded-md border ${answerRevealed && currentQuestion.true_false_answer === true ? 'bg-green-100 border-green-500' : 'bg-gray-50 border-gray-200'}`}>
                                            <span className="text-lg font-medium text-gray-800">True</span>
                                        </div>
                                        <div className={`p-3 rounded-md border ${answerRevealed && currentQuestion.true_false_answer === false ? 'bg-green-100 border-green-500' : 'bg-gray-50 border-gray-200'}`}>
                                            <span className="text-lg font-medium text-gray-800">False</span>
                                        </div>
                                    </div>
                                )}

                                {currentQuestion.type === 'short-answer' && (
                                    <div className={`mt-4 p-3 rounded-md border ${answerRevealed ? 'bg-green-100 border-green-500' : 'bg-gray-50 border-gray-200'}`}>
                                        <span className="text-lg font-medium text-gray-800">
                                            Hint: Not all possible answers for short answer will be shown, but this is the set answer:
                                            <br />
                                            {answerRevealed && <span className="font-bold">{currentQuestion.short_answer}</span>}
                                        </span>
                                    </div>
                                )}

                                {answerRevealed && (
                                    <p className="mt-4 text-green-700 font-bold text-lg flex items-center">
                                        <CheckCircle className="mr-2 h-5 w-5" /> Correct Answer: {getCorrectAnswerText(currentQuestion)}
                                    </p>
                                )}

                                {isHost && (
                                    <div className="mt-6 flex justify-between gap-4">
                                        <button
                                            onClick={handleRevealAnswer}
                                            disabled={answerRevealed}
                                            className={`inline-flex items-center px-6 py-3 rounded-md font-semibold text-white uppercase tracking-widest transition ease-in-out duration-150 ${answerRevealed ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 focus:bg-blue-700 active:bg-blue-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'}`}
                                        >
                                            <CheckCircle className="mr-2 h-5 w-5" /> Reveal Answer
                                        </button>
                                        <button
                                            onClick={handleNextQuestion}
                                            className="inline-flex items-center px-6 py-3 bg-indigo-600 border border-transparent rounded-md font-semibold text-white uppercase tracking-widest hover:bg-indigo-700 focus:bg-indigo-700 active:bg-indigo-900 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition ease-in-out duration-150"
                                        >
                                            <FastForward className="mr-2 h-5 w-5" /> Next Question
                                        </button>
                                    </div>
                                )}
                            </>
                        )}

                        {isQuizFinished && (
                            <div className="text-center py-8">
                                <h3 className="text-3xl font-bold text-green-700 mb-4">Quiz Finished!</h3>
                                <p className="text-lg text-gray-700 mb-6">
                                    You can now check the final leaderboard.
                                </p>
                                <button
                                    onClick={() => router.visit(route('dashboard'))}
                                    className="inline-flex items-center px-6 py-3 bg-gray-600 border border-transparent rounded-md font-semibold text-white uppercase tracking-widest hover:bg-gray-700 focus:bg-gray-700 active:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition ease-in-out duration-150"
                                >
                                    Back to Dashboard
                                </button>
                            </div>
                        )}
                    </div>

                    <div className="md:col-span-1 bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                        <h3 className="text-2xl font-bold mb-4 flex items-center">
                            <Award className="mr-2 h-6 w-6 text-yellow-500" /> Leaderboard
                        </h3>
                        {participants.length > 0 ? (
                            <ol className="space-y-3">
                                {participants.map((p, index) => {
                                    const participantAnswer = getParticipantAnswerForCurrentQuestion(p);
                                    return (
                                        <li key={p.user_id} className={`flex flex-col items-start p-3 rounded-md shadow-sm border ${
                                            index === 0 ? 'bg-yellow-100 border-yellow-400' :
                                            index === 1 ? 'bg-gray-100 border-gray-300' :
                                            index === 2 ? 'bg-amber-100 border-amber-300' :
                                            'bg-white border-gray-200'
                                        }`}>
                                            <div className="flex justify-between w-full items-center mb-1">
                                                <div className="flex items-center">
                                                    <span className="font-bold text-lg mr-2 w-6 text-center">{index + 1}.</span>
                                                    <User className="mr-2 h-5 w-5 text-gray-500" />
                                                    <span className="font-medium text-gray-800">{p.user_name}</span>
                                                </div>
                                                <span className="font-bold text-xl text-indigo-600">{p.score}</span>
                                            </div>
                                        </li>
                                    );
                                })}
                            </ol>
                        ) : (
                            <p className="text-gray-600">No participants yet. Waiting for players.</p>
                        )}
                        {participants.length > 0 && isHost && ( // Show buttons only if there are participants and current user is host
                            <div className="mt-6 flex flex-col sm:flex-row justify-center gap-4">
                                <button
                                    onClick={handlePrintLeaderboard}
                                    className="inline-flex items-center px-4 py-2 bg-gray-200 border border-gray-300 rounded-md font-semibold text-gray-700 uppercase tracking-widest shadow-sm hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-25 transition ease-in-out duration-150"
                                >
                                    <Printer className="mr-2 h-4 w-4" /> Print Leaderboard
                                </button>
                                <button
                                    onClick={handleDownloadCsv}
                                    className="inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-white uppercase tracking-widest shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-25 transition ease-in-out duration-150"
                                >
                                    <Download className="mr-2 h-4 w-4" /> Download CSV Report
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}