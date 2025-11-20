import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, usePage } from '@inertiajs/react';
import React, { useState, useEffect, useMemo } from 'react';
import { AlertCircle, CheckCircle, XCircle, Loader } from 'lucide-react';
import Swal from 'sweetalert2';
import AnimatedTimer from '@/CustomComponents/AnimatedTimer';

interface Option {
    id: number;
    option_text: string;
    is_correct: boolean; // This will only be true for the correct option
}

interface Question {
    id: number;
    type: 'multiple-choice' | 'true-false' | 'short-answer';
    question_text: string;
    image_path?: string;
    time_limit?: number;
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

interface JoinQuizSessionProps {
    quiz: Quiz;
    // The current authenticated user will be available via usePage().props.auth.user
}

export default function JoinQuizSession({ quiz }: JoinQuizSessionProps) {
    const { auth } = usePage().props as any;
    const currentUserId = auth.user?.id;
    const currentUserName = auth.user?.name;

    const [liveSession, setLiveSession] = useState<LiveSessionData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [selectedAnswer, setSelectedAnswer] = useState<string | boolean | null>(null);
    const [isAnswerSubmitted, setIsAnswerSubmitted] = useState(false);
    const [participantScore, setParticipantScore] = useState<number>(0);
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const [timeLeft, setTimeLeft] = useState<number | null>(null); // State for countdown timer

    const sessionId = quiz.id;

    useEffect(() => {
        const token = (document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement)?.content;
        if (token) {
            setCsrfToken(token);
        } else {
            console.error("CSRF token meta tag not found in DOM!");
            setError("CSRF token missing. Please refresh the page.");
        }
    }, []);

    useEffect(() => {
        const fetchSessionData = async () => {
            if (!currentUserId || !csrfToken) return;

            try {
                // First, try to join the session if not already joined
                const joinResponse = await fetch(`/api/live-quizzes/${sessionId}/join-participant`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'include',
                    body: JSON.stringify({ user_id: currentUserId }),
                });

                if (!joinResponse.ok && joinResponse.status !== 409) {
                    // 409 means already joined, which is fine
                    const joinError = await joinResponse.json().catch(() => ({ message: 'Failed to join session' }));
                    throw new Error(joinError.message || `Failed to join session: ${joinResponse.statusText}`);
                }

                // Then, fetch the live session state
                const sessionResponse = await fetch(`/api/live-quizzes/${sessionId}/session`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-TOKEN': csrfToken,
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'include',
                });

                if (!sessionResponse.ok) {
                    if (sessionResponse.status === 404) {
                        setError('Live session not found. Please wait for the host to start the quiz.');
                        setLoading(false);
                        return;
                    }
                    const errorData = await sessionResponse.json().catch(() => ({ message: sessionResponse.statusText }));
                    throw new Error(errorData.message || `Failed to fetch session: ${sessionResponse.statusText}`);
                }

                const sessionData: LiveSessionData = await sessionResponse.json();
                setLiveSession(sessionData);

            } catch (err: any) {
                console.error("Error fetching live session data:", err);
                setError(`Failed to load quiz session: ${err.message || 'Unknown error'}`);
            } finally {
                setLoading(false);
            }
        };

        if (csrfToken) { // Only fetch when CSRF token is available
            fetchSessionData();
            const pollInterval = setInterval(fetchSessionData, 2000); // Poll every 2 seconds

            return () => clearInterval(pollInterval);
        }
    }, [sessionId, currentUserId, csrfToken]);

    const currentQuestion = liveSession ? quiz.questions[liveSession.current_question_index] : null;

    useEffect(() => {
        // Reset selected answer and submission status when question changes
        // Also initialize timer when a new question becomes active and host hasn't revealed answer
        if (liveSession && liveSession.status === 'active' && currentQuestion && !liveSession.show_answer) {
            setSelectedAnswer(null);
            setIsAnswerSubmitted(false);
            if (currentQuestion.time_limit !== undefined) {
                setTimeLeft(currentQuestion.time_limit);
            } else {
                setTimeLeft(null); // No time limit for this question
            }
        } else if (liveSession?.show_answer || liveSession?.status !== 'active') {
            setTimeLeft(null); // Stop timer if answer is revealed or session is not active
        }
    }, [currentQuestion, liveSession]);

    // Timer countdown logic for participant
   useEffect(() => {
        let timer: NodeJS.Timeout | null = null;

        if (liveSession && liveSession.status === 'active' && currentQuestion && currentQuestion.time_limit !== undefined && timeLeft !== null && timeLeft > 0 && !isAnswerSubmitted && !liveSession.show_answer) {
            timer = setInterval(() => {
                setTimeLeft((prevTime) => {
                    if (prevTime === null || prevTime <= 1) { // Timer stops and sets to 0 here
                        clearInterval(timer!);
                        // Optional: Show a "Time's Up!" message or disable controls
                        Swal.fire({
                            toast: true,
                            position: 'top-end',
                            icon: 'warning',
                            title: 'Time\'s Up!',
                            text: 'Your answer was not submitted.',
                            showConfirmButton: false,
                            timer: 3000,
                            timerProgressBar: true,
                        });
                        return 0; // Ensures timeLeft stays at 0
                    }
                    return prevTime - 1;
                });
            }, 1000);
        }

        // Clean up timer when component unmounts or dependencies change
        return () => {
            if (timer) {
                clearInterval(timer);
            }
        };
    }, [liveSession, currentQuestion, timeLeft, isAnswerSubmitted]);


    const handleSubmitAnswer = async () => {
        if (!currentQuestion || !liveSession || isAnswerSubmitted || selectedAnswer === null) return;
        
        // Prevent submission if time is up
        if (timeLeft !== null && timeLeft <= 0) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'warning',
                title: 'Time has run out!',
                text: 'Cannot submit answer after time limit.',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            return;
        }

        if (liveSession.show_answer) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'warning',
                title: 'Answer already revealed!',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            return;
        }
        
        // Handle short-answer empty string submission
        if (currentQuestion.type === 'short-answer' && typeof selectedAnswer === 'string' && selectedAnswer.trim() === '') {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'warning',
                title: 'Please type an answer!',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            return;
        }

        try {
            const response = await fetch(`/api/live-quizzes/${sessionId}/submit-answer`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken!,
                },
                body: JSON.stringify({
                    question_id: currentQuestion.id,
                    answer: selectedAnswer,
                }),
            });

            const result = await response.json();

            if (response.ok) {
                setIsAnswerSubmitted(true);
                setParticipantScore(result.score);
                
                // Show modal confirmation alert
                Swal.fire({
                    icon: result.is_correct ? 'success' : 'error',
                    title: result.is_correct ? 'Answer Submitted Successfully!' : 'Answer Submitted',
                    html: `
                        <div class="text-left">
                            <p class="mb-2">Your answer has been submitted successfully.</p>
                            <p class="text-sm text-gray-600 mb-2">${result.is_correct ? '✓ Correct Answer!' : '✗ Incorrect Answer'}</p>
                            <p class="text-sm text-gray-600">Your current score: <strong>${result.score}</strong> points</p>
                        </div>
                    `,
                    confirmButtonColor: result.is_correct ? '#10b981' : '#f97316',
                    confirmButtonText: 'OK',
                    allowOutsideClick: false,
                });
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Submission Failed',
                    html: `
                        <div class="text-left">
                            <p class="mb-2">${result.message || 'Failed to submit answer.'}</p>
                            <p class="text-sm text-gray-600">Please try again or contact the organizer if the problem persists.</p>
                        </div>
                    `,
                    confirmButtonColor: '#f97316',
                    confirmButtonText: 'OK',
                    allowOutsideClick: false,
                });
            }
        } catch (e: any) {
            console.error("Error submitting answer:", e);
            Swal.fire({
                icon: 'error',
                title: 'Submission Error',
                html: `
                    <div class="text-left">
                        <p class="mb-2">An error occurred while submitting your answer.</p>
                        <p class="text-sm text-gray-600">${e.message || 'Please try again or contact the organizer if the problem persists.'}</p>
                    </div>
                `,
                confirmButtonColor: '#f97316',
                confirmButtonText: 'OK',
                allowOutsideClick: false,
            });
        }
    };

    const getCorrectAnswerDetails = (question: Question): string => {
        switch (question.type) {
            case 'multiple-choice':
                const correctOption = question.options?.find(opt => opt.is_correct);
                return correctOption ? `Correct Answer: ${correctOption.option_text}` : 'No correct answer specified.';
            case 'true-false':
                return `Correct Answer: ${question.true_false_answer ? 'True' : 'False'}`;
            case 'short-answer':
                return `Correct Answer: ${question.short_answer || 'No correct answer specified.'}`;
            default:
                return 'Unknown question type.';
        }
    };

    // The submit button should be disabled if an answer has already been submitted,
    // if no answer is selected, if the selected answer for short-answer is empty,
    // or if the time has run out.
    const isSubmitButtonDisabled = isAnswerSubmitted || selectedAnswer === null || (typeof selectedAnswer === 'string' && selectedAnswer.trim() === '') || (timeLeft !== null && timeLeft <= 0);

    // Answer options/input should NOT be disabled by isAnswerSubmitted.
    // They should only be disabled if time has run out or the answer is revealed by the host.
    const areOptionsDisabled = (timeLeft !== null && timeLeft <= 0) || liveSession?.show_answer;


    if (loading) {
        return (
            <AuthenticatedLayout>
                <Head title="Join Live Quiz" />
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
                <Head title="Join Live Quiz" />
                <div className="py-12 text-center text-red-600">
                    <AlertCircle className="inline-block mr-2" /> {error}
                </div>
            </AuthenticatedLayout>
        );
    }

    if (!liveSession || !currentQuestion) {
        // Handle scenarios where liveSession or currentQuestion might be null
        // This usually happens when the quiz is not started, or has finished, or an error occurred.
        const isQuizFinished = liveSession?.status === 'finished';
        const isWaitingForHost = liveSession?.status === 'waiting';

        if (isWaitingForHost) {
            return (
                <AuthenticatedLayout>
                    <Head title="Join Live Quiz" />
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
                    <Head title="Join Live Quiz" />
                    <div className="py-12 text-center">
                        <h3 className="text-3xl font-bold text-green-700 mb-4">Quiz Finished!</h3>
                        <p className="text-lg text-gray-700 mb-6">Your final score: <span className="font-bold text-indigo-600">{participantScore}</span></p>
                        <button
                            onClick={() => window.location.href = route('dashboard')}
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
                <Head title="Join Live Quiz" />
                <div className="py-12 text-center">
                    <p className="text-gray-600">No active question in this live session.</p>
                </div>
            </AuthenticatedLayout>
        );
    }

    const isQuizFinished = liveSession.status === 'finished';
    const isWaitingForHost = liveSession.status === 'waiting';
    const answerRevealed = liveSession.show_answer;

    return (
        <AuthenticatedLayout
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">Join Live Quiz: {quiz.title}</h2>}
        >
            <Head title={`Join Quiz: ${quiz.title}`} />

            <div className="py-12">
                <div className="max-w-3xl mx-auto sm:px-6 lg:px-8">
                    <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                        <h3 className="text-2xl font-bold mb-4 text-center">
                            Question {liveSession.current_question_index + 1} / {quiz.questions.length}
                        </h3>

                        {/* Display countdown timer if active and time_limit exists */}
                         {liveSession.status === 'active' && currentQuestion.time_limit !== undefined && (
                            <div className="text-right mb-4">
                                <AnimatedTimer 
                                    timeLeft={timeLeft} 
                                    totalTime={currentQuestion.time_limit}
                                />
                            </div>
                        )}
                        {isWaitingForHost && (
                            <div className="text-center py-8">
                                <p className="text-lg text-gray-700 mb-4">Waiting for the host to start the quiz.</p>
                                <p className="text-gray-600">Quiz Code: <span className="font-bold text-indigo-700">{quiz.code}</span></p>
                            </div>
                        )}

                        {isQuizFinished && (
                            <div className="text-center py-8">
                                <h3 className="text-3xl font-bold text-green-700 mb-4">Quiz Finished!</h3>
                                <p className="text-lg text-gray-700 mb-6">Your final score: <span className="font-bold text-indigo-600">{participantScore}</span></p>
                                <button
                                    onClick={() => window.location.href = route('dashboard')}
                                    className="inline-flex items-center px-6 py-3 bg-gray-600 border border-transparent rounded-md font-semibold text-white uppercase tracking-widest hover:bg-gray-700 focus:bg-gray-700 active:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition ease-in-out duration-150"
                                >
                                    Back to Dashboard
                                </button>
                            </div>
                        )}

                        {!isWaitingForHost && !isQuizFinished && (
                            <>
                                <p className="text-md text-gray-600 mb-2">
                                    Difficulty: <span className={`font-semibold ${
                                        currentQuestion.difficulty === 'easy' ? 'text-green-600' :
                                        currentQuestion.difficulty === 'average' ? 'text-yellow-600' :
                                        'text-red-600'
                                    }`}>
                                        {currentQuestion.difficulty.charAt(0).toUpperCase() + currentQuestion.difficulty.slice(1)}
                                    </span>
                                </p>
                                <p className="text-xl mb-4 font-semibold">{currentQuestion.question_text}</p>

                                {currentQuestion.image_path && (
                                    <img
                                        src={`/storage/${currentQuestion.image_path}`}
                                        alt="Question Image"
                                        className="mb-4 max-h-80 object-contain mx-auto rounded-lg shadow-md"
                                    />
                                )}

                                {/* Answer submission area */}
                                {!answerRevealed ? (
                                    <div className="mt-4">
                                        {currentQuestion.type === 'multiple-choice' && (
                                            <div className="space-y-3">
                                                {currentQuestion.options?.map((option) => (
                                                    <button
                                                        key={option.id}
                                                        onClick={() => setSelectedAnswer(option.id.toString())}
                                                        disabled={areOptionsDisabled}
                                                        className={
                                                            `w-full p-3 rounded-md border text-left transition-all duration-200 ` +
                                                            (selectedAnswer === option.id.toString()
                                                                ? 'bg-indigo-100 border-indigo-500 text-indigo-800 '
                                                                : 'bg-gray-50 border-gray-200 hover:bg-gray-100 ') +
                                                            (areOptionsDisabled ? 'opacity-70 cursor-not-allowed' : 'cursor-pointer')
                                                        }
                                                    >
                                                        {option.option_text}
                                                    </button>
                                                ))}
                                            </div>
                                        )}

                                        {currentQuestion.type === 'true-false' && (
                                            <div className="flex space-x-4">
                                                <button
                                                    onClick={() => setSelectedAnswer('true')}
                                                    disabled={areOptionsDisabled}
                                                    className={
                                                        `flex-1 p-3 rounded-md border text-center transition-all duration-200 ` +
                                                        (selectedAnswer === 'true'
                                                            ? 'bg-indigo-100 border-indigo-500 text-indigo-800 '
                                                            : 'bg-gray-50 border-gray-200 hover:bg-gray-100 ') +
                                                        (areOptionsDisabled ? 'opacity-70 cursor-not-allowed' : 'cursor-pointer')
                                                    }
                                                >
                                                    True
                                                </button>
                                                <button
                                                    onClick={() => setSelectedAnswer('false')}
                                                    disabled={areOptionsDisabled}
                                                    className={
                                                        `flex-1 p-3 rounded-md border text-center transition-all duration-200 ` +
                                                        (selectedAnswer === 'false'
                                                            ? 'bg-indigo-100 border-indigo-500 text-indigo-800 '
                                                            : 'bg-gray-50 border-gray-200 hover:bg-gray-100 ') +
                                                        (areOptionsDisabled ? 'opacity-70 cursor-not-allowed' : 'cursor-pointer')
                                                    }
                                                >
                                                    False
                                                </button>
                                            </div>
                                        )}

                                        {currentQuestion.type === 'short-answer' && (
                                            <div>
                                                <input
                                                    type="text"
                                                    value={selectedAnswer as string || ''}
                                                    onChange={(e) => setSelectedAnswer(e.target.value)}
                                                    disabled={areOptionsDisabled}
                                                    placeholder="Type your answer here..."
                                                    className="w-full p-3 rounded-md border border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
                                                />
                                                <p className="text-sm text-gray-500 mt-1">
                                                    * For short answers, please type your answer exactly as expected (e.g., "Paris"). Answers are case-sensitive and must match perfectly.
                                                </p>
                                            </div>
                                        )}

                                        <button
                                            onClick={handleSubmitAnswer}
                                            disabled={isSubmitButtonDisabled}
                                            className={`mt-4 w-full inline-flex items-center justify-center px-6 py-3 rounded-md font-semibold text-white uppercase tracking-widest transition ease-in-out duration-150
                                                ${isSubmitButtonDisabled
                                                    ? 'bg-gray-400 cursor-not-allowed'
                                                    : 'bg-blue-600 hover:bg-blue-700 focus:bg-blue-700 active:bg-blue-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'}
                                            `}
                                        >
                                            Submit Answer
                                        </button>
                                    </div>
                                ) : (
                                    <div className="mt-4 p-4 rounded-md text-center">
                                        <p className="text-xl font-bold text-gray-800 mb-2">Answer Revealed!</p>
                                        <p className="text-lg text-green-700 font-semibold">{getCorrectAnswerDetails(currentQuestion)}</p>
                                        {isAnswerSubmitted && (
                                            <p className={`mt-2 text-md font-medium ${selectedAnswer && ((currentQuestion.type === 'multiple-choice' && currentQuestion.options?.find(opt => opt.id.toString() === selectedAnswer)?.is_correct) || (currentQuestion.type === 'true-false' && (selectedAnswer === 'true' && currentQuestion.true_false_answer) || (selectedAnswer === 'false' && !currentQuestion.true_false_answer)) || (currentQuestion.type === 'short-answer' && selectedAnswer.toString().toLowerCase() === currentQuestion.short_answer?.toLowerCase())) ? 'text-green-600' : 'text-red-600'}`}>
                                                Your Answer: {selectedAnswer?.toString()}
                                            </p>
                                        )}
                                        {!isAnswerSubmitted && (timeLeft !== null && timeLeft <= 0) && (
                                            <p className="mt-2 text-md font-medium text-red-600">
                                                You did not submit an answer in time.
                                            </p>
                                        )}
                                        <p className="mt-4 text-xl font-bold text-indigo-600">Your Score: {participantScore}</p>
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
