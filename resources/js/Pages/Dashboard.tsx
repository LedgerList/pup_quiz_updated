import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, usePage } from '@inertiajs/react';
import { useState, ChangeEvent } from 'react';
import { PlusCircle, FileText, Clock, Star, Code } from 'lucide-react'; // Import icons
import Swal from 'sweetalert2'; // Import Swal for toasts
import 'sweetalert2/dist/sweetalert2.min.css';
import axios from 'axios';

// Define interfaces for quiz data received from backend, matching snake_case
interface Option {
    id: number;
    option_text: string;
    is_correct: boolean;
}

interface Question {
    id: number;
    quiz_id: number;
    type: 'multiple-choice' | 'true-false' | 'short-answer';
    question_text: string;
    image_path: string | null;
    options: Option[];
    true_false_answer: boolean | null;
    short_answer: string | null;
    time_limit: number | null;
    points: number | null;
}

interface Quiz {
    id: number;
    title: string;
    status: 'published' | 'draft' | 'archived'; // Essential for filtering tabs
    created_at: string; // ISO 8601 string
    questions: Question[];
    user_id: number;
    updated_at: string;
    code: string | null; // To display the quiz code
}

// Define User interface from usePage().props
interface User {
    id: number;
    name: string;
    email: string;
    role: number;
}

export default function Dashboard() {
    const { auth } = usePage().props as { auth: { user: User } };
    const user: User = auth.user;

    const [joinCode, setJoinCode] = useState<string>(''); // State for join code input
    // Added state to store CSRF token once it's retrieved
    
    // Check if user is a teacher (role 1) or student (role 2)
    const isTeacher = user?.role === 1;
    const isStudent = user?.role === 2; 

    // Effect to get CSRF token once the component mounts and DOM is fully ready
    // Teachers don't use lobby system - no data fetching needed

    const handleJoinQuiz = async () => {
        if (!joinCode.trim()) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'warning',
                title: 'Please enter a join code.',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            return;
        }

        try {
            const { data } = await axios.post('/quizzes/join', { code: joinCode });

            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'success',
                title: data.message || 'Successfully joined the quiz!',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            setJoinCode(''); 
   
            if (data.quiz_id) {
                window.location.href = `/quizzes/${data.quiz_id}/starting`;
            }
        } catch (err: any) {
            const status = err?.response?.status;
            const apiMessage = err?.response?.data?.message;
            const errorMessage = status === 419
                ? 'Your session has expired. Please refresh and try again.'
                : apiMessage || 'Quiz not found or failed to join.';

            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: status === 419 ? 'warning' : 'error',
                title: errorMessage,
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            if (status === 419) {
                console.error('CSRF/token mismatch while joining quiz');
            }
        }
    };

    return (
        <AuthenticatedLayout>
            <Head title="Dashboard" />

            <div className="py-12">
                <div className="mx-auto max-w-7xl sm:px-6 lg:px-8">
                    <div className="overflow-hidden bg-white shadow-sm sm:rounded-lg">
                        <div className="p-6 text-gray-900">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {/* Main Card - Hello User */}
                                <div
                                    className="bg-white shadow rounded-lg p-6"
                                    style={{ backgroundImage: 'url(/images/card.jpg)', backgroundSize: 'cover' }}
                                >
                                    <h2 className="text-3xl font-semibold text-white"> Hello, {user?.name || 'Guest'}</h2>
                                    <p className="mt-4 text-white text-lg">
                                        {isTeacher 
                                            ? "Create engaging quizzes for your students!" 
                                            : "Let's put your knowledge to the test!"}
                                    </p>
                                </div>

                                {/* Conditional Card - Join Code for Students, Quick Actions for Teachers */}
                                {isStudent ? (
                                    <div
                                        className="bg-white shadow rounded-lg p-6 border-2 border-red-500"
                                        style={{ backgroundImage: 'url(/images/card2.jpg)', backgroundSize: 'cover' }}
                                    >
                                        <input
                                            type="text"
                                            placeholder="Enter Join Code"
                                            className="mt-4 p-2 rounded-md w-full text-black"
                                            value={joinCode}
                                            onChange={(e: ChangeEvent<HTMLInputElement>) => setJoinCode(e.target.value)}
                                        />
                                        <button
                                            onClick={handleJoinQuiz}
                                            className="mt-4 w-full bg-red-500 text-white p-3 rounded-md text-lg hover:bg-red-600 transition-colors"
                                        >
                                            Join
                                        </button>
                                    </div>
                                ) : isTeacher ? (
                                    <div
                                        className="bg-white shadow rounded-lg p-6 border-2 border-blue-500"
                                        style={{ backgroundImage: 'url(/images/card2.jpg)', backgroundSize: 'cover' }}
                                    >
                                        <h3 className="text-xl font-semibold text-white mb-4">Quick Actions</h3>
                                        <div className="space-y-3">
                                            <Link
                                                href="/createquiz"
                                                className="block w-full bg-blue-500 text-white p-3 rounded-md text-lg hover:bg-blue-600 transition-colors text-center"
                                            >
                                                Create New Quiz
                                            </Link>
                                            <Link
                                                href="/myquizzes"
                                                className="block w-full bg-orange-500 text-white p-3 rounded-md text-lg hover:bg-orange-600 transition-colors text-center"
                                            >
                                                Manage Quiz
                                            </Link>
                                        </div>
                                    </div>
                                ) : null}
                            </div>

                            <div className="mt-8 text-center">
                                <p className="text-lg font-semibold text-gray-800">
                                    {isTeacher ? "Create & Manage" : "Discover"}
                                </p>
                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-6">
                                    {isTeacher ? (
                                        <>
                                            {/* Create Your Own Quiz on a Blank Canvas Card */}
                                            <Link href="/createquiz" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition cursor-pointer">
                                                    <img
                                                        src="/images/quiz2.png"
                                                        alt="Create Your Own Quiz"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">Create Your Own Quiz</h3>
                                                    </div>
                                                </div>
                                            </Link>

                                            {/* My Library Card */}
                                            <Link href="/mylibrary" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition cursor-pointer">
                                                    <img
                                                        src="/images/quiz.png"
                                                        alt="My Library"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">My Library</h3>
                                                    </div>
                                                </div>
                                            </Link>

                                            {/* My Quizzes Card */}
                                            <Link href="/myquizzes" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition cursor-pointer">
                                                    <img
                                                        src="/images/quiz.png"
                                                        alt="My Quizzes"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">My Quizzes</h3>
                                                    </div>
                                                </div>
                                            </Link>

                                            {/* AI Quiz Generator Card */}
                                            <Link href="/explore" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition cursor-pointer">
                                                    <img
                                                        src="/images/quiz3.png"
                                                        alt="AI Quiz Generator"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">AI Quiz Generator</h3>
                                                    </div>
                                                </div>
                                            </Link>
                                        </>
                                    ) : (
                                        <>
                                            {/* Flashcards Card */}
                                            <div className="bg-white shadow rounded-lg overflow-hidden">
                                                <img
                                                    src="/images/quiz.png"
                                                    alt="Flashcards"
                                                    className="w-full h-48 object-cover"
                                                />
                                                <div className="p-4">
                                                    <h3 className="text-lg font-semibold">Flashcards</h3>
                                                </div>
                                            </div>

                                            {/* Convert PDF/Docs to Quiz Card */}
                                            <Link href="/explore" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition cursor-pointer">
                                                    <img
                                                        src="/images/quiz4.png"
                                                        alt="Convert PDF/Docs to Quiz"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">Convert PDF/Docs to Quiz</h3>
                                                    </div>
                                                </div>
                                            </Link>

                                            {/* Generate a Quiz Instantly with AI Card */}
                                            <Link href="/explore" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition cursor-pointer">
                                                    <img
                                                        src="/images/quiz3.png"
                                                        alt="Generate Quiz Instantly"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">Generate a Quiz Instantly with AI</h3>
                                                    </div>
                                                </div>
                                            </Link>

                                            {/* Create Your Own Quiz on a Blank Canvas Card */}
                                            <Link href="/createquiz" className="block">
                                                <div className="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition">
                                                    <img
                                                        src="/images/quiz2.png"
                                                        alt="Create Your Own Quiz"
                                                        className="w-full h-48 object-cover"
                                                    />
                                                    <div className="p-4">
                                                        <h3 className="text-lg font-semibold">Create Your Own Quiz on a Blank Canvas</h3>
                                                    </div>
                                                </div>
                                            </Link>
                                        </>
                                    )}
                                </div>
                            </div>

                            {/* My Quizzes Section - Removed for Teachers (no lobby system) */}

                          
                        </div>
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}