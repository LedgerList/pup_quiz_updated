import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, usePage } from '@inertiajs/react';
import { useState, useEffect } from 'react';
import { PlusCircle, FileText, Clock, Star, Code, PlayCircle } from 'lucide-react'; // Import PlayCircle icon
import Swal from 'sweetalert2'; // Import Swal for toasts
import 'sweetalert2/dist/sweetalert2.min.css';
export default function Dashboard() {
    const { auth } = usePage().props;
    const user = auth.user;
    const [myQuizzes, setMyQuizzes] = useState([]);
    const [joinedQuizzes, setJoinedQuizzes] = useState([]); // New state for joined quizzes
    const [activeTab, setActiveTab] = useState('published');
    const [loadingMyQuizzes, setLoadingMyQuizzes] = useState(true); // Separate loading state
    const [loadingJoinedQuizzes, setLoadingJoinedQuizzes] = useState(true); // Separate loading state
    const [errorMyQuizzes, setErrorMyQuizzes] = useState(null);
    const [errorJoinedQuizzes, setErrorJoinedQuizzes] = useState(null);
    const [joinCode, setJoinCode] = useState(''); // State for join code input
    const [csrfToken, setCsrfToken] = useState(null); // State to store CSRF token
    // Effect to get CSRF token once the component mounts and DOM is fully ready
    useEffect(() => {
        const token = document.querySelector('meta[name="csrf-token"]')?.content;
        if (token) {
            setCsrfToken(token);
        }
        else {
            console.error("CSRF token meta tag not found in DOM!");
            // Optionally show a user-friendly error or toast here
        }
    }, []); // Runs once on component mount
    // Effect to fetch quizzes created by the user
    useEffect(() => {
        const fetchMyQuizzes = async () => {
            setLoadingMyQuizzes(true);
            setErrorMyQuizzes(null);
            try {
                const response = await fetch('/quizzes/my');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                setMyQuizzes(data);
            }
            catch (err) {
                console.error("Failed to fetch quizzes created by user:", err);
                setErrorMyQuizzes("Failed to load your quizzes. Please try again.");
            }
            finally {
                setLoadingMyQuizzes(false);
            }
        };
        fetchMyQuizzes();
    }, []);
    // Effect to fetch quizzes joined by the user
    useEffect(() => {
        const fetchJoinedQuizzes = async () => {
            setLoadingJoinedQuizzes(true);
            setErrorJoinedQuizzes(null);
            try {
                const response = await fetch('/quizzes/myj');
                
                // Handle non-OK responses
                if (!response.ok) {
                    // Only show error for actual server errors (5xx), not for empty results
                    if (response.status >= 500) {
                        throw new Error(`Server error: ${response.status}`);
                    }
                    // For 404 or other client errors, just return empty array
                    if (response.status === 404 || response.status === 401) {
                        setJoinedQuizzes([]);
                        setLoadingJoinedQuizzes(false);
                        return;
                    }
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                // Ensure data is an array (handle null or undefined)
                setJoinedQuizzes(Array.isArray(data) ? data : []);
            }
            catch (err) {
                console.error("Failed to fetch joined quizzes:", err);
                // Only show error for actual network/server errors, not for empty results
                if (err.message && !err.message.includes('404') && !err.message.includes('401')) {
                    setErrorJoinedQuizzes("Failed to load joined quizzes. Please try again.");
                } else {
                    // For client errors (404, 401), just set empty array without showing error
                    setJoinedQuizzes([]);
                }
            }
            finally {
                setLoadingJoinedQuizzes(false);
            }
        };
        fetchJoinedQuizzes();
    }, []); // Empty dependency array means this runs once on mount
    // Filter quizzes based on active tab
    const filteredMyQuizzes = myQuizzes.filter(quiz => {
        if (activeTab === 'published') {
            return quiz.status === 'published';
        }
        else if (activeTab === 'drafts') {
            return quiz.status === 'draft';
        }
        else if (activeTab === 'archive') {
            return quiz.status === 'archived';
        }
        return false;
    });
    // Calculate counts for each tab
    const publishedCount = myQuizzes.filter(q => q.status === 'published').length;
    const draftsCount = myQuizzes.filter(q => q.status === 'draft').length;
    const archiveCount = myQuizzes.filter(q => q.status === 'archived').length;
    // Function to format date for display
    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        });
    };
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
        const tokenToUse = csrfToken || document.querySelector('meta[name="csrf-token"]')?.content;
        if (!tokenToUse) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'CSRF token not found. Please refresh the page.',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            console.error("Attempted to send request without CSRF token.");
            return;
        }
        try {
            const response = await fetch('/quizzes/join', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': tokenToUse,
                },
                body: JSON.stringify({ code: joinCode }),
            });
            const result = await response.json();
            if (response.ok) {
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'success',
                    title: result.message || 'Successfully joined the quiz!',
                    showConfirmButton: false,
                    timer: 3000,
                    timerProgressBar: true,
                });
                setJoinCode(''); // Clear input on success
                // Re-fetch joined quizzes to update the list
                const joinedResponse = await fetch('/quizzes/myj');
                if (joinedResponse.ok) {
                    const updatedJoinedQuizzes = await joinedResponse.json();
                    setJoinedQuizzes(updatedJoinedQuizzes);
                }
                // Redirect to the quiz page using the quiz_id from the response
                if (result.quiz_id) {
                    window.location.href = `/quizzes/${result.quiz_id}`; // Direct redirect for now
                }
            }
            else {
                const iconType = response.status === 400 ? 'warning' : 'error';
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: iconType,
                    title: result.message || 'Quiz not found or failed to join.',
                    showConfirmButton: false,
                    timer: 3000,
                    timerProgressBar: true,
                });
            }
        }
        catch (err) {
            console.error("Error joining quiz:", err);
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'An error occurred while trying to join the quiz.',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
        }
    };
    return (_jsxs(AuthenticatedLayout, { children: [_jsx(Head, { title: "Dashboard" }), _jsx("div", { className: "py-12", children: _jsx("div", { className: "mx-auto max-w-7xl sm:px-6 lg:px-8", children: _jsxs("div", { className: "overflow-hidden bg-white shadow-sm sm:rounded-lg p-6", children: [_jsx("h1", { className: "text-3xl font-bold text-red-600 mb-8", children: "My Library" }), _jsxs("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: [_jsx("div", { children: _jsxs("div", { className: "bg-white shadow rounded-lg p-4 border", children: [_jsx("h2", { className: "text-xl font-semibold mb-2", children: "Created by me" }), _jsx("hr", { className: "border-black mb-4" }), _jsxs(Link, { href: ('/createquiz'), className: "inline-flex items-center px-4 py-2 bg-red-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-red-700 active:bg-red-900 focus:outline-none focus:border-red-900 focus:ring ring-gray-300 disabled:opacity-25 transition ease-in-out duration-150 mb-4", children: [_jsx(PlusCircle, { size: 18, className: "mr-2" }), " Create New Quiz"] }), loadingMyQuizzes && _jsx("p", { className: "text-gray-600", children: "Loading your quizzes..." }), errorMyQuizzes && _jsx("p", { className: "text-red-500", children: errorMyQuizzes }), !loadingMyQuizzes && !errorMyQuizzes && filteredMyQuizzes.length === 0 && (_jsx("p", { className: "text-gray-500", children: "No quizzes found in this category." })), _jsx("div", { className: "space-y-4", children: !loadingMyQuizzes && !errorMyQuizzes && filteredMyQuizzes.map(quiz => (_jsxs("div", { className: "bg-gray-100 rounded-lg p-4 flex items-start gap-4 shadow-sm", children: [_jsx("img", { src: quiz.questions[0]?.image_path ? `/storage/${quiz.questions[0].image_path}` : "https://placehold.co/96x96/e0e0e0/333333?text=Quiz", alt: "Quiz Thumbnail", className: "w-16 h-16 object-cover rounded" }), _jsxs("div", { children: [_jsx("h3", { className: "text-red-600 text-lg font-semibold", children: quiz.title }), quiz.code && (_jsxs("p", { className: "text-sm text-gray-700 mt-1 flex items-center gap-2 font-medium", children: [_jsx(Code, { size: 16 }), " Quiz Code: ", quiz.code] })), _jsxs("p", { className: "text-sm text-gray-700 mt-1 flex items-center gap-2", children: [_jsx(FileText, { size: 16 }), " ", quiz.questions.length, " Questions"] }), _jsxs("p", { className: "text-sm text-gray-500 mt-1 flex items-center gap-2", children: [_jsx(Clock, { size: 16 }), " Created: ", formatDate(quiz.created_at)] }), _jsxs("p", { className: "text-sm text-gray-500 mt-1 flex items-center gap-2", children: [_jsx(Star, { size: 16 }), " Total Points: ", quiz.questions.reduce((sum, q) => sum + (q.points || 0), 0)] }), _jsx("div", { className: "mt-2 flex gap-2", children: _jsxs(Link, { href: route('quiz.start', quiz.id), className: "text-blue-600 hover:underline text-sm flex items-center", children: [_jsx(PlayCircle, { size: 16, className: "mr-1" }), " Start"] }) }), _jsxs(Link, { href: route('quizzes.edit', quiz.id), className: "text-green-600 hover:underline text-sm flex items-center", children: [_jsxs("svg", { xmlns: "http://www.w3.org/2000/svg", width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", className: "mr-1", children: [_jsx("path", { d: "M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" }), _jsx("path", { d: "M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4Z" })] }), "Edit"] })] })] }, quiz.id))) })] }) }), _jsxs("div", { children: [_jsxs("div", { className: "bg-white shadow rounded-lg p-4 border mb-6", children: [_jsx("h2", { className: "text-xl font-semibold mb-2", children: "Quiz Status" }), _jsxs("div", { className: "flex justify-between text-sm font-semibold mb-2 border-b pb-2", children: [_jsxs("button", { onClick: () => setActiveTab('published'), className: `px-3 py-1 rounded-md transition-colors ${activeTab === 'published' ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-100'}`, children: ["Published (", publishedCount, ")"] }), _jsxs("button", { onClick: () => setActiveTab('drafts'), className: `px-3 py-1 rounded-md transition-colors ${activeTab === 'drafts' ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-100'}`, children: ["Drafts (", draftsCount, ")"] }), _jsxs("button", { onClick: () => setActiveTab('archive'), className: `px-3 py-1 rounded-md transition-colors ${activeTab === 'archive' ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-100'}`, children: ["Archive (", archiveCount, ")"] })] }), _jsx("p", { className: "text-gray-500 text-sm mt-4", children: "Quizzes filtered by status are shown in the \"Created by me\" section. Click on a tab to see quizzes of that status." })] }), _jsxs("div", { className: "bg-white shadow rounded-lg p-4 border", children: [_jsx("h2", { className: "text-xl font-semibold mb-2", children: "Joined Quizzes" }), _jsx("hr", { className: "border-black mb-4" }), loadingJoinedQuizzes && _jsx("p", { className: "text-gray-600", children: "Loading joined quizzes..." }), errorJoinedQuizzes && _jsx("p", { className: "text-red-500", children: errorJoinedQuizzes }), !loadingJoinedQuizzes && !errorJoinedQuizzes && joinedQuizzes.length === 0 && (_jsx("p", { className: "text-gray-500", children: "No joined quizzes to display yet." })), _jsx("div", { className: "space-y-4", children: !loadingJoinedQuizzes && !errorJoinedQuizzes && joinedQuizzes.map(quiz => (_jsxs("div", { className: "bg-gray-100 rounded-lg p-4 flex items-start gap-4 shadow-sm", children: [_jsx("img", { src: quiz.questions[0]?.image_path ? `/storage/${quiz.questions[0].image_path}` : "https://placehold.co/96x96/e0e0e0/333333?text=Quiz", alt: "Quiz Thumbnail", className: "w-16 h-16 object-cover rounded" }), _jsxs("div", { children: [_jsx("h3", { className: "text-blue-600 text-lg font-semibold", children: quiz.title }), _jsxs("p", { className: "text-sm text-gray-700 mt-1 flex items-center gap-2", children: [_jsx(FileText, { size: 16 }), " ", quiz.questions.length, " Questions"] }), _jsxs("p", { className: "text-sm text-gray-500 mt-1 flex items-center gap-2", children: [_jsx(Clock, { size: 16 }), " Created: ", formatDate(quiz.created_at)] }), _jsxs("p", { className: "text-sm text-gray-500 mt-1 flex items-center gap-2", children: [_jsx(Star, { size: 16 }), " Total Points: ", quiz.questions.reduce((sum, q) => sum + (q.points || 0), 0)] }), _jsxs("p", { className: "text-sm text-gray-500 mt-1 flex items-center gap-2", children: [_jsx(Clock, { size: 16 }), " Status: ", (quiz.statusquiz)] }), _jsx("div", { className: "mt-2", children: _jsx("div", { className: "mt-2 flex gap-2", children: _jsxs(Link, { href: route('quiz.start', quiz.id), className: "text-blue-600 hover:underline text-sm flex items-center", children: [_jsx(PlayCircle, { size: 16, className: "mr-1" }), " Start"] }) }) })] })] }, quiz.id))) })] })] })] })] }) }) })] }));
}
