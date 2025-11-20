import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, usePage } from '@inertiajs/react';

interface QuizAttempt {
    id: number;
    quiz_id: number;
    quiz_title: string;
    quiz_code: string;
    category: string;
    score: number;
    date_taken: string;
    type: string;
    status: string;
}

export default function MyPerformance() {
    const { quizAttempts } = usePage().props as { quizAttempts: QuizAttempt[] };
    
    // Ensure quizAttempts is an array
    const attempts = Array.isArray(quizAttempts) ? quizAttempts : [];

    return (
        <AuthenticatedLayout>
            <Head title="My Performance" />

            <div className="py-12 bg-gray-50">
                <div className="max-w-7xl mx-auto px-6 space-y-8">
                    {/* Title */}
                    <div>
                        <h1 className="text-3xl font-bold text-red-600">My Performance</h1>
                        <div className="w-full h-1 bg-red-600 mt-2"></div>
                    </div>

                    {/* Quiz History */}
                    <div>
                        <h2 className="text-xl font-semibold text-gray-800 mb-4">Quiz History</h2>

                        {/* Table */}
                        <div className="overflow-auto bg-white rounded-lg shadow border border-gray-200">
                            {attempts.length > 0 ? (
                                <table className="min-w-full text-sm text-left">
                                    <thead className="bg-gray-100 border-b border-gray-200">
                                        <tr>
                                            <th className="px-4 py-3">Quiz Title</th>
                                            <th className="px-4 py-3">Quiz Code</th>
                                            <th className="px-4 py-3">Category</th>
                                            <th className="px-4 py-3">Score</th>
                                            <th className="px-4 py-3">Date Taken</th>
                                            <th className="px-4 py-3">Type</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-200">
                                        {attempts.map((attempt) => (
                                            <tr key={attempt.id} className="hover:bg-gray-50">
                                                <td className="px-4 py-3">{attempt.quiz_title}</td>
                                                <td className="px-4 py-3">{attempt.quiz_code}</td>
                                                <td className="px-4 py-3">{attempt.category}</td>
                                                <td className="px-4 py-3 font-semibold">{attempt.score}</td>
                                                <td className="px-4 py-3">{attempt.date_taken}</td>
                                                <td className="px-4 py-3 text-red-600 font-medium">{attempt.type}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="text-center py-12">
                                    <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                        <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                        </svg>
                                    </div>
                                    <h3 className="text-lg font-medium text-gray-900 mb-2">No Quiz History Yet</h3>
                                    <p className="text-gray-500">You haven't completed any quizzes yet. Start taking quizzes to see your performance here.</p>
                                </div>
                            )}
                        </div>

                        {/* Download Button - Only show if there are attempts */}
                        {attempts.length > 0 && (
                            <div className="mt-6 text-right">
                                <button className="bg-red-600 text-white px-6 py-2 rounded-md hover:bg-red-700 transition">
                                    Download Performance Report
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
