import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, router, usePage } from '@inertiajs/react';
import { useEffect, useState, useRef } from 'react';
import { Upload, Sparkles, FileText, Loader2 } from 'lucide-react';
import Swal from 'sweetalert2';

const AI_API_URL = 'http://localhost:8800'; // Flask AI service URL

type QuestionType = 'multiple-choice' | 'true-false' | 'short-answer';

export default function Explore() {
    const { subject_id } = usePage().props as { subject_id?: number | string | null };
    const normalizedSubjectId = subject_id !== undefined && subject_id !== null && subject_id !== ''
        ? Number(subject_id)
        : null;
    const [loading, setLoading] = useState(false);
    const [uploadMethod, setUploadMethod] = useState<'image' | 'text' | 'prompt'>('image');
    
    // Image upload state
    const [selectedImage, setSelectedImage] = useState<File | null>(null);
    const [imagePreview, setImagePreview] = useState<string | null>(null);
    const imageInputRef = useRef<HTMLInputElement>(null);
    
    // Text input state
    const [textContent, setTextContent] = useState('');
    const [topic, setTopic] = useState('');
    
    // Custom prompt state
    const [customPrompt, setCustomPrompt] = useState('');
    
    // Quiz settings - Per question type configuration
    const [questionTypeCounts, setQuestionTypeCounts] = useState<Record<QuestionType, number>>({
        'multiple-choice': 5,
        'true-false': 0,
        'short-answer': 0,
    });
    const [randomizeCounts, setRandomizeCounts] = useState(false);
    const [randomRanges, setRandomRanges] = useState<Record<QuestionType, { min: number; max: number }>>({
        'multiple-choice': { min: 3, max: 5 },
        'true-false': { min: 0, max: 0 },
        'short-answer': { min: 0, max: 0 },
    });
    const [difficulty, setDifficulty] = useState<'easy' | 'average' | 'hard' | 'mixed'>('mixed');

    const handleQuestionTypeCountChange = (questionType: QuestionType, count: number) => {
        setQuestionTypeCounts((prev) => ({
            ...prev,
            [questionType]: count,
        }));
    };

    const handleQuestionTypeRangeChange = (questionType: QuestionType, field: 'min' | 'max', value: number) => {
        setRandomRanges((prev) => ({
            ...prev,
            [questionType]: {
                ...prev[questionType],
                [field]: value,
            },
        }));
    };


    const handleImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            setSelectedImage(file);
            // Only show preview for images, not PDFs
            if (file.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onloadend = () => {
                    setImagePreview(reader.result as string);
                };
                reader.readAsDataURL(file);
            } else {
                setImagePreview(null);
            }
        }
    };

    const convertImageToBase64 = (file: File): Promise<string> => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => resolve(reader.result as string);
            reader.onerror = error => reject(error);
        });
    };

    const getRandomQuestionCount = ({ min, max }: { min: number; max: number }) => {
        const sanitizedMin = Math.max(0, Math.floor(Number.isFinite(min) ? min : 0));
        const sanitizedMaxCandidate = Math.max(0, Math.floor(Number.isFinite(max) ? max : 0));
        const sanitizedMax = Math.max(sanitizedMin, sanitizedMaxCandidate);

        if (sanitizedMax === 0) {
            return 0;
        }

        return Math.floor(Math.random() * (sanitizedMax - sanitizedMin + 1)) + sanitizedMin;
    };

    const handleGenerateQuiz = async () => {
        if (loading) return;

        // Validate that at least one question type has questions configured
        const questionTypes: QuestionType[] = ['multiple-choice', 'true-false', 'short-answer'];

        const hasConfiguredType = questionTypes.some((type) => {
            if (!randomizeCounts) {
                return questionTypeCounts[type] > 0;
            }

            const { min, max } = randomRanges[type];
            return Math.max(min, max) > 0;
        });

        if (!hasConfiguredType) {
            Swal.fire({
                icon: 'warning',
                title: 'No Questions',
                text: randomizeCounts
                    ? 'Please make sure at least one question type has a max value greater than zero.'
                    : 'Please set at least one question for any question type (Multiple Choice, True/False, or Short Answer).',
            });
            return;
        }

        setLoading(true);
        try {
            // Generate questions for each question type separately
            const allQuestions: any[] = [];
            const typeCountsUsed: Record<QuestionType, number> = {
                'multiple-choice': 0,
                'true-false': 0,
                'short-answer': 0,
            };

            for (const questionType of questionTypes) {
                const questionsForType = randomizeCounts
                    ? getRandomQuestionCount(randomRanges[questionType])
                    : questionTypeCounts[questionType];

                if (!questionsForType || questionsForType <= 0) continue; // Skip types with 0 questions

                typeCountsUsed[questionType] = questionsForType;

                let response;
                const requestBody: any = {
                    difficulty: difficulty === 'mixed' ? 'medium' : (difficulty === 'average' ? 'medium' : difficulty),
                    num_questions: questionsForType,
                    question_type: questionType,
                };

                if (uploadMethod === 'image' && selectedImage) {
                    // Generate from image or PDF
                    const base64File = await convertImageToBase64(selectedImage);
                    requestBody.file = base64File;
                    requestBody.file_name = selectedImage.name;
                    requestBody.file_type = selectedImage.type;
                    if (topic) requestBody.topic = topic;
                    
                    response = await fetch(`${AI_API_URL}/generate-quiz`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(requestBody),
                    });
                } else if (uploadMethod === 'text') {
                    // Generate from text/topic
                    if (!textContent && !topic) {
                        Swal.fire({
                            icon: 'warning',
                            title: 'Missing Information',
                            text: 'Please provide either text content or a topic.',
                        });
                        setLoading(false);
                        return;
                    }
                    
                    requestBody.text = textContent;
                    requestBody.topic = topic;
                    
                    response = await fetch(`${AI_API_URL}/generate-quiz-from-text`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(requestBody),
                    });
                } else if (uploadMethod === 'prompt') {
                    // Generate from custom prompt
                    if (!customPrompt.trim()) {
                        Swal.fire({
                            icon: 'warning',
                            title: 'Missing Prompt',
                            text: 'Please enter a custom prompt.',
                        });
                        setLoading(false);
                        return;
                    }
                    
                    requestBody.prompt = customPrompt;
                    
                    response = await fetch(`${AI_API_URL}/generate-custom-prompt-quiz`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(requestBody),
                    });
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Invalid Method',
                        text: 'Please select a generation method and provide the required input.',
                    });
                    setLoading(false);
                    return;
                }

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || `Server error: ${response.status}`);
                }

                const result = await response.json();
                
                if (result.success && result.quiz && result.quiz.questions) {
                    // Map difficulty back to 'average' if it was 'medium'
                    const mappedQuestions = result.quiz.questions.map((q: any) => ({
                        ...q,
                        difficulty: q.difficulty === 'medium' ? 'average' : q.difficulty
                    }));
                    allQuestions.push(...mappedQuestions);
                } else {
                    throw new Error(`Invalid response from AI service for ${questionType} questions`);
                }
            }

            // Combine all questions from all question types
            if (allQuestions.length > 0) {
                const summaryText = questionTypes
                    .filter(type => typeCountsUsed[type] > 0)
                    .map((type) => {
                        const typeLabel = type === 'multiple-choice' ? 'Multiple Choice' : 
                                         type === 'true-false' ? 'True/False' : 'Short Answer';
                        return `${typeLabel}: ${typeCountsUsed[type]}`;
                    })
                    .join(', ');

                const combinedQuiz = {
                    quiz_title: topic || 'AI Generated Quiz',
                    quiz_description: `Quiz generated with ${allQuestions.length} questions across multiple question types`,
                    topic: topic || 'General',
                    difficulty: difficulty,
                    questions: allQuestions,
                    subject_id: normalizedSubjectId,
                    question_type_config: {
                        randomize_counts: randomizeCounts,
                        counts_used: typeCountsUsed,
                        random_ranges: randomizeCounts ? randomRanges : null,
                        requested_counts: questionTypeCounts,
                    },
                };

                // Store quiz data in sessionStorage to pass to create quiz page
                sessionStorage.setItem('aiGeneratedQuiz', JSON.stringify(combinedQuiz));
                
                // Show success message briefly, then auto-redirect
                Swal.fire({
                    icon: 'success',
                    title: 'Quiz Generated!',
                    text: `Successfully generated ${allQuestions.length} questions (${summaryText}). Redirecting to create quiz...`,
                    timer: 2000,
                    showConfirmButton: false,
                    timerProgressBar: true,
                }).then(() => {
                    // Automatically redirect to create quiz page
                    const subjectQuery = normalizedSubjectId ? `?subject_id=${normalizedSubjectId}` : '';
                    router.visit(`/createquiz${subjectQuery}`);
                });
            } else {
                throw new Error('No questions were generated');
            }
        } catch (error: any) {
            console.error('Error generating quiz:', error);
            Swal.fire({
                icon: 'error',
                title: 'Generation Failed',
                text: error.message || 'Failed to generate quiz. Please try again.',
            });
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthenticatedLayout>
            <Head title="AI Quiz Generator" />

            <div className="py-12">
                <div className="mx-auto max-w-7xl sm:px-6 lg:px-8">
                    <div className="overflow-hidden bg-white shadow-sm sm:rounded-lg">
                        <div className="p-6 text-gray-900">
                            {/* Title */}
                            <div className="mb-6">
                                <h2 className="text-2xl font-semibold text-gray-800 flex items-center gap-2">
                                    <Sparkles className="w-6 h-6 text-purple-600" />
                                    AI Quiz Generator
                                </h2>
                                <p className="text-gray-600 mt-2">Generate quizzes instantly using AI from your study materials, text, or custom prompts.</p>
                            </div>

                            {/* Method Selection */}
                            <div className="mb-6">
                                <label className="block text-sm font-medium text-gray-700 mb-2">Generation Method</label>
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <button
                                        onClick={() => setUploadMethod('image')}
                                        className={`p-4 border-2 rounded-lg transition-colors ${
                                            uploadMethod === 'image'
                                                ? 'border-purple-500 bg-purple-50'
                                                : 'border-gray-200 hover:border-gray-300'
                                        }`}
                                    >
                                        <Upload className="w-6 h-6 mx-auto mb-2" />
                                        <h3 className="font-semibold">From Image</h3>
                                        <p className="text-sm text-gray-600">Upload study materials</p>
                                    </button>
                                    <button
                                        onClick={() => setUploadMethod('text')}
                                        className={`p-4 border-2 rounded-lg transition-colors ${
                                            uploadMethod === 'text'
                                                ? 'border-purple-500 bg-purple-50'
                                                : 'border-gray-200 hover:border-gray-300'
                                        }`}
                                    >
                                        <FileText className="w-6 h-6 mx-auto mb-2" />
                                        <h3 className="font-semibold">From Text/Topic</h3>
                                        <p className="text-sm text-gray-600">Enter text or topic</p>
                                    </button>
                                    <button
                                        onClick={() => setUploadMethod('prompt')}
                                        className={`p-4 border-2 rounded-lg transition-colors ${
                                            uploadMethod === 'prompt'
                                                ? 'border-purple-500 bg-purple-50'
                                                : 'border-gray-200 hover:border-gray-300'
                                        }`}
                                    >
                                        <Sparkles className="w-6 h-6 mx-auto mb-2" />
                                        <h3 className="font-semibold">Custom Prompt</h3>
                                        <p className="text-sm text-gray-600">Describe what you want</p>
                                    </button>
                                </div>
                            </div>

                            {/* Input Section */}
                            <div className="mb-6">
                                {uploadMethod === 'image' && (
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                                Upload Study Material (Image/PDF)
                                            </label>
                                            <input
                                                ref={imageInputRef}
                                                type="file"
                                                accept="image/*,.pdf"
                                                onChange={handleImageChange}
                                                className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-purple-50 file:text-purple-700 hover:file:bg-purple-100"
                                            />
                                            {selectedImage && (
                                                <div className="mt-2">
                                                    <p className="text-sm text-gray-600">
                                                        <span className="font-medium">Selected file:</span> {selectedImage.name}
                                                        <span className="text-gray-400 ml-2">
                                                            ({(selectedImage.size / 1024 / 1024).toFixed(2)} MB)
                                                        </span>
                                                    </p>
                                                </div>
                                            )}
                                            {imagePreview && (
                                                <div className="mt-4">
                                                    <img
                                                        src={imagePreview}
                                                        alt="Preview"
                                                        className="max-w-md h-48 object-contain border rounded-lg"
                                                    />
                                                </div>
                                            )}
                                            {selectedImage && selectedImage.type === 'application/pdf' && (
                                                <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                                                    <p className="text-sm text-blue-700">
                                                        <span className="font-medium">📄 PDF file selected.</span> The quiz will be generated from the content of this PDF.
                                                    </p>
                                                </div>
                                            )}
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                                Topic (Optional)
                                            </label>
                                            <input
                                                type="text"
                                                value={topic}
                                                onChange={(e) => setTopic(e.target.value)}
                                                placeholder="e.g., Biology, Mathematics, History"
                                                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-purple-500 focus:border-purple-500"
                                            />
                                        </div>
                                    </div>
                                )}

                                {uploadMethod === 'text' && (
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                                Topic
                                            </label>
                                            <input
                                                type="text"
                                                value={topic}
                                                onChange={(e) => setTopic(e.target.value)}
                                                placeholder="e.g., Philippine History, Algebra, Biology"
                                                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-purple-500 focus:border-purple-500"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                                Text Content (Optional)
                                            </label>
                                            <textarea
                                                value={textContent}
                                                onChange={(e) => setTextContent(e.target.value)}
                                                placeholder="Paste your study material text here..."
                                                rows={6}
                                                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-purple-500 focus:border-purple-500"
                                            />
                                        </div>
                                    </div>
                                )}

                                {uploadMethod === 'prompt' && (
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2">
                                            Custom Prompt
                                        </label>
                                        <textarea
                                            value={customPrompt}
                                            onChange={(e) => setCustomPrompt(e.target.value)}
                                            placeholder="e.g., Create a quiz about the Spanish colonial period in the Philippines with 15 questions focusing on key events and figures."
                                            rows={6}
                                            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-purple-500 focus:border-purple-500"
                                        />
                                    </div>
                                )}
                            </div>

                            {/* Quiz Settings */}
                            <div className="mb-6 space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                        Difficulty Level
                                    </label>
                                    <p className="text-xs text-gray-500 mb-2">
                                        Select the difficulty level for all generated questions.
                                    </p>
                                    <select
                                        value={difficulty}
                                        onChange={(e) => setDifficulty(e.target.value as typeof difficulty)}
                                        className="w-full md:w-1/3 px-4 py-2 border border-gray-300 rounded-md focus:ring-purple-500 focus:border-purple-500"
                                    >
                                        <option value="easy">Easy</option>
                                        <option value="average">Average</option>
                                        <option value="hard">Hard</option>
                                        <option value="mixed">Mixed</option>
                                    </select>
                                </div>
                                
                                <div>
                                    <div className="flex flex-col gap-2 mb-3">
                                        <label className="text-sm font-medium text-gray-700">
                                            Questions Per Question Type (for Live Quiz)
                                        </label>
                                        <label className="inline-flex items-center gap-2 text-sm text-gray-600">
                                            <input
                                                type="checkbox"
                                                className="rounded border-gray-300"
                                                checked={randomizeCounts}
                                                onChange={(e) => setRandomizeCounts(e.target.checked)}
                                            />
                                            Randomize question counts for each question type on every AI generation
                                        </label>
                                        <p className="text-xs text-gray-500">
                                            {randomizeCounts
                                                ? 'Provide the minimum and maximum number of questions per question type. The AI will randomly pick a quantity within the range each time.'
                                                : 'Set the exact number of questions for each question type. At least one question type must have questions.'}
                                        </p>
                                    </div>

                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    {[
                                        {
                                            key: 'multiple-choice' as QuestionType,
                                            label: 'Multiple Choice',
                                            border: 'border-blue-200',
                                            bg: 'bg-blue-50',
                                            text: 'text-blue-700',
                                        },
                                        {
                                            key: 'true-false' as QuestionType,
                                            label: 'True/False',
                                            border: 'border-purple-200',
                                            bg: 'bg-purple-50',
                                            text: 'text-purple-700',
                                        },
                                        {
                                            key: 'short-answer' as QuestionType,
                                            label: 'Short Answer',
                                            border: 'border-indigo-200',
                                            bg: 'bg-indigo-50',
                                            text: 'text-indigo-700',
                                        },
                                    ].map((questionType) => (
                                        <div
                                            key={questionType.key}
                                            className={`border rounded-lg p-4 ${questionType.border} ${questionType.bg}`}
                                        >
                                            <label className={`block text-sm font-semibold mb-2 ${questionType.text}`}>
                                                {questionType.label}
                                            </label>

                                            {!randomizeCounts ? (
                                                <input
                                                    type="number"
                                                    min="0"
                                                    max="50"
                                                    value={questionTypeCounts[questionType.key]}
                                                    onChange={(e) => handleQuestionTypeCountChange(questionType.key, parseInt(e.target.value) || 0)}
                                                    className="w-full px-4 py-2 border rounded-md focus:ring-purple-500 focus:border-purple-500 border-gray-200"
                                                    placeholder="Number of questions"
                                                />
                                            ) : (
                                                <div className="grid grid-cols-2 gap-2">
                                                    <div>
                                                        <label className="text-xs text-gray-600">Min</label>
                                                        <input
                                                            type="number"
                                                            min="0"
                                                            max="50"
                                                            value={randomRanges[questionType.key].min}
                                                            onChange={(e) => handleQuestionTypeRangeChange(questionType.key, 'min', parseInt(e.target.value) || 0)}
                                                            className="w-full px-3 py-2 border rounded-md focus:ring-purple-500 focus:border-purple-500 border-gray-200"
                                                            placeholder="Min"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="text-xs text-gray-600">Max</label>
                                                        <input
                                                            type="number"
                                                            min="0"
                                                            max="50"
                                                            value={randomRanges[questionType.key].max}
                                                            onChange={(e) => handleQuestionTypeRangeChange(questionType.key, 'max', parseInt(e.target.value) || 0)}
                                                            className="w-full px-3 py-2 border rounded-md focus:ring-purple-500 focus:border-purple-500 border-gray-200"
                                                            placeholder="Max"
                                                        />
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                    </div>
                                </div>
                            </div>

                            {/* Generate Button */}
                            <div className="flex justify-end">
                                <button
                                    onClick={handleGenerateQuiz}
                                    disabled={loading}
                                    className="bg-purple-600 text-white px-8 py-3 rounded-md text-lg font-semibold hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                                >
                                    {loading ? (
                                        <>
                                            <Loader2 className="w-5 h-5 animate-spin" />
                                            Generating Quiz...
                                        </>
                                    ) : (
                                        <>
                                            <Sparkles className="w-5 h-5" />
                                            Generate Quiz
                                        </>
                                    )}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
