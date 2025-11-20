import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, router, usePage } from '@inertiajs/react';
import { useState, useRef, useMemo, ChangeEvent, useEffect } from 'react';
import { X, PlusCircle, Eye, Save, LogOut, Trash2, Copy, Clock, List, Star, Image as ImageIcon, Trash2Icon, Edit2Icon, ChevronDown, Sparkles } from 'lucide-react';
import Swal from 'sweetalert2';
import 'sweetalert2/dist/sweetalert2.min.css';
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/Components/ui/dialog';
import { Button, Input } from '@headlessui/react';
import { Label } from 'recharts';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/Components/ui/tabs';
import EditModal from '@/CustomComponents/EditModal';
import axios from 'axios';
// Define interfaces for better type safety, matching backend snake_case for saving
interface Option {
    id: number;
    text: string; // Frontend uses 'text' for input, will map to 'option_text' for backend
    isCorrect: boolean; // Frontend uses 'isCorrect', will map to 'is_correct' for backend
}

interface Question {
    id: number;
    type: 'multiple-choice' | 'true-false' | 'short-answer';
    questionText: string; // Frontend uses 'questionText', will map to 'question_text' for backend
    image: string | null; // Frontend uses 'image' (base64), will map to 'image_path' for backend
    options: Option[];
    trueFalseAnswer: boolean | null; // Frontend uses 'trueFalseAnswer', will map to 'true_false_answer' for backend
    shortAnswer: string; // Frontend uses 'shortAnswer', will map to 'short_answer' for backend
    timeLimit: string; // Frontend uses 'timeLimit', will map to 'time_limit' for backend
    points: string;
    difficulty: 'easy' | 'average' | 'hard'; // New: Difficulty level
    showDetails: boolean;
}

export default function SubjectQuestionForm() {
    const { auth } = usePage().props as any;
    const user = auth?.user;

    const [questions, setQuestions] = useState<Question[]>([]);
    const [previewContent, setPreviewContent] = useState<React.ReactNode[]>([]);
    // Add this state variable to your component
    const [isFirstColumnCollapsed, setIsFirstColumnCollapsed] = useState(false);
    const [showEditModal, setShowEditModal] = useState(null)
    const [selectedQuestion, setSelectedQuestion] = useState(null)
    const { subject_questions, subjectId } = usePage().props;
    const [showPreview, setShowPreview] = useState<boolean>(true);
    const [quizTitle, setQuizTitle] = useState<string>(subject_questions[0].subject_name);
    const fileInputRefs = useRef<{ [key: number]: HTMLInputElement | null }>({});
    const [showModal, setShowModal] = useState<boolean>(subject_questions[0].subjects_questions.length < 1 ? true : false);

    const [bulkQuestion, setBulkQuestions] = useState<Question[]>([]);

    const handleBlankCanvasClick = (): void => {
        setShowModal(false);
    };

    const saveToBulkQuestion = () => {
        if (questions.length > 0) {
            if (questions[0].questionText.trim().length > 0 && questions[0].timeLimit.length > 0 && questions[0].points.length > 0) {
                setBulkQuestions(prevQuestions => [
                    ...prevQuestions,
                    questions[0]
                ]);
            }

        }
    }

    const addQuestion = (type: 'multiple-choice' | 'true-false' | 'short-answer', level: 'easy' | 'average' | 'hard'): void => {


        saveToBulkQuestion()

        setQuestions([{
            id: Date.now(),
            type: type,
            questionText: '',
            image: null,
            options: type === 'multiple-choice' ? [{ id: 1, text: '', isCorrect: false }, { id: 2, text: '', isCorrect: false }, { id: 3, text: '', isCorrect: false }, { id: 4, text: '', isCorrect: false }] : [],
            trueFalseAnswer: null,
            shortAnswer: '',
            timeLimit: '',
            points: '',
            difficulty: level, // Default difficulty
            showDetails: true,
        }]
        );
    };

    const handleQuestionChange = (id: number, field: keyof Question, value: string | boolean | null): void => {
        setQuestions(prevQuestions =>
            prevQuestions.map(q => q.id === id ? { ...q, [field]: value } : q)
        );
    };

    const handleOptionChange = (questionId: number, optionId: number, field: keyof Option, value: string | boolean): void => {
        setQuestions(prevQuestions =>
            prevQuestions.map(q =>
                q.id === questionId
                    ? {
                        ...q,
                        options: q.options.map(opt =>
                            opt.id === optionId ? { ...opt, [field]: value } : opt
                        ),
                    }
                    : q
            )
        );
    };

    const handleCorrectAnswerChange = (questionId: number, optionId: number): void => {
        setQuestions(prevQuestions =>
            prevQuestions.map(q =>
                q.id === questionId
                    ? {
                        ...q,
                        options: q.options.map(opt => ({
                            ...opt,
                            isCorrect: opt.id === optionId,
                        })),
                    }
                    : q
            )
        );
    };

    const handleTrueFalseChange = (questionId: number, value: boolean): void => {
        setQuestions(prevQuestions =>
            prevQuestions.map(q => q.id === questionId ? { ...q, trueFalseAnswer: value } : q)
        );
    };

    const handleImageUpload = (questionId: number, event: ChangeEvent<HTMLInputElement>): void => {
        const file = event.target.files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                setQuestions(prevQuestions =>
                    prevQuestions.map(q => q.id === questionId ? { ...q, image: reader.result as string } : q)
                );
            };
            reader.readAsDataURL(file);
        }
    };

    const toggleQuestionDetails = (id: number): void => {
        setQuestions(prevQuestions =>
            prevQuestions.map(q => q.id === id ? { ...q, showDetails: !q.showDetails } : q)
        );
    };

    const handleDeleteQuestion = async (question, elId) => {
        const result = await Swal.fire({
            title: 'Are you sure?',
            text: `Delete ${question.question}? This cannot be undone!`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        });

        if (result.isConfirmed) {
            // Perform delete operation
            try {

                router.delete(route('question.delete'), {
                    data: { id: question.id },
                    onSuccess: () => {
                        Swal.fire(
                            'Deleted!',
                            `${question.question} has been deleted.`,
                            'success'
                        )
                    },
                })
            } catch (error) {
                console.log(error)
            }


        }
    };

    const updatePreview = () => {
        const parsedQuestions = subject_questions[0].subjects_questions.map(q => ({
            ...q,
            options: JSON.parse(q.options),
        }));

        const merged = [...parsedQuestions, ...questions];

        const easy_questions = merged.filter(q => q.difficulty.toLowerCase() === "easy");
        const average_questions = merged.filter(q => q.difficulty.toLowerCase() === "average");
        const hard_questions = merged.filter(q => q.difficulty.toLowerCase() === "hard");

        // Reusable component for question table
        const QuestionTable = ({ questions, difficulty, difficultyLabel }) => (
            <Table>
                <TableCaption>A list of {difficultyLabel} Questions.</TableCaption>

                <TableHeader>
                    <TableRow>
                        <TableHead className="w-[100px]">Question</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Answer</TableHead>
                        <TableHead>Time Limit</TableHead>
                        <TableHead>Points</TableHead>
                        <TableHead>Action</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {questions.length > 0 ? (
                        questions.map((q, index) => (
                            <TableRow key={`${difficulty}-${q.id}`} id={`${difficulty}-${q.id}`}>
                                <TableCell className="font-medium">
                                    <p className="font-semibold">
                                        {q.questionText || q.question || 'Untitled'}
                                    </p>
                                </TableCell>
                                <TableCell>{q.type}</TableCell>
                                <TableCell>
                                    {q.type === 'multiple-choice' && (
                                        <ul className="list-disc ml-5 text-sm">
                                            {q.options
                                                .filter(opt => opt.isCorrect)
                                                .map(opt => (
                                                    <li key={opt.id} className="text-green-600 font-medium list-none">
                                                        {opt.text || 'Option'} (Correct)
                                                    </li>
                                                ))
                                            }
                                        </ul>
                                    )}
                                    {q.type === 'true-false' && (
                                        <p className="text-sm">
                                            Correct Answer: {q.trueFalseAnswer !== null ? (q.trueFalseAnswer == 1 ? 'True' : 'False') : 'Not set'}
                                        </p>
                                    )}
                                    {q.type === 'short-answer' && (
                                        <p className="text-sm">
                                            Correct Answer: {q.shortAnswer || 'Not set'}
                                        </p>
                                    )}
                                </TableCell>
                                <TableCell>{q.timeLimit}</TableCell>
                                <TableCell>{q.points}</TableCell>
                                <TableCell>
                                    <div className="flex items-center justify-evenly space-x-2">
                                        <div className="p-1 rounded hover:bg-red-200 hover:text-white cursor-pointer">
                                            <Trash2Icon
                                                onClick={() => handleDeleteQuestion(q, `${difficulty}-${q.id}`)}
                                                className="w-4 h-4 text-red-600"
                                            />
                                        </div>
                                        <div className="p-1 rounded hover:bg-yellow-200 hover:text-white cursor-pointer">
                                            <Edit2Icon
                                                onClick={() => { setShowEditModal(true); setSelectedQuestion(q) }}
                                                className="w-4 h-4 text-yellow-600"
                                            />
                                        </div>
                                    </div>
                                </TableCell>
                            </TableRow>
                        ))
                    ) : (
                        <TableRow>
                            <TableCell colSpan={6} className="text-center text-gray-500">
                                No {difficultyLabel.toLowerCase()} questions
                            </TableCell>
                        </TableRow>
                    )}
                </TableBody>
            </Table>
        );

        const newPreviewContent = (
            <div className="mt-3">
                <Tabs defaultValue="easy" className="w-full">
                    <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="easy" className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                            Easy ({easy_questions.length})
                        </TabsTrigger>
                        <TabsTrigger value="average" className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-yellow-500 rounded-full"></span>
                            Average ({average_questions.length})
                        </TabsTrigger>
                        <TabsTrigger value="hard" className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                            Hard ({hard_questions.length})
                        </TabsTrigger>
                    </TabsList>

                    <TabsContent value="easy" className="mt-6">
                        <div className="space-y-4">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                                <h3 className="text-lg font-semibold text-green-700">Easy Questions</h3>
                            </div>
                            <QuestionTable
                                questions={easy_questions}
                                difficulty="easy"
                                difficultyLabel="Easy"
                            />
                        </div>
                    </TabsContent>

                    <TabsContent value="average" className="mt-6">
                        <div className="space-y-4">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                                <h3 className="text-lg font-semibold text-yellow-700">Average Questions</h3>
                            </div>
                            <QuestionTable
                                questions={average_questions}
                                difficulty="average"
                                difficultyLabel="Average"
                            />
                        </div>
                    </TabsContent>

                    <TabsContent value="hard" className="mt-6">
                        <div className="space-y-4">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                                <h3 className="text-lg font-semibold text-red-700">Hard Questions</h3>
                            </div>
                            <QuestionTable
                                questions={hard_questions}
                                difficulty="hard"
                                difficultyLabel="Hard"
                            />
                        </div>
                    </TabsContent>
                </Tabs>
            </div>
        );

        setPreviewContent([newPreviewContent]);
        setShowPreview(true);
    };
    // const updatePreview = () => {


    //     const parsedQuestions = subject_questions[0].subjects_questions.map(q => ({
    //         ...q,
    //         options: JSON.parse(q.options),
    //     }));



    //     const merged = [...parsedQuestions, ...questions];

    //     const easy_questions = merged.filter(q => q.difficulty.toLowerCase() == "easy")
    //     const average_questions = merged.filter(q => q.difficulty.toLowerCase() == "average")
    //     const hard_questions = merged.filter(q => q.difficulty.toLowerCase() == "hard")

    //     const newPreviewContent = <div className='mt-3 flex flex-col gap-y-10'>

    //         <div>
    //             <p className='text-red-600 font-bold'>Easy Questions</p>
    //             <Table>
    //                 <TableCaption>A list Easy Questions.</TableCaption>
    //                 <TableHeader>
    //                     <TableRow>
    //                         <TableHead className="w-[100px]">Question</TableHead>
    //                         <TableHead>Type</TableHead>
    //                         <TableHead>Answer</TableHead>
    //                         <TableHead >Time Limit</TableHead>
    //                         <TableHead >Points</TableHead>
    //                         <TableHead >Action</TableHead>
    //                     </TableRow>
    //                 </TableHeader>
    //                 <TableBody>
    //                     {
    //                         easy_questions.length > 0 ?
    //                             easy_questions?.map((q, index) =>
    //                                 <TableRow key={`easy${q.id}`} id={`easy-${q.id}`}>
    //                                     <TableCell className="font-medium">     <p className="font-semibold"> {q.questionText || q.question || `Untitled`} </p></TableCell>
    //                                     <TableCell>{q.type}</TableCell>
    //                                     <TableCell>

    //                                         {q.type === 'multiple-choice' && (
    //                                             <ul className="list-disc ml-5 text-sm">
    //                                                 {q.options
    //                                                     .filter(opt => opt.isCorrect)
    //                                                     .map(opt => (
    //                                                         <li key={opt.id} className="text-green-600 font-medium list-none">
    //                                                             {opt.text || 'Option'} (Correct)
    //                                                         </li>
    //                                                     ))
    //                                                 }

    //                                             </ul>
    //                                         )}
    //                                         {q.type === 'true-false' && (
    //                                             <p className="text-sm">Correct Answer: {q.trueFalseAnswer !== null ? (q.trueFalseAnswer == 1 ? 'True' : 'False') : 'Not set'}</p>
    //                                         )}
    //                                         {q.type === 'short-answer' && (
    //                                             <p className="text-sm">Correct Answer: {q.shortAnswer || 'Not set'}</p>
    //                                         )}
    //                                     </TableCell>
    //                                     <TableCell >{q.timeLimit}</TableCell>
    //                                     <TableCell>{q.points}</TableCell>
    //                                     <TableCell>
    //                                         <div className="flex items-center justify-evenly space-x-2">
    //                                             <div className="p-1 rounded hover:bg-red-200 hover:text-white cursor-pointer">
    //                                                 <Trash2Icon onClick={() => handleDeleteQuestion(q, `easy-${q.id}`)} className="w-4 h-4 text-red-600" />
    //                                             </div>
    //                                             <div className="p-1 rounded hover:bg-yellow-200 hover:text-white cursor-pointer">
    //                                                 <Edit2Icon onClick={() => { setShowEditModal(true); setSelectedQuestion(q) }} className="w-4 h-4 text-yellow-600" />
    //                                             </div>
    //                                         </div>
    //                                     </TableCell>

    //                                 </TableRow>
    //                             )
    //                             : <p>No easy questions</p>
    //                     }

    //                 </TableBody>
    //             </Table>
    //         </div>

    //         <div>
    //             <p className='text-red-600 font-bold'>Average Questions</p>
    //             <Table>
    //                 <TableCaption>A list Average Questions.</TableCaption>
    //                 <TableHeader>
    //                     <TableRow>
    //                         <TableHead className="w-[100px]">Question</TableHead>
    //                         <TableHead>Type</TableHead>
    //                         <TableHead>Answer</TableHead>
    //                         <TableHead >Time Limit</TableHead>
    //                         <TableHead >Points</TableHead>
    //                         <TableHead >Action</TableHead>
    //                     </TableRow>
    //                 </TableHeader>
    //                 <TableBody>
    //                     {
    //                         average_questions.length > 0 ?
    //                             average_questions?.map((q, index) =>
    //                                 <TableRow key={q.id} id={`average-${q.id}`}>
    //                                     <TableCell className="font-medium">     <p className="font-semibold"> {q.questionText || q.question || `Untitled`} </p></TableCell>
    //                                     <TableCell>{q.type}</TableCell>
    //                                     <TableCell>

    //                                         {q.type === 'multiple-choice' && (
    //                                             <ul className="list-disc ml-5 text-sm">
    //                                                 {q.options
    //                                                     .filter(opt => opt.isCorrect)
    //                                                     .map(opt => (
    //                                                         <li key={opt.id} className="text-green-600 font-medium list-none">
    //                                                             {opt.text || 'Option'} (Correct)
    //                                                         </li>
    //                                                     ))
    //                                                 }

    //                                             </ul>
    //                                         )}
    //                                         {q.type === 'true-false' && (
    //                                             <p className="text-sm">Correct Answer: {q.trueFalseAnswer !== null ? (q.trueFalseAnswer == 1 ? 'True' : 'False') : 'Not set'}</p>
    //                                         )}
    //                                         {q.type === 'short-answer' && (
    //                                             <p className="text-sm">Correct Answer: {q.shortAnswer || 'Not set'}</p>
    //                                         )}
    //                                     </TableCell>
    //                                     <TableCell >{q.timeLimit}</TableCell>
    //                                     <TableCell>{q.points}</TableCell>
    //                                     <TableCell>
    //                                         <div className="flex items-center justify-evenly space-x-2">
    //                                             <div className="p-1 rounded hover:bg-red-200 hover:text-white cursor-pointer">
    //                                                 <Trash2Icon onClick={() => handleDeleteQuestion(q, `average-${q.id}`)} className="w-4 h-4 text-red-600" />
    //                                             </div>
    //                                             <div className="p-1 rounded hover:bg-yellow-200 hover:text-white cursor-pointer">
    //                                                 <Edit2Icon onClick={() => { setShowEditModal(true); setSelectedQuestion(q) }} className="w-4 h-4 text-yellow-600" />
    //                                             </div>
    //                                         </div>
    //                                     </TableCell>

    //                                 </TableRow>
    //                             )
    //                             : <p>No average questions</p>
    //                     }

    //                 </TableBody>
    //             </Table>
    //         </div>

    //         <div>
    //             <p className='text-red-600 font-bold'>Hard Questions</p>
    //             <Table>
    //                 <TableCaption>A list Hard Questions.</TableCaption>
    //                 <TableHeader>
    //                     <TableRow>
    //                         <TableHead className="w-[100px]">Question</TableHead>
    //                         <TableHead>Type</TableHead>
    //                         <TableHead>Answer</TableHead>
    //                         <TableHead >Time Limit</TableHead>
    //                         <TableHead >Points</TableHead>
    //                         <TableHead >Action</TableHead>
    //                     </TableRow>
    //                 </TableHeader>
    //                 <TableBody>
    //                     {
    //                         hard_questions.length > 0 ?
    //                             hard_questions?.map((q, index) =>
    //                                 <TableRow key={q.id} id={`hard-${q.id}`}>
    //                                     <TableCell className="font-medium">     <p className="font-semibold"> {q.questionText || q.question || `Untitled`} </p></TableCell>
    //                                     <TableCell>{q.type}</TableCell>
    //                                     <TableCell>

    //                                         {q.type === 'multiple-choice' && (
    //                                             <ul className="list-disc ml-5 text-sm">
    //                                                 {q.options
    //                                                     .filter(opt => opt.isCorrect)
    //                                                     .map(opt => (
    //                                                         <li key={opt.id} className="text-green-600 font-medium list-none">
    //                                                             {opt.text || 'Option'} (Correct)
    //                                                         </li>
    //                                                     ))
    //                                                 }

    //                                             </ul>
    //                                         )}
    //                                         {q.type === 'true-false' && (
    //                                             <p className="text-sm">Correct Answer: {q.trueFalseAnswer !== null ? (q.trueFalseAnswer == 1 ? 'True' : 'False') : 'Not set'}</p>
    //                                         )}
    //                                         {q.type === 'short-answer' && (
    //                                             <p className="text-sm">Correct Answer: {q.shortAnswer || 'Not set'}</p>
    //                                         )}
    //                                     </TableCell>
    //                                     <TableCell >{q.timeLimit}</TableCell>
    //                                     <TableCell>{q.points}</TableCell>
    //                                     <TableCell>
    //                                         <div className="flex items-center justify-evenly space-x-2">
    //                                             <div className="p-1 rounded hover:bg-red-200 hover:text-white cursor-pointer">
    //                                                 <Trash2Icon onClick={() => handleDeleteQuestion(q, `hard-${q.id}`)} className="w-4 h-4 text-red-600" />
    //                                             </div>
    //                                             <div className="p-1 rounded hover:bg-yellow-200 hover:text-white cursor-pointer">
    //                                                 <Edit2Icon onClick={() => { setShowEditModal(true); setSelectedQuestion(q) }} className="w-4 h-4 text-yellow-600" />
    //                                             </div>
    //                                         </div>
    //                                     </TableCell>

    //                                 </TableRow>
    //                             )
    //                             : <p>No hard questions</p>
    //                     }

    //                 </TableBody>
    //             </Table>
    //         </div>
    //     </div>


    //     // const newPreviewContent = merged.map((q, index) => (
    //     //     <div key={q.id} className="mb-2 p-2 border rounded-md bg-gray-50">
    //     //         <p className="font-semibold">Question {index + 1}: {q.questionText || q.question || `Untitled ${q.type}`} </p>
    //     //         <p className="text-xs text-gray-600">Difficulty: {q.difficulty.charAt(0).toUpperCase() + q.difficulty.slice(1)}</p> {/* Display difficulty */}
    //     //         {q.type === 'multiple-choice' && (
    //     //             <ul className="list-disc ml-5 text-sm">
    //     //                 {q.options.map(opt => (
    //     //                     <li key={opt.id} className={opt.isCorrect ? 'text-green-600 font-medium' : ''}>
    //     //                         {opt.text || 'Option'} {opt.isCorrect && '(Correct)'}
    //     //                     </li>
    //     //                 ))}
    //     //             </ul>
    //     //         )}
    //     //         {q.type === 'true-false' && (
    //     //             <p className="text-sm">Correct Answer: {q.trueFalseAnswer !== null ? (q.trueFalseAnswer ? 'True' : 'False') : 'Not set'}</p>
    //     //         )}
    //     //         {q.type === 'short-answer' && (
    //     //             <p className="text-sm">Correct Answer: {q.shortAnswer || 'Not set'}</p>
    //     //         )}
    //     //         {q.timeLimit && <p className="text-sm">Time Limit: {q.timeLimit} seconds</p>}
    //     //         {q.points && <p className="text-sm">Points: {q.points}</p>}
    //     //         {q.image != 0 && <img src={q.image} alt="Question" className="mt-2 h-20 w-auto object-cover rounded" />}
    //     //     </div>
    //     // ));
    //     setPreviewContent([newPreviewContent]);
    //     setShowPreview(true);
    // };

    const totalPoints = useMemo<number>(() => {
        const saveQuestionsTotalPoints = subject_questions[0].subjects_questions.reduce((sum, q) => sum + (parseInt(q.points) || 0), 0);
        const addedBulkQuestionsTotalPoints = bulkQuestion.reduce((sum, q) => sum + (parseInt(q.points) || 0), 0);
        const addedQuestionsTotalPoints = questions.reduce((sum, q) => sum + (parseInt(q.points) || 0), 0);
        return saveQuestionsTotalPoints + addedQuestionsTotalPoints + addedBulkQuestionsTotalPoints
    }, [questions, bulkQuestion, subject_questions]);

    const totalTimeLimit = useMemo<number>(() => {

        const saveQuestionsTotalTime = subject_questions[0].subjects_questions.reduce((sum, q) => sum + (parseInt(q.timeLimit) || 0), 0);
        const addedBulkQuestionsTotalTime = bulkQuestion.reduce((sum, q) => sum + (parseInt(q.timeLimit) || 0), 0);
        const addedQuestionsTotalTime = questions.reduce((sum, q) => sum + (parseInt(q.timeLimit) || 0), 0);

        return saveQuestionsTotalTime + addedQuestionsTotalTime + addedBulkQuestionsTotalTime
    }, [questions, bulkQuestion, subject_questions]);

    // const totalQuestionsCount = questions.length;
    const totalQuestionsCount = questions.length + bulkQuestion.length;
    useEffect(() => {
        updatePreview()
    }, [subject_questions])
    const handleSave = (): void => {
        // compute the new state manually
        let updatedBulk = bulkQuestion
        if (questions.length > 0) {
            if (questions[0].questionText.trim().length > 0 && questions[0].timeLimit.length > 0 && questions[0].points.length > 0) {
                updatedBulk = [...bulkQuestion, questions[0]];
            }

        }


        let quizes_questions = []

        if (quizTitle.trim().length == 0) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'Quiz title is required',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
                background: '#fff',
                // color: '#399918',
                // iconColor: '#399918 ',
            });
            return
        }
        updatedBulk.forEach(question => {
            const quizData = {
                title: quizTitle,
                subject_id: subjectId as number, // or as string, depending on what it is
                question: question.questionText,
                type: question.type,
                image: question.image,
                timeLimit: question.timeLimit ? parseInt(question.timeLimit) : null,
                points: question.points,
                difficulty: question.difficulty,
                options: JSON.stringify(question.type === 'multiple-choice' ? question.options.map(opt => ({
                    text: opt.text,
                    isCorrect: opt.isCorrect,
                })) : null),
                trueFalseAnswer: question.type === 'true-false'
                    ? (question.trueFalseAnswer === true || question.trueFalseAnswer === false
                        ? question.trueFalseAnswer
                        : null)
                    : null,

                shortAnswer: question.type === 'short-answer' ? (question.shortAnswer || null) : null,
                quiz_title: quizTitle

            };
            quizes_questions.push(quizData)
        });


        console.log(quizes_questions)
        // return;
        // return;
        router.post('/add-subject-quiz',
            { data: JSON.stringify(quizes_questions), quiz_title: quizTitle, subject_id: subjectId as number }
            , {
                onSuccess: () => {
                    Swal.fire({
                        toast: true,
                        position: 'top-end',
                        icon: 'success',
                        title: 'Quiz created successfully!',
                        showConfirmButton: false,
                        timer: 3000,
                        timerProgressBar: true,
                    });
                    setQuizTitle('');
                    setQuestions([]);
                    setPreviewContent([]);
                    setShowPreview(false);
                    setBulkQuestions([]);


                },
                onError: (errors) => {
                    console.error('Error saving quiz:', errors);
                    Swal.fire({
                        toast: true,
                        position: 'top-end',
                        icon: 'error',
                        title: 'Error saving quiz. Please check your inputs.',
                        showConfirmButton: false,
                        timer: 3000,
                        timerProgressBar: true,
                    });
                },
            });
    };

    const handleExit = (): void => {
        // setShowModal(true);
        // setQuestions([]);
        // setQuizTitle('');
        // setPreviewContent([]);
        // setShowPreview(false);
        
        // Redirect based on user role
        // Role 3 = Organizer → organizerLobby
        // Role 1 = Teacher → dashboard
        if (user?.role === 3) {
            router.get("/organizerLobby");
        } else if (user?.role === 1) {
            router.get("/dashboard");
        } else {
            // Default fallback
            router.get("/dashboard");
        }
    };

    const handleDelete = (id: number): void => {
        setQuestions(prevQuestions => prevQuestions.filter(q => q.id !== id));
    };

    const handleDuplicate = (id: number): void => {
        const questionToDuplicate = questions.find(q => q.id === id);
        if (questionToDuplicate) {
            const duplicatedQuestion: Question = { ...questionToDuplicate, id: Date.now(), questionText: `${questionToDuplicate.questionText} (Copy)`, showDetails: true };
            setQuestions(prevQuestions => [...prevQuestions, duplicatedQuestion]);
        }
    };
    useEffect(() => {
        if (subject_questions) {
            setQuizTitle(subject_questions[0]?.['quiz_title'] || "")
        }
    }, [subject_questions])
    const [selectedRound, setSelectedRound] = useState('');

    const rounds = [
        { value: 'easy', label: 'Easy Round', color: 'red' },
        { value: 'average', label: 'Average Round', color: 'red' },
        { value: 'hard', label: 'Hard Round', color: 'red' }
    ];

    const currentRound = rounds.find(round => round.value === selectedRound);

    useEffect(() => {
        setQuizTitle(subject_questions[0].subject_name)
    }, [subject_questions])


    return (
        <AuthenticatedLayout>
            <Head title="Create Quiz" />

            {
                showEditModal && <EditModal setShow={setShowEditModal} show={showEditModal} question={selectedQuestion} />
            }

            {showModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center" onClick={() => setShowModal(false)}>
                    <div className="bg-white p-6 rounded-lg w-full max-w-4xl relative shadow-2xl" onClick={(e) => e.stopPropagation()}>
                        <button onClick={() => setShowModal(false)} className="absolute top-3 right-3 text-gray-500 hover:text-gray-700">
                            <X size={24} />
                        </button>
                        <h2 className="text-2xl font-bold mb-4">Create a new quiz</h2>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div className="border rounded-lg p-4 shadow-md text-center cursor-pointer hover:bg-gray-50 transition-colors bg-gradient-to-br from-purple-50 to-pink-50 border-purple-200" onClick={() => {
                                setShowModal(false);
                                const subjectQuery = subjectId ? `?subject_id=${subjectId}` : '';
                                router.visit(`/explore${subjectQuery}`);
                            }}>
                                <div className="flex items-center justify-center mb-2">
                                    <div className="bg-gradient-to-br from-purple-500 to-pink-500 rounded-full p-3">
                                        <Sparkles size={32} className="text-white" />
                                    </div>
                                </div>
                                <h3 className="font-semibold text-purple-700">AI Generation</h3>
                                <p className="text-sm text-gray-600 mb-2">Generate quiz using AI</p>
                                <button className="bg-gradient-to-r from-purple-500 to-pink-500 text-white px-4 py-2 rounded hover:from-purple-600 hover:to-pink-600 transition-colors font-medium">AI Generate</button>
                            </div>
                            <div className="border rounded-lg p-4 shadow-md text-center cursor-not-allowed opacity-60">
                                <img src="https://placehold.co/96x96/e0e0e0/333333?text=PDF" alt="PDF to Quiz" className="mx-auto mb-2 w-24 h-24 object-contain" />
                                <h3 className="font-semibold">PDF to Quiz</h3>
                                <p className="text-sm text-gray-600 mb-2">Generate or extract questions from your PDF</p>
                                <button className="border border-red-500 text-red-500 px-3 py-1 rounded cursor-not-allowed">AI Assisted</button>
                            </div>
                            <div className="border rounded-lg p-4 shadow-md text-center cursor-not-allowed opacity-60">
                                <img src="https://placehold.co/96x96/e0e0e0/333333?text=Notes" alt="Notes to Quiz" className="mx-auto mb-2 w-24 h-24 object-contain" />
                                <h3 className="font-semibold">Notes to Quiz</h3>
                                <p className="text-sm text-gray-600 mb-2">Generate extract questions from your Notes</p>
                                <button className="border border-red-500 text-red-500 px-3 py-1 rounded cursor-not-allowed">AI Assisted</button>
                            </div>
                            <div className="border rounded-lg p-4 shadow-md text-center flex flex-col items-center justify-center cursor-pointer hover:bg-gray-50 transition-colors" onClick={handleBlankCanvasClick}>
                                <PlusCircle size={48} className="text-gray-500 mb-2" />
                                <h3 className="font-semibold">Blank Canvas</h3>
                                <p className="text-sm text-gray-600">Create a quiz from scratch</p>
                            </div>
                        </div>

                        <div className="mt-6 text-center">
                            <button
                                onClick={() => setShowModal(false)}
                                className="bg-gray-200 text-gray-800 px-6 py-2 rounded shadow hover:bg-gray-300 transition-colors"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <div className={`py-12 px-6 grid gap-6 transition-all duration-300 grid-cols-3`}>

                {/* Column 1 - Quiz Questions (Collapsible) */}
                <div className={`relative transition-all duration-300 ${isFirstColumnCollapsed ? 'md:hidden' : 'block'
                    }`}>
                    {/* Collapse/Expand Button - Only show when NOT collapsed */}
                    {!isFirstColumnCollapsed && (
                        <button
                            onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                setIsFirstColumnCollapsed(true);
                            }}
                            className="absolute -right-3 top-4 z-50 bg-red-600 text-white p-2 rounded-full shadow-lg hover:bg-red-700 transition-colors md:flex hidden items-center justify-center cursor-pointer"
                            title="Collapse Questions Panel"
                            type="button"
                        >
                            <ChevronLeft size={16} />
                        </button>
                    )}
                    <div>
                        <div className="mt-6 mb-10">
                            {/* Round Selector */}
                            <div className="mb-4">
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Select Difficulty Round
                                </label>
                                <div className="relative">
                                    <select
                                        value={selectedRound}
                                        onChange={(e) => setSelectedRound(e.target.value)}
                                        className="w-full appearance-none bg-white border border-gray-300 rounded-lg px-4 py-2 pr-8 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                    >
                                        <option value={""}>
                                            Select
                                        </option>
                                        {rounds.map(round => (
                                            <option key={round.value} value={round.value}>
                                                {round.label}
                                            </option>
                                        ))}
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
                                </div>
                            </div>

                            {/* Question Type Buttons */}
                            {selectedRound !== ""
                                && <div className="flex flex-wrap gap-3">
                                    <p className={`border-b border-${currentRound.color}-600 w-full p-2 font-bold text-${currentRound.color}-600`}>
                                        {currentRound.label}
                                    </p>
                                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 w-full">
                                        <button
                                            onClick={() => addQuestion('multiple-choice', selectedRound)}
                                            className={`bg-${currentRound.color}-600 text-white rounded-full px-6 py-2 shadow-lg hover:bg-${currentRound.color}-700 transition-colors flex items-center justify-center gap-2`}
                                        >
                                            <PlusCircle size={20} /> Add Multiple Choice
                                        </button>
                                        <button
                                            onClick={() => addQuestion('true-false', selectedRound)}
                                            className={`bg-${currentRound.color}-600 text-white rounded-full px-6 py-2 shadow-lg hover:bg-${currentRound.color}-700 transition-colors flex items-center justify-center gap-2`}
                                        >
                                            <PlusCircle size={20} /> Add True/False
                                        </button>
                                        <button
                                            onClick={() => addQuestion('short-answer', selectedRound)}
                                            className={`bg-${currentRound.color}-600 text-white rounded-full px-6 py-2 shadow-lg hover:bg-${currentRound.color}-700 transition-colors flex items-center justify-center gap-2`}
                                        >
                                            <PlusCircle size={20} /> Add Short Answer
                                        </button>
                                    </div>
                                </div>
                            }

                        </div>
                    </div>
                    {/* <label htmlFor="quiz-title" className="block text-sm font-medium text-gray-700 mb-1">Quiz Title</label>
                    <input
                        id="quiz-title"
                        type="text"
                        placeholder="Enter Quiz Title"
                        className="w-full border p-3 mb-4 rounded-lg shadow-sm focus:ring-red-500 focus:border-red-500"
                        value={quizTitle}
                        onChange={(e: ChangeEvent<HTMLInputElement>) => setQuizTitle(e.target.value)}
                        disabled
                    /> */}

                    <div className="space-y-4">
                        {questions.map((q) => (
                            <div key={q.id} className="border rounded-lg p-4 shadow-md bg-white">
                                <div className="flex justify-between items-center mb-2">
                                    <h4 className="font-semibold text-lg cursor-pointer" onClick={() => toggleQuestionDetails(q.id)}>
                                        Question: {q.questionText || `Untitled ${q.type}`}
                                    </h4>
                                    <div className="flex gap-2">
                                        <button onClick={() => handleDelete(q.id)} className="text-red-500 hover:text-red-700">
                                            <Trash2 size={20} />
                                        </button>
                                        <button onClick={() => handleDuplicate(q.id)} className="text-gray-500 hover:text-gray-700">
                                            <Copy size={20} />
                                        </button>
                                    </div>
                                </div>

                                {q.showDetails && (
                                    <>
                                        <div className="mb-3">
                                            <label htmlFor={`question-text-${q.id}`} className="block text-sm font-medium text-gray-700 mb-1">Question Text</label>
                                            <input
                                                id={`question-text-${q.id}`}
                                                type="text"
                                                placeholder="Enter question text"
                                                className="w-full border p-2 rounded-md focus:ring-black focus:border-black"
                                                value={q.questionText}
                                                onChange={(e: ChangeEvent<HTMLInputElement>) => {
                                                    const value = e.target.value.replace(/\?/g, ''); // remove all “?”
                                                    handleQuestionChange(q.id, 'questionText', value);
                                                }}
                                            />
                                        </div>

                                        {/* <div className="mb-3">
                                            <label className="block text-sm font-medium text-gray-700 mb-1">Question Type</label>
                                            <select
                                                // disabled={true}
                                                className="w-full border p-2 rounded-md focus:ring-red-500 focus:border-red-500"
                                                value={q.type}
                                                onChange={(e: ChangeEvent<HTMLSelectElement>) => handleQuestionChange(q.id, 'type', e.target.value as Question['type'])}
                                            >
                                                <option value="multiple-choice">Multiple Choice</option>
                                                <option value="true-false">True/False</option>
                                                <option value="short-answer">Short Answer</option>
                                            </select>
                                        </div> */}

                                        {/* New: Difficulty Level Selection */}
                                        {/* <div className="mb-3">
                                            <label htmlFor={`difficulty-${q.id}`} className="block text-sm font-medium text-gray-700 mb-1">Difficulty Level</label>
                                            <select
                                                // disabled={true}
                                                id={`difficulty-${q.id}`}
                                                className="w-full border p-2 rounded-md focus:ring-red-500 focus:border-red-500"
                                                value={q.difficulty}
                                                onChange={(e: ChangeEvent<HTMLSelectElement>) => handleQuestionChange(q.id, 'difficulty', e.target.value as Question['difficulty'])}
                                            >
                                                <option value="easy">Easy</option>
                                                <option value="average">Average</option>
                                                <option value="hard">Hard</option>
                                            </select>
                                        </div> */}

                                        {q.type === 'multiple-choice' && (
                                            <div className="mb-3">
                                                <label className="block text-sm font-medium text-gray-700 mb-2">Answer Options (Select correct one)</label>
                                                {q.options.map((opt, index) => (
                                                    <div key={opt.id} className="flex items-center gap-2 mb-2">
                                                        <input
                                                            type="radio"
                                                            name={`correct-answer-${q.id}`}
                                                            checked={opt.isCorrect}
                                                            onChange={() => handleCorrectAnswerChange(q.id, opt.id)}
                                                            className="form-radio text-red-600"
                                                        />
                                                        <input
                                                            type="text"
                                                            placeholder={`Option ${index + 1}`}
                                                            className="flex-grow border p-2 rounded-md focus:ring-black focus:border-black"
                                                            value={opt.text}
                                                            onChange={(e: ChangeEvent<HTMLInputElement>) => handleOptionChange(q.id, opt.id, 'text', e.target.value)}
                                                        />
                                                    </div>
                                                ))}
                                            </div>
                                        )}

                                        {q.type === 'true-false' && (
                                            <div className="mb-3">
                                                <label className="block text-sm font-medium text-gray-700 mb-2">Correct Answer</label>
                                                <div className="flex gap-4">
                                                    <label className="inline-flex items-center">
                                                        <input
                                                            type="radio"
                                                            name={`true-false-${q.id}`}
                                                            value="true"
                                                            checked={q.trueFalseAnswer === true}
                                                            onChange={() => handleTrueFalseChange(q.id, true)}
                                                            className="form-radio text-red-600"
                                                        />
                                                        <span className="ml-2">True</span>
                                                    </label>
                                                    <label className="inline-flex items-center">
                                                        <input
                                                            type="radio"
                                                            name={`true-false-${q.id}`}
                                                            value="false"
                                                            checked={q.trueFalseAnswer === false}
                                                            onChange={() => handleTrueFalseChange(q.id, false)}
                                                            className="form-radio text-red-600"
                                                        />
                                                        <span className="ml-2">False</span>
                                                    </label>
                                                </div>
                                            </div>
                                        )}

                                        {q.type === 'short-answer' && (
                                            <div className="mb-3">
                                                <label htmlFor={`short-answer-${q.id}`} className="block text-sm font-medium text-gray-700 mb-1">Correct Answer</label>
                                                <input
                                                    id={`short-answer-${q.id}`}
                                                    type="text"
                                                    placeholder="Enter short answer"
                                                    className="w-full border p-2 rounded-md focus:ring-black focus:border-black"
                                                    value={q.shortAnswer}
                                                    onChange={(e: ChangeEvent<HTMLInputElement>) => handleQuestionChange(q.id, 'shortAnswer', e.target.value)}
                                                />
                                            </div>
                                        )}

                                        <div className="mb-3">
                                            <label htmlFor={`time-limit-${q.id}`} className="block text-sm font-medium text-gray-700 mb-1">Time Limit (seconds)</label>
                                            <input
                                                id={`time-limit-${q.id}`}
                                                type="text"
                                                placeholder="e.g., 30"
                                                className="w-full border p-2 rounded-md focus:ring-black focus:border-black"
                                                value={q.timeLimit}


                                                onChange={(e: ChangeEvent<HTMLInputElement>) => {
                                                    const val = e.target.value;
                                                    if (/^\d*$/.test(val)) { // ✅ allow only digits (0–9) or empty
                                                        handleQuestionChange(q.id, 'timeLimit', e.target.value)
                                                    }
                                                }

                                                }
                                            />
                                        </div>

                                        <div className="mb-3">
                                            <label htmlFor={`points-${q.id}`} className="block text-sm font-medium text-gray-700 mb-1">Points</label>
                                            <input
                                                id={`points-${q.id}`}
                                                type="text"
                                                placeholder="e.g., 10"
                                                className="w-full border p-2 rounded-md focus:ring-black focus:border-black"
                                                value={q.points}

                                                onChange={(e: ChangeEvent<HTMLInputElement>) => {
                                                    const val = e.target.value;
                                                    if (/^\d*$/.test(val)) { // ✅ allow only digits (0–9) or empty
                                                        handleQuestionChange(q.id, 'points', e.target.value)
                                                    }
                                                }

                                                }
                                            />
                                        </div>

                                        <div className="mb-3">
                                            <label htmlFor={`image-upload-${q.id}`} className="block text-sm font-medium text-gray-700 mb-1">Image (Optional)</label>
                                            <input
                                                id={`image-upload-${q.id}`}
                                                type="file"
                                                accept="image/*"
                                                className="hidden"
                                                ref={el => fileInputRefs.current[q.id] = el}
                                                onChange={(e: ChangeEvent<HTMLInputElement>) => handleImageUpload(q.id, e)}
                                            />
                                            <button
                                                type="button"
                                                onClick={() => fileInputRefs.current[q.id]?.click()}
                                                className="bg-gray-200 text-gray-700 px-4 py-2 rounded-md flex items-center gap-2 hover:bg-gray-300 transition-colors"
                                            >
                                                <ImageIcon size={18} /> Upload Image
                                            </button>
                                            {q.image && (
                                                <div className="mt-2 relative">
                                                    <img src={q.image} alt="Question Preview" className="h-24 w-auto object-cover rounded-md" />
                                                    <button
                                                        onClick={() => handleQuestionChange(q.id, 'image', null)}
                                                        className="absolute top-0 right-0 bg-red-500 text-white rounded-full p-1"
                                                        aria-label="Remove image"
                                                    >
                                                        <X size={16} />
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    </>
                                )}
                            </div>
                        ))}
                    </div>
                    {/* // */}
                </div>

                {/* Collapsed State - Show Expand Button */}
                {isFirstColumnCollapsed && (
                    <div className="fixed left-4 top-1/2 transform -translate-y-1/2 z-50 md:flex hidden items-center justify-center">
                        <button
                            onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                setIsFirstColumnCollapsed(false);
                            }}
                            className="bg-red-600 text-white p-3 rounded-full shadow-lg hover:bg-red-700 transition-colors cursor-pointer"
                            title="Expand Questions Panel"
                            type="button"
                        >
                            <ChevronRight size={20} />
                        </button>
                    </div>
                )}

                {/* Column 2 - Preview */}
                <div className={`space-y-4 relative ${isFirstColumnCollapsed ? "col-span-2" : "col-span-1"}`}>
                    <div className="p-4 bg-white rounded-lg shadow-md h-full min-h-[200px]">
                        <h4 className="font-bold text-xl mb-3 text-gray-800">Quiz Preview</h4>
                        {showPreview ? (
                            previewContent.length > 0 ? (
                                <div>
                                    <h5 className="font-semibold text-lg mb-2">{quizTitle || subject_questions[0]?.['quiz_title'] || "Untitled Quiz"}</h5>
                                    {previewContent}
                                </div>
                            ) : (
                                <p className="text-gray-500">No questions to preview yet. Add some questions!</p>
                            )
                        ) : (
                            <p className="text-gray-500">Click 'Preview' button to see your quiz layout.</p>
                        )}
                    </div>
                </div>

                {/* Column 3 - Settings and Actions */}
                <div className="space-y-4">
                    <button
                        onClick={updatePreview}
                        className="flex items-center justify-center bg-gray-200 text-gray-800 px-4 py-2 rounded-lg shadow-md w-full hover:bg-gray-300 transition-colors font-semibold"
                    >
                        <Eye size={18} className="mr-2" /> Preview
                    </button>
                    <div className="flex gap-2 w-full">
                        <button

                            onClick={() => {
                                handleSave()
                            }}
                            className="bg-red-600 text-white px-4 py-2 rounded-lg shadow-md flex-1 flex items-center justify-center hover:bg-red-700 transition-colors font-semibold"
                        >
                            <Save size={18} className="mr-2" /> Save
                        </button>
                        <button
                            onClick={handleExit}
                            type="button"
                            className="bg-gray-200 text-gray-800 px-4 py-2 rounded-lg shadow-md flex-1 flex items-center justify-center hover:bg-gray-300 transition-colors font-semibold"
                        >
                            <LogOut size={18} className="mr-2" /> Exit
                        </button>
                    </div>

                    <div className="bg-white p-4 rounded-lg shadow-md">
                        <h3 className="text-lg font-bold mb-3 text-gray-800">Quiz Summary</h3>
                        <div className="space-y-3">
                            <div className="flex items-center gap-2 text-gray-700">
                                <List size={18} className="text-red-500" /> <span className="font-medium">Total Questions:</span>
                                <span>{totalQuestionsCount + subject_questions[0]?.subjects_questions?.length}</span>
                            </div>
                            <div className="flex items-center gap-2 text-gray-700">
                                <Clock size={18} className="text-blue-500" /> <span className="font-medium">Total Time Limit:</span>
                                <span>{totalTimeLimit} seconds</span>
                            </div>
                            <div className="flex items-center gap-2 text-gray-700">
                                <Star size={18} className="text-yellow-500" /> <span className="font-medium">Total Points:</span>
                                <span>{totalPoints}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        </AuthenticatedLayout>
    );
}
