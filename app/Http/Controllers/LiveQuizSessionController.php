<?php

namespace App\Http\Controllers;

use App\Models\Quiz;
use App\Models\Question;
use App\Models\LiveSession;
use App\Models\LiveParticipant;
use App\Models\User;
use App\Models\PointsHistory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class LiveQuizSessionController extends Controller
{
    public function getSessionState(Quiz $quiz)
    {
        try {
            $liveSession = LiveSession::where('quiz_id', $quiz->id)->first();

            if (!$liveSession) {
                return response()->json(['message' => 'Live session not found.'], 404);
            }

            // Return only the necessary fields to avoid serialization issues
            return response()->json([
                'id' => $liveSession->id,
                'quiz_id' => $liveSession->quiz_id,
                'current_question_index' => $liveSession->current_question_index,
                'show_answer' => $liveSession->show_answer,
                'status' => $liveSession->status,
                'session_host_id' => $liveSession->session_host_id,
                'created_at' => $liveSession->created_at,
                'updated_at' => $liveSession->updated_at,
            ]);
        } catch (\Exception $e) {
            Log::error('Error fetching live session state: ' . $e->getMessage(), [
                'quiz_id' => $quiz->id,
                'exception' => $e
            ]);
            return response()->json(['message' => 'An error occurred while fetching session state.'], 500);
        }
    }

    public function createSession(Request $request, Quiz $quiz)
    {
        if (LiveSession::where('quiz_id', $quiz->id)->exists()) {
            return response()->json(['message' => 'Session already exists for this quiz.'], 409);
        }

        if (Auth::id() !== $quiz->user_id) {
            return response()->json(['message' => 'You are not authorized to create a session for this quiz.'], 403);
        }

        $request->validate([
            'current_question_index' => 'required|integer|min:0',
            'show_answer' => 'required|boolean',
            'status' => 'required|in:waiting,active,finished',
        ]);

        $liveSession = LiveSession::create([
            'quiz_id' => $quiz->id,
            'current_question_index' => $request->current_question_index,
            'show_answer' => $request->show_answer,
            'status' => $request->status,
            'session_host_id' => Auth::id(),
        ]);

        return response()->json($liveSession, 201);
    }

    public function startQuiz(Quiz $quiz)
    {
        $liveSession = LiveSession::where('quiz_id', $quiz->id)->firstOrFail();

        if (Auth::id() !== $liveSession->session_host_id) {
            return response()->json(['message' => 'You are not authorized to start this session.'], 403);
        }

        if ($liveSession->status === 'active') {
            return response()->json(['message' => 'Quiz is already active.'], 409);
        }

        $liveSession->update([
            'status' => 'active',
            'current_question_index' => 0,
            'show_answer' => false,
        ]);

        return response()->json($liveSession);
    }

    public function nextQuestion(Request $request, Quiz $quiz)
    {
        $liveSession = LiveSession::where('quiz_id', $quiz->id)->firstOrFail();

        if (Auth::id() !== $liveSession->session_host_id) {
            return response()->json(['message' => 'You are not authorized to advance questions in this session.'], 403);
        }

        if ($liveSession->status !== 'active') {
            return response()->json(['message' => 'Quiz is not active.'], 409);
        }

        $nextIndex = $request->input('next_question_index');

        if ($nextIndex >= count($quiz->questions)) {
            $liveSession->update(['status' => 'finished', 'show_answer' => true]);
            return response()->json($liveSession);
        }

        $liveSession->update([
            'current_question_index' => $nextIndex,
            'show_answer' => false,
        ]);

        return response()->json($liveSession);
    }

    public function revealAnswer(Quiz $quiz)
    {
        $liveSession = LiveSession::where('quiz_id', $quiz->id)->firstOrFail();

        if (Auth::id() !== $liveSession->session_host_id) {
            return response()->json(['message' => 'You are not authorized to reveal answers in this session.'], 403);
        }

        $liveSession->update(['show_answer' => true]);

        return response()->json($liveSession);
    }

    public function endQuiz(Quiz $quiz)
    {
        $liveSession = LiveSession::where('quiz_id', $quiz->id)->firstOrFail();

        if (Auth::id() !== $liveSession->session_host_id) {
            return response()->json(['message' => 'You are not authorized to end this session.'], 403);
        }

        $liveSession->update(['status' => 'finished', 'show_answer' => true]);

        return response()->json($liveSession);
    }

    public function getParticipants(Quiz $quiz)
    {
        $liveSession = LiveSession::where('quiz_id', $quiz->id)->first();

        if (!$liveSession) {
            return response()->json([], 200);
        }

        // The 'answers' attribute is already cast to an array by the LiveParticipant model.
        // No need for json_decode() here.
        $participants = LiveParticipant::where('live_session_id', $liveSession->id)
                            ->with('user')
                            ->get()
                            ->map(function ($participant) {
                                return [
                                    'user_id' => $participant->user_id,
                                    'user_name' => $participant->user->name ?? 'Anonymous', // Only name, no sensitive data
                                    'score' => $participant->score,
                                    'last_answer_time' => $participant->last_answer_time,
                                    'answers' => $participant->answers ?? [], // Access as array directly
                                    // Exclude sensitive user data: email, student_number, etc.
                                ];
                            });

        return response()->json($participants);
    }

    public function joinParticipant(Request $request, Quiz $quiz)
    {
        try {
            $liveSession = LiveSession::where('quiz_id', $quiz->id)->first();

            if (!$liveSession) {
                // If session doesn't exist, create it (for teachers/hosts)
                if (Auth::id() === $quiz->user_id) {
                    $liveSession = LiveSession::firstOrCreate(
                        ['quiz_id' => $quiz->id],
                        [
                            'current_question_index' => 0,
                            'show_answer' => false,
                            'status' => 'waiting',
                            'session_host_id' => Auth::id(),
                        ]
                    );
                } else {
                    return response()->json(['message' => 'Live session is not active for this quiz.'], 404);
                }
            }

            $participant = LiveParticipant::firstOrCreate(
                [
                    'live_session_id' => $liveSession->id,
                    'user_id' => Auth::id(),
                ],
                [
                    'score' => 0,
                    'last_answer_time' => now(),
                    'answers' => [], // Initialize as empty array; model cast handles JSON conversion
                ]
            );

            // Ensure answers is set if participant already existed
            if ($participant->answers === null || !is_array($participant->answers)) {
                $participant->answers = [];
                $participant->save();
            }

            return response()->json(['message' => 'Successfully joined live session.', 'participant_id' => $participant->id], 200);
        } catch (\Exception $e) {
            Log::error('Error joining participant: ' . $e->getMessage(), [
                'quiz_id' => $quiz->id,
                'user_id' => Auth::id(),
                'exception' => $e->getTraceAsString()
            ]);
            return response()->json(['message' => 'An error occurred while joining the session.', 'error' => $e->getMessage()], 500);
        }
    }

    public function submitAnswer(Request $request, Quiz $quiz)
    {
        $liveSession = LiveSession::where('quiz_id', $quiz->id)->firstOrFail();
        $participant = LiveParticipant::where('live_session_id', $liveSession->id)
                                    ->where('user_id', Auth::id())
                                    ->firstOrFail();

        if ($liveSession->status !== 'active' || $liveSession->show_answer) {
            return response()->json(['message' => 'Quiz is not active or answer has been revealed.'], 409);
        }

        $currentQuestion = $quiz->questions()->find($request->input('question_id'));

        if (!$currentQuestion) {
            return response()->json(['message' => 'Question not found.'], 404);
        }

        // Access answers directly as an array thanks to model casting
        $participantAnswers = $participant->answers ?? [];
        if (isset($participantAnswers[$currentQuestion->id])) {
            return response()->json(['message' => 'You have already answered this question.'], 409);
        }

        $isCorrect = false;
        $submittedAnswer = $request->input('answer');

        switch ($currentQuestion->type) {
            case 'multiple-choice':
                $correctOption = $currentQuestion->options->where('is_correct', true)->first();
                if ($correctOption && $submittedAnswer == $correctOption->id) {
                    $isCorrect = true;
                }
                break;
            case 'true-false':
                $submittedBool = filter_var($submittedAnswer, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                if ($submittedBool !== null && $submittedBool === $currentQuestion->true_false_answer) {
                    $isCorrect = true;
                }
                break;
            case 'short-answer':
                if (strtolower($submittedAnswer) === strtolower($currentQuestion->short_answer)) {
                    $isCorrect = true;
                }
                break;
        }

        DB::transaction(function () use ($participant, $currentQuestion, $isCorrect, $submittedAnswer, $liveSession, &$participantAnswers) {
            $pointsAwarded = 0;
            if ($isCorrect) {
                $pointsAwarded = $currentQuestion->points ?? 0;
                $participant->score += $pointsAwarded;
            }
            $participant->last_answer_time = now();

            // Assign the array directly; model cast handles JSON conversion
            $participantAnswers[$currentQuestion->id] = [
                'submitted' => $submittedAnswer,
                'is_correct' => $isCorrect,
                'points_awarded' => $pointsAwarded,
            ];
            $participant->answers = $participantAnswers; // Assign array directly

            $participant->save();

            // Save to points_history for report generation
            // Note: LiveParticipant uses user_id, but PointsHistory uses participant_id (from Participants table)
            // For live quizzes, we need to find or create a Participants record, or use a different approach
            // For now, we'll try to find a Participants record by user_id, or skip if not found
            // This is a limitation - live quizzes and main questionnaire use different participant systems
            $mainParticipant = \App\Models\Participants::where('team_leader_email', $participant->user->email ?? '')
                ->orWhere('student_number', $participant->user->email ?? '')
                ->first();
            
            // Format answer text based on question type
            $answerText = '';
            switch ($currentQuestion->type) {
                case 'multiple-choice':
                    $selectedOption = $currentQuestion->options->find($submittedAnswer);
                    $answerText = $selectedOption ? $selectedOption->option_text : 'Option ' . $submittedAnswer;
                    break;
                case 'true-false':
                    $answerText = filter_var($submittedAnswer, FILTER_VALIDATE_BOOLEAN) ? 'True' : 'False';
                    break;
                case 'short-answer':
                    $answerText = $submittedAnswer;
                    break;
            }

            // Save to points_history for report generation
            // Note: LiveParticipant uses user_id, but PointsHistory uses participant_id (from Participants table)
            // For live quizzes, we try to find a Participants record, but this may not always work
            // since LiveQuizSession and main Questionnaire use different participant systems
            if ($mainParticipant) {
                // Check if record exists for this participant and question today
                $existingRecord = PointsHistory::where('participant_id', $mainParticipant->id)
                    ->where('question_id', $currentQuestion->id)
                    ->whereDate('created_at', now()->toDateString())
                    ->first();

                if ($existingRecord) {
                    // Update existing record: increment attempt count
                    $existingRecord->attempt_answers = ($existingRecord->attempt_answers ?? 1) + 1;
                    $existingRecord->answer = $answerText;
                    $existingRecord->points = $pointsAwarded;
                    $existingRecord->save();
                } else {
                    // Create new record in points_history
                    // Note: Using quiz_id as lobby_id for live quizzes (may need adjustment based on your schema)
                    PointsHistory::create([
                        'participant_id' => $mainParticipant->id,
                        'question_id' => $currentQuestion->id,
                        'lobby_id' => $liveSession->quiz_id, // Using quiz_id as lobby_id for live quizzes
                        'points' => $pointsAwarded,
                        'question' => $currentQuestion->question_text,
                        'answer' => $answerText,
                        'attempt_answers' => 1
                    ]);
                }
            }
            // If no main participant found, skip points_history saving (live quiz uses different system)
        });

        return response()->json(['message' => 'Answer submitted.', 'is_correct' => $isCorrect, 'score' => $participant->score], 200);
    }

    private function getMimeTypeExtension($mimeType)
    {
        $mimeMap = [
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'image/gif' => 'gif',
            'image/webp' => 'webp',
        ];
        return $mimeMap[$mimeType] ?? null;
    }
}
